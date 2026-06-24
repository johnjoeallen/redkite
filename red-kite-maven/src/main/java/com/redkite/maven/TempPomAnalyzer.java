package com.redkite.maven;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Runs the Maven enforcer against a temporary copy of the project's POM tree, with all
 * RedKite remediations and existing dep-management stripped so the pristine conflict set
 * is visible. A second variant re-runs with computed dep-management pins applied for
 * Phase 2 auto-fix verification.
 *
 * <p>Original files are never modified — work is always done in a temp directory.
 */
public class TempPomAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(TempPomAnalyzer.class.getName());

    private final RemediationApplier applier = new RemediationApplier();
    private final EnforcerRunner runner = new EnforcerRunner();

    /**
     * Result of a pristine enforcer run, including metadata about what was stripped.
     */
    public record PristineResult(
            EnforcerRunner.EnforcerRunResult enforcerResult,
            int exclusionsStripped,
            List<String> depMgmtRemoved,
            List<String> allRedkiteExclusions) {}

    /**
     * Strips all RedKite remediations and all existing dep-management from every POM in
     * the project, then runs the enforcer against the temp tree.
     */
    public PristineResult runPristine(Path projectRoot, Path pomPath) throws IOException {
        List<Path> allPoms = findAllPoms(projectRoot);

        int exclusionsStripped = 0;
        List<String> depMgmtRemoved = new ArrayList<>();
        List<String> allRedkiteExclusions = new ArrayList<>();

        for (Path pom : allPoms) {
            String content = Files.readString(pom, StandardCharsets.UTF_8);
            exclusionsStripped += applier.countRedkiteExclusions(content);
            allRedkiteExclusions.addAll(applier.parseRedkiteExclusions(content));
            depMgmtRemoved.addAll(applier.extractDepMgmtEntries(content));
        }

        int finalExclusionsStripped = exclusionsStripped;
        LOGGER.info(() -> "Pristine analysis: stripping " + finalExclusionsStripped + " exclusion(s) and "
                + depMgmtRemoved.size() + " dep-management entry(ies) across " + allPoms.size() + " POM(s)");

        Path tempRoot = Files.createTempDirectory("redkite-pristine-");
        try {
            for (Path pom : allPoms) {
                String content = Files.readString(pom, StandardCharsets.UTF_8);
                String stripped = applier.stripRedkiteRemediations(content);
                stripped = applier.stripAllDepManagement(stripped);
                Path dest = tempRoot.resolve(projectRoot.relativize(pom));
                Files.createDirectories(dest.getParent());
                Files.writeString(dest, stripped, StandardCharsets.UTF_8);
            }
            Path tempPomPath = tempRoot.resolve(projectRoot.relativize(pomPath));
            EnforcerRunner.EnforcerRunResult result = runner.run(projectRoot, tempPomPath);
            return new PristineResult(result, exclusionsStripped,
                    List.copyOf(depMgmtRemoved), List.copyOf(allRedkiteExclusions));
        } finally {
            deleteQuietly(tempRoot);
        }
    }

    /**
     * Strips all RedKite remediations and all existing dep-management from every POM, applies
     * the given computed pins to the root POM, then runs the enforcer against the temp tree.
     *
     * @param pins map of "groupId:artifactId" → version to pin
     */
    public EnforcerRunner.EnforcerRunResult runWithPins(Path projectRoot, Path pomPath,
            Map<String, String> pins) throws IOException {
        List<Path> allPoms = findAllPoms(projectRoot);
        Path tempRoot = Files.createTempDirectory("redkite-phase2-");
        try {
            for (Path pom : allPoms) {
                String content = Files.readString(pom, StandardCharsets.UTF_8);
                String stripped = applier.stripRedkiteRemediations(content);
                stripped = applier.stripAllDepManagement(stripped);
                if (pom.toAbsolutePath().equals(pomPath.toAbsolutePath())) {
                    for (Map.Entry<String, String> pin : pins.entrySet()) {
                        String[] ga = pin.getKey().split(":", 2);
                        stripped = applier.applyDependencyManagementPin(
                                stripped, ga[0], ga[1], pin.getValue(), "redkite-phase2");
                    }
                }
                Path dest = tempRoot.resolve(projectRoot.relativize(pom));
                Files.createDirectories(dest.getParent());
                Files.writeString(dest, stripped, StandardCharsets.UTF_8);
            }
            Path tempPomPath = tempRoot.resolve(projectRoot.relativize(pomPath));
            return runner.run(projectRoot, tempPomPath);
        } finally {
            deleteQuietly(tempRoot);
        }
    }

    /** Recursively finds all {@code pom.xml} files, skipping {@code target/} and hidden dirs. */
    private static List<Path> findAllPoms(Path root) throws IOException {
        List<Path> poms = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                String name = dir.getFileName().toString();
                if (name.equals("target") || name.startsWith(".")) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if ("pom.xml".equals(file.getFileName().toString())) {
                    poms.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return poms;
    }

    private static void deleteQuietly(Path dir) {
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path d, IOException exc) throws IOException {
                    Files.delete(d);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            LOGGER.warning(() -> "Failed to delete temp dir " + dir + ": " + e.getMessage());
        }
    }
}
