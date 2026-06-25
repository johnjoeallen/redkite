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
 * <p>The temp directory mirrors the project's POM tree with stripped POMs and symlinks
 * for all other content (src/, resources/, etc.), so {@code mvn verify -DskipTests}
 * can compile even when enforcer rules are bound to the lifecycle rather than configured
 * for direct {@code enforcer:enforce} invocation.
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

    /** Dep-management and exclusion metadata read from POM files without invoking Maven. */
    public record PomMetadata(int exclusionsStripped, List<String> depMgmtEntries,
                              List<String> allRedkiteExclusions) {}

    /**
     * Scans all POM files under {@code projectRoot} and returns dep-management entries and
     * RedKite exclusion counts — without running Maven.
     */
    public PomMetadata scanPomMetadata(Path projectRoot) throws IOException {
        List<Path> allPoms = findAllPoms(projectRoot);
        int exclusionsStripped = 0;
        List<String> depMgmtEntries = new ArrayList<>();
        List<String> allRedkiteExclusions = new ArrayList<>();
        for (Path pom : allPoms) {
            String content = Files.readString(pom, StandardCharsets.UTF_8);
            exclusionsStripped += applier.countRedkiteExclusions(content);
            allRedkiteExclusions.addAll(applier.parseRedkiteExclusions(content));
            depMgmtEntries.addAll(applier.extractDepMgmtEntries(content));
        }
        return new PomMetadata(exclusionsStripped,
                List.copyOf(depMgmtEntries), List.copyOf(allRedkiteExclusions));
    }

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
            writePoms(allPoms, projectRoot, tempRoot, (pom, content) -> {
                String s = applier.stripRedkiteRemediations(content);
                return applier.stripAllDepManagement(s);
            });
            try {
                symlinkNonPomContent(allPoms, projectRoot, tempRoot);
            } catch (Exception e) {
                LOGGER.warning(() -> "Symlink creation failed, verify fallback may not compile: " + e.getMessage());
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
        return runWithPins(projectRoot, pomPath, pins, false);
    }

    public EnforcerRunner.EnforcerRunResult runWithPins(Path projectRoot, Path pomPath,
            Map<String, String> pins, boolean skipDirectEnforce) throws IOException {
        List<Path> allPoms = findAllPoms(projectRoot);
        Path tempRoot = Files.createTempDirectory("redkite-phase2-");
        try {
            writePoms(allPoms, projectRoot, tempRoot, (pom, content) -> {
                String s = applier.stripRedkiteRemediations(content);
                s = applier.stripAllDepManagement(s);
                if (pom.toAbsolutePath().equals(pomPath.toAbsolutePath())) {
                    for (Map.Entry<String, String> pin : pins.entrySet()) {
                        String[] ga = pin.getKey().split(":", 2);
                        s = applier.applyDependencyManagementPin(s, ga[0], ga[1], pin.getValue(), "redkite-phase2");
                    }
                }
                return s;
            });
            try {
                symlinkNonPomContent(allPoms, projectRoot, tempRoot);
            } catch (Exception e) {
                LOGGER.warning(() -> "Symlink creation failed, verify fallback may not compile: " + e.getMessage());
            }
            Path tempPomPath = tempRoot.resolve(projectRoot.relativize(pomPath));
            return runner.run(projectRoot, tempPomPath, skipDirectEnforce);
        } finally {
            deleteQuietly(tempRoot);
        }
    }

    @FunctionalInterface
    private interface PomTransform {
        String transform(Path pom, String content) throws IOException;
    }

    private static void writePoms(List<Path> allPoms, Path projectRoot, Path tempRoot,
            PomTransform transform) throws IOException {
        for (Path pom : allPoms) {
            String content = Files.readString(pom, StandardCharsets.UTF_8);
            String transformed = transform.transform(pom, content);
            Path dest = tempRoot.resolve(projectRoot.relativize(pom));
            Files.createDirectories(dest.getParent());
            Files.writeString(dest, transformed, StandardCharsets.UTF_8);
        }
    }

    /**
     * For each module directory that has a POM, creates symlinks in the temp directory
     * for all non-pom, non-target entries (src/, resources/, etc.). This allows
     * {@code mvn verify -DskipTests} to compile even though only the POMs live in temp.
     * Failures are silently logged — symlinks are best-effort.
     */
    private static void symlinkNonPomContent(List<Path> allPoms, Path projectRoot, Path tempRoot) {
        for (Path pom : allPoms) {
            Path pomDir = pom.getParent();
            Path destDir = tempRoot.resolve(projectRoot.relativize(pomDir));
            try (var stream = Files.list(pomDir)) {
                stream.forEach(child -> {
                    String name = child.getFileName().toString();
                    if (name.equals("pom.xml") || name.equals("target") || name.startsWith(".")) return;
                    Path destChild = destDir.resolve(name);
                    if (Files.exists(destChild)) return; // module subdir already created
                    try {
                        Files.createSymbolicLink(destChild, child.toAbsolutePath());
                    } catch (Exception e) {
                        LOGGER.fine(() -> "Could not symlink " + destChild + " → " + child + ": " + e.getMessage());
                    }
                });
            } catch (Exception e) {
                LOGGER.fine(() -> "Could not list " + pomDir + " for symlinking: " + e.getMessage());
            }
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

    /**
     * Deletes a temp directory tree, following symlinks only one level deep so that
     * symlinks to original source directories are removed without deleting source files.
     */
    private static void deleteQuietly(Path dir) {
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes attrs) throws IOException {
                    // Don't follow symlinks into the original project tree
                    if (!d.equals(dir) && Files.isSymbolicLink(d)) {
                        Files.delete(d);
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

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
