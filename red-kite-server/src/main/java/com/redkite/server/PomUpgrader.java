package com.redkite.server;

import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.maven.RemediationApplier;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Applies chosen dependency changes to a project's POMs without the server: the headless
 * counterpart of the server's "Apply selected". It reuses the server's own POM patching, so a
 * version stays property-backed, a literal version is normalised to a property, and BOM-managed
 * dependencies get an explicit version.
 *
 * <ul>
 *   <li>A <em>direct</em> dependency is upgraded where it is declared.
 *   <li>A <em>transitive</em> dependency has no declaration to change, so it is pinned: a
 *       {@code <dependencyManagement>} entry marked {@code redkite:user-pin} goes in the root POM.
 *   <li>A pin can be <em>dropped</em> or <em>unpinned</em> again, which needs no analysis.
 * </ul>
 */
public final class PomUpgrader {
    private PomUpgrader() {}

    /** One change after resolution against the analysis. {@code pin} marks a transitive pin rather than an upgrade. */
    public record Change(String groupId, String artifactId, String currentVersion, String targetVersion, boolean pin) {}

    /** What is planned: the changes, the pins dropped, every POM that would be rewritten (path relative to the
     *  project root), and what was refused. */
    public record Plan(List<Change> changes, List<String> dropped, List<String> unpinned,
                       Map<String, String> patchedPoms, List<String> problems) {}

    /**
     * @param projectRoot directory containing the root {@code pom.xml}
     * @param pomFiles    every project POM (the root's and each module's); read from disk
     * @param result      an analysis of the project, needed only when {@code requested} is not empty (may be null otherwise)
     * @param requested   {@code groupId:artifactId} to the wanted version; null or blank means RedKite's recommended version
     * @param bulk        true when RedKite chose {@code requested} itself (upgrade-all, upgrade-cve): a transitive then gets a
     *                    computed pin that later bulk runs may move, instead of the user pin an explicit request gets
     * @param drops       {@code groupId:artifactId} whose RedKite pin should be removed
     * @param unpins      {@code groupId:artifactId} whose user pin should be released, keeping the version
     * @return the planned POM contents; nothing is written
     */
    public static Plan plan(Path projectRoot, List<Path> pomFiles, ReportExporter.Result result,
                            Map<String, String> requested, boolean bulk, Set<String> drops,
                            Set<String> unpins) throws IOException {
        Path root = projectRoot.toAbsolutePath().normalize();
        Map<String, String> original = new LinkedHashMap<>();
        Path rootPom = root.resolve("pom.xml");
        Set<Path> files = new LinkedHashSet<>();
        files.add(rootPom);
        for (Path f : pomFiles) files.add(f.toAbsolutePath().normalize());
        for (Path f : files) {
            if (Files.exists(f)) original.put(rel(root, f), Files.readString(f, StandardCharsets.UTF_8));
        }
        Map<String, String> working = new LinkedHashMap<>(original);
        List<String> problems = new ArrayList<>();
        List<Change> changes = new ArrayList<>();
        List<String> dropped = new ArrayList<>();
        List<String> unpinned = new ArrayList<>();
        RemediationApplier applier = new RemediationApplier();

        for (String coord : drops) {
            String[] ga = coord.split(":");
            boolean found = false;
            for (Map.Entry<String, String> e : working.entrySet()) {
                String next = applier.removePin(e.getValue(), ga[0], ga[1]);
                if (!next.equals(e.getValue())) {
                    e.setValue(next);
                    found = true;
                }
            }
            if (found) dropped.add(coord);
            else problems.add(coord + ": no RedKite pin to drop");
        }

        for (String coord : unpins) {
            String[] ga = coord.split(":");
            boolean found = false;
            for (Map.Entry<String, String> e : working.entrySet()) {
                String next = applier.removeUserPin(e.getValue(), ga[0], ga[1]);
                if (!next.equals(e.getValue())) {
                    e.setValue(next);
                    found = true;
                }
            }
            if (found) unpinned.add(coord);
            else problems.add(coord + ": no user pin to release");
        }

        if (!requested.isEmpty()) {
            if (result == null) throw new IllegalArgumentException("an analysis is needed to plan upgrades");
            Map<String, String> directUpdates = new LinkedHashMap<>();
            Set<String> userPinned = new LinkedHashSet<>();
            for (String content : working.values()) userPinned.addAll(applier.findUserPinnedCoordinates(content));
            Set<Long> repinIds = new LinkedHashSet<>();
            for (Map.Entry<String, String> want : requested.entrySet()) {
                String coord = want.getKey();
                List<ScanComponent> all = result.report().components().stream()
                        .filter(c -> coord.equals(c.coordinate().groupId() + ":" + c.coordinate().artifactId())).toList();
                if (all.isEmpty()) {
                    problems.add(coord + ": not a dependency of this project");
                    continue;
                }
                String version = want.getValue();
                if (version == null || version.isBlank()) {
                    version = result.report().recommendations().stream()
                            .filter(r -> coord.equals(r.coordinate().groupId() + ":" + r.coordinate().artifactId()))
                            .map(UpgradeRecommendation::targetVersion).findFirst().orElse(null);
                    if (version == null) {
                        problems.add(coord + ": no recommended version, name one explicitly as " + coord + ":<version>");
                        continue;
                    }
                }
                List<ScanComponent> direct = all.stream()
                        .filter(c -> c.direct() && !c.snapshot() && c.sourceFilePath() != null).toList();
                if (direct.isEmpty()) {
                    if (all.stream().anyMatch(ScanComponent::direct)) {
                        problems.add(coord + ": a SNAPSHOT or undeclared dependency, nothing to change");
                        continue;
                    }
                    // Transitive: no declaration of its own, so force the version with a pin in the root POM.
                    ScanComponent c = all.get(0);
                    String rootContent = working.get("pom.xml");
                    if (rootContent == null) {
                        problems.add(coord + ": no root pom.xml to hold the pin");
                        continue;
                    }
                    String[] ga = coord.split(":");
                    working.put("pom.xml", applier.applyDependencyManagementPin(rootContent, ga[0], ga[1], version,
                            bulk ? "set by a redkite upgrade goal" : "pinned with redkite:upgrade",
                            bulk ? RemediationApplier.PinKind.COMPUTED : RemediationApplier.PinKind.USER));
                    changes.add(new Change(ga[0], ga[1], c.version(), version, true));
                    continue;
                }
                for (ScanComponent c : direct) {
                    if (version.equals(c.version())) continue;
                    directUpdates.put(Long.toString(c.id()), version);
                    // An explicit upgrade of a user-pinned dependency keeps it pinned, at the new version.
                    if (userPinned.contains(coord)) repinIds.add(c.id());
                    changes.add(new Change(c.coordinate().groupId(), c.coordinate().artifactId(), c.version(), version, false));
                }
            }
            if (!directUpdates.isEmpty()) {
                Map<String, String> patched;
                try {
                    patched = new PomChanges(null, new EnforcerAnalysis(null))
                            .generatePomPatches(result.report(), working, root.toString(), directUpdates, Map.of(),
                                    repinIds, Set.of());
                } catch (IOException | RuntimeException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IOException("Could not patch the POMs: " + e.getMessage(), e);
                }
                working.putAll(patched);
            }
        }

        boolean anyChange = !changes.isEmpty() || !dropped.isEmpty() || !unpinned.isEmpty();
        Map<String, String> changed = new LinkedHashMap<>();
        if (anyChange) {
            refreshSummaries(applier, working);
            for (Map.Entry<String, String> e : working.entrySet()) {
                if (!e.getValue().equals(original.get(e.getKey()))) changed.put(e.getKey(), e.getValue());
            }
        }
        return new Plan(changes, dropped, unpinned, changed, problems);
    }

    /** Writes the planned POMs under {@code projectRoot}. */
    public static void write(Path projectRoot, Plan plan) throws IOException {
        for (Map.Entry<String, String> e : plan.patchedPoms().entrySet()) {
            Files.writeString(projectRoot.resolve(e.getKey()), e.getValue(), StandardCharsets.UTF_8);
        }
    }

    /** Keeps the {@code redkite:pin-summary} comment in every POM accurate, as the server does after an apply. */
    private static void refreshSummaries(RemediationApplier applier, Map<String, String> poms) {
        boolean multi = poms.size() > 1;
        Map<String, RemediationApplier.PinCounts> counts = new LinkedHashMap<>();
        int total = 0, user = 0;
        for (Map.Entry<String, String> e : poms.entrySet()) {
            RemediationApplier.PinCounts c = applier.countPins(e.getValue());
            counts.put(e.getKey(), c);
            total += c.total();
            user += c.userPinned();
        }
        RemediationApplier.PinCounts project = new RemediationApplier.PinCounts(total, user);
        for (Map.Entry<String, String> e : poms.entrySet()) {
            boolean isRoot = e.getKey().equals("pom.xml");
            e.setValue(applier.applyPinSummaryComment(e.getValue(), counts.get(e.getKey()), isRoot && multi ? project : null));
        }
    }

    private static String rel(Path root, Path file) {
        return root.relativize(file).toString().replace('\\', '/');
    }
}
