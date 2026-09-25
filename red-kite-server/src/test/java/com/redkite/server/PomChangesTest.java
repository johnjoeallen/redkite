package com.redkite.server;

import com.redkite.core.domain.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Turning version selections and pin toggles into patched POM text. */
class PomChangesTest {
    private static final String ROOT = """
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>app</artifactId>
              <version>1.0</version>
              <properties>
                <lib.version>1.0</lib.version>
              </properties>
              <dependencies>
                <dependency>
                  <groupId>g</groupId>
                  <artifactId>lib</artifactId>
                  <version>${lib.version}</version>
                </dependency>
                <dependency>
                  <groupId>g</groupId>
                  <artifactId>parent-dep</artifactId>
                  <version>3.0</version>
                </dependency>
              </dependencies>
            </project>
            """;

    private static final String MODULE = """
            <project>
              <modelVersion>4.0.0</modelVersion>
              <parent><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></parent>
              <artifactId>mod</artifactId>
              <dependencies>
                <dependency>
                  <groupId>g</groupId>
                  <artifactId>other</artifactId>
                  <version>2.0</version>
                </dependency>
              </dependencies>
            </project>
            """;

    @TempDir
    Path project;

    // Store is only needed for refreshPinSummaryComments; patch generation never touches it.
    private final PomChanges changes = new PomChanges(null, new EnforcerAnalysis(null));

    private static ScanComponent direct(long id, String artifactId, String version, VersionSource source, String file) {
        return new ScanComponent(id, new ComponentCoordinate("g", artifactId), version, DependencyScope.COMPILE, true,
                source, file, null, Map.of(), false, source == VersionSource.PROPERTY ? file + "#lib.version" : file + "#dependency", file);
    }

    private static ScanComponent transitive(long id, String artifactId, String version) {
        return new ScanComponent(id, new ComponentCoordinate("g", artifactId), version, DependencyScope.COMPILE, false,
                VersionSource.UNKNOWN, "pom.xml", null, Map.of(), false, null, "pom.xml");
    }

    private static ScanReport report(ScanComponent... components) {
        return new ScanReport("scan", "p", true, "ok", Instant.now(), List.of(components), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of());
    }

    private Map<String, String> poms() {
        Map<String, String> poms = new LinkedHashMap<>();
        poms.put("pom.xml", ROOT);
        poms.put("mod/pom.xml", MODULE);
        return poms;
    }

    private Map<String, String> patch(ScanReport report, Map<String, String> updates, Set<Long> pinned, Set<Long> unpinned,
            Map<String, List<TransitiveConflictFinding>> conflicts) throws Exception {
        return changes.generatePomPatches(report, poms(), project.toString(), updates, conflicts, pinned, unpinned);
    }

    @Test
    void directUpgradesPatchTheDeclaringFileAndIgnoreUnknownIds() throws Exception {
        ScanReport report = report(
                direct(1, "lib", "1.0", VersionSource.PROPERTY, "pom.xml"),
                direct(2, "other", "2.0", VersionSource.LITERAL, "mod/pom.xml"));
        Map<String, String> updates = new LinkedHashMap<>();
        updates.put("1", "1.1");
        updates.put("2", "2.5");
        updates.put("not-a-number", "9");
        updates.put("99", "9");
        Map<String, String> result = patch(report, updates, Set.of(), Set.of(), Map.of());

        assertEquals(Set.of("pom.xml", "mod/pom.xml"), result.keySet());
        assertTrue(result.get("pom.xml").contains("<lib.version>1.1</lib.version>"), result.get("pom.xml"));
        assertTrue(result.get("mod/pom.xml").contains("2.5"), result.get("mod/pom.xml"));
        assertFalse(result.get("mod/pom.xml").contains("<version>2.0</version>"), result.get("mod/pom.xml"));
    }

    @Test
    void nothingSelectedMeansNoPatches() throws Exception {
        ScanReport report = report(direct(1, "lib", "1.0", VersionSource.PROPERTY, "pom.xml"), transitive(3, "t", "1.0"));
        assertEquals(Map.of(), patch(report, Map.of("3", "1.0"), Set.of(), Set.of(), Map.of()),
                "re-selecting the current version is not a change");
        assertEquals(Map.of(), changes.generatePomPatches(report, Map.of(), project.toString(), Map.of("1", "2.0"), Map.of()),
                "no source POMs, nothing to patch");
    }

    @Test
    void pinningADirectDependencyMarksItWithoutChangingItsVersion() throws Exception {
        ScanReport report = report(direct(1, "lib", "1.0", VersionSource.PROPERTY, "pom.xml"));
        String pinned = patch(report, Map.of(), Set.of(1L), Set.of(), Map.of()).get("pom.xml");
        assertNotNull(pinned);
        assertTrue(pinned.contains("redkite:user-pin"), pinned);
        assertTrue(pinned.contains("<lib.version>1.0</lib.version>"), pinned);

        Map<String, String> unpinnedPoms = poms();
        unpinnedPoms.put("pom.xml", pinned);
        Map<String, String> unpinned = changes.generatePomPatches(report, unpinnedPoms, project.toString(), Map.of(),
                Map.of(), Set.of(), Set.of(1L));
        assertFalse(unpinned.get("pom.xml").contains("redkite:user-pin"), unpinned.get("pom.xml"));
    }

    @Test
    void transitiveSelectionBecomesAManagedPinAndExcludesTheOtherVersions() throws Exception {
        ScanComponent t = transitive(3, "t", "1.0");
        TransitiveConflictFinding conflict = new TransitiveConflictFinding("g", "t", "1.0", List.of("2.0"), List.of(),
                "dependencyConvergence", null, List.of(
                        new ConflictCandidateAction(ConflictCandidateAction.ActionType.ADD_DEPENDENCY_MANAGEMENT, "g", "t", "1.0", null, null),
                        new ConflictCandidateAction(ConflictCandidateAction.ActionType.ADD_EXCLUSION, "g", "t", "1.0", "g", "parent-dep"),
                        new ConflictCandidateAction(ConflictCandidateAction.ActionType.ADD_EXCLUSION, "g", "t", "2.0", "g", "other")));
        Map<String, String> result = patch(report(t), Map.of("3", "2.0"), Set.of(), Set.of(), Map.of("g:t", List.of(conflict)));

        String root = result.get("pom.xml");
        assertTrue(root.contains("redkite:dependency-management pin groupId=\"g\" artifactId=\"t\" version=\"2.0\""), root);
        assertTrue(root.contains("redkite:exclusion"), "parent-dep introduces 1.0, which was not selected: " + root);
        assertFalse(result.containsKey("mod/pom.xml"), "other introduces the selected 2.0, so it is left alone");
    }

    @Test
    void transitivePinAndUnpinToggles() throws Exception {
        ScanComponent t = transitive(3, "t", "1.0");
        String pinned = patch(report(t), Map.of(), Set.of(3L), Set.of(), Map.of()).get("pom.xml");
        assertTrue(pinned.contains("redkite:user-pin"), pinned);
        assertTrue(pinned.contains("<artifactId>t</artifactId>"), pinned);

        Map<String, String> withPin = poms();
        withPin.put("pom.xml", pinned);
        String unpinned = changes.generatePomPatches(report(t), withPin, project.toString(), Map.of(), Map.of(),
                Set.of(), Set.of(3L)).get("pom.xml");
        assertFalse(unpinned.contains("redkite:user-pin"), unpinned);
        assertTrue(unpinned.contains("<artifactId>t</artifactId>"), "unpinning keeps the managed entry: " + unpinned);

        String unpinnedAndMoved = changes.generatePomPatches(report(t), withPin, project.toString(), Map.of("3", "1.5"), Map.of(),
                Set.of(), Set.of(3L)).get("pom.xml");
        assertFalse(unpinnedAndMoved.contains("redkite:user-pin"), unpinnedAndMoved);
        assertTrue(unpinnedAndMoved.contains("redkite:dependency-management pin groupId=\"g\" artifactId=\"t\" version=\"1.5\""), unpinnedAndMoved);
    }

    @Test
    void snapshotsAreNeverPatched() throws Exception {
        ScanComponent snapshot = new ScanComponent(4, new ComponentCoordinate("g", "s"), "1.0-SNAPSHOT", DependencyScope.COMPILE,
                false, VersionSource.UNKNOWN, "pom.xml", null, Map.of(), true, null, "pom.xml");
        assertEquals(Map.of(), patch(report(snapshot), Map.of("4", "1.0"), Set.of(), Set.of(), Map.of()));
        // A pin request still triggers the root POM's usual literal-to-property normalisation,
        // but the snapshot itself is neither pinned nor managed.
        String root = patch(report(snapshot), Map.of("4", "1.0"), Set.of(4L), Set.of(), Map.of()).get("pom.xml");
        assertFalse(root.contains("redkite:user-pin"), root);
        assertFalse(root.contains("<artifactId>s</artifactId>"), root);
    }

    @Test
    void pinSummariesAreRefreshedAcrossEveryProjectPom() throws Exception {
        String savedRepos = System.getProperty("redkite.maven.repositories");
        System.setProperty("redkite.maven.repositories", "http://127.0.0.1:1/repo");
        try {
            java.nio.file.Files.writeString(project.resolve("pom.xml"), ROOT);
            java.nio.file.Files.createDirectories(project.resolve("mod"));
            java.nio.file.Files.writeString(project.resolve("mod/pom.xml"), MODULE);
            Store store = Store.connect("jdbc:h2:mem:" + java.util.UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1", "sa", "");
            String scanId = store.ingest(new ScanInput("app", project.toString(), project.toString(), "main", "abc", true, false,
                    Instant.now(), List.of(), List.of(), Map.of("pom.xml", "h", "mod/pom.xml", "h"), List.of())).scanId();
            PomChanges refresher = new PomChanges(store, new EnforcerAnalysis(store));
            com.redkite.maven.RemediationApplier applier = new com.redkite.maven.RemediationApplier();

            // The root gains a user pin in this apply; an extra file outside the scan is also being written.
            Path rootPath = project.resolve("pom.xml").normalize();
            Path extraPath = project.resolve("extra/pom.xml");
            Map<Path, String> modified = new LinkedHashMap<>();
            modified.put(rootPath, applier.applyDependencyManagementPin(ROOT, "g", "t", "2.0", "r", com.redkite.maven.RemediationApplier.PinKind.USER));
            modified.put(extraPath, "<project/>");
            Map<Path, String> originals = new LinkedHashMap<>();
            originals.put(rootPath, ROOT); // recorded by the apply itself before it modified the root

            refresher.refreshPinSummaryComments(applier, scanId, project, modified, originals);

            assertTrue(modified.get(rootPath).contains("redkite:pin-summary project: 1 redkite pin(s) (1 user pinned) — this file: 1 redkite pin(s) (1 user pinned)"),
                    modified.get(rootPath));
            Path modPath = project.resolve("mod/pom.xml").normalize();
            assertTrue(modified.get(modPath).contains("redkite:pin-summary 0 redkite pin(s) (0 user pinned)"), modified.get(modPath));
            assertTrue(modified.get(extraPath).contains("redkite:pin-summary 0 redkite pin(s)"), modified.get(extraPath));
            assertEquals(MODULE, originals.get(modPath), "a file touched only for its summary can be reverted");
            assertEquals(ROOT, originals.get(rootPath), "an original the apply already recorded is kept");

            // Running it again changes nothing further.
            Map<Path, String> again = new LinkedHashMap<>(modified);
            refresher.refreshPinSummaryComments(applier, scanId, project, again, null);
            assertEquals(modified, again);
        } finally {
            if (savedRepos == null) System.clearProperty("redkite.maven.repositories");
            else System.setProperty("redkite.maven.repositories", savedRepos);
        }
    }

    @Test
    void unknownIdsBlankRequestsAndPropertiesOwnedByAParentOrBomAreHandled() throws Exception {
        String root = """
                <project>
                  <properties><bom-owned.version>1</bom-owned.version><parent-owned.version>2</parent-owned.version><orphan.version>3</orphan.version></properties>
                  <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>
                </project>
                """;
        ScanComponent bomManaged = new ScanComponent(5, new ComponentCoordinate("g", "b"), "1", DependencyScope.COMPILE, false,
                VersionSource.PLATFORM_MANAGED, "pom.xml", null, Map.of(), false, "g:bom:1#bom-owned.version", "pom.xml");
        ScanComponent parentManaged = new ScanComponent(6, new ComponentCoordinate("g", "p"), "2", DependencyScope.COMPILE, false,
                VersionSource.PARENT_MANAGED, "pom.xml", null, Map.of(), false, "g:parent:1#parent-owned.version", "pom.xml");
        ScanComponent unfiled = new ScanComponent(7, new ComponentCoordinate("g", "unfiled"), "1.0", DependencyScope.COMPILE, true,
                VersionSource.LITERAL, null, null, Map.of(), false, null, "pom.xml");
        ScanComponent versionless = new ScanComponent(8, new ComponentCoordinate("g", "lib"), null, DependencyScope.COMPILE, true,
                VersionSource.LITERAL, "pom.xml", null, Map.of(), false, null, "pom.xml");
        ScanReport report = report(bomManaged, parentManaged, unfiled, versionless, transitive(3, "t", "1.0"));

        Map<String, String> result = changes.generatePomPatches(report, Map.of("pom.xml", root), project.toString(),
                Map.of("7", "2.0", "3", " "), Map.of(), Set.of(8L, 99L), Set.of(98L));
        String patched = result.get("pom.xml");
        assertNotNull(patched);
        assertTrue(patched.contains("<bom-owned.version>1</bom-owned.version>"), "kept: a BOM relies on it: " + patched);
        assertTrue(patched.contains("<parent-owned.version>2</parent-owned.version>"), "kept: a parent relies on it: " + patched);
        assertFalse(patched.contains("orphan.version"), "an unreferenced version property is tidied away: " + patched);
        assertFalse(patched.contains("<artifactId>t</artifactId>"), "a blank transitive request changes nothing: " + patched);
    }

    @Test
    void pinSummariesNeedTheScansSourcePoms() throws Exception {
        String savedRepos = System.getProperty("redkite.maven.repositories");
        System.setProperty("redkite.maven.repositories", "http://127.0.0.1:1/repo");
        try {
            Store store = Store.connect("jdbc:h2:mem:" + java.util.UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1", "sa", "");
            String scanId = store.ingest(new ScanInput("app", project.toString(), project.toString(), "main", "abc", true, false,
                    Instant.now(), List.of(), List.of(), Map.of("gone/pom.xml", "h"), List.of())).scanId();
            Map<Path, String> modified = new LinkedHashMap<>();
            new PomChanges(store, new EnforcerAnalysis(store)).refreshPinSummaryComments(
                    new com.redkite.maven.RemediationApplier(), scanId, project, modified, null);
            assertEquals(Map.of(), modified, "no stored POMs, nothing to refresh");
        } finally {
            if (savedRepos == null) System.clearProperty("redkite.maven.repositories");
            else System.setProperty("redkite.maven.repositories", savedRepos);
        }
    }
}
