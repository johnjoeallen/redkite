package com.redkite.server;

import com.redkite.core.domain.EnforcerStatus;
import com.redkite.core.domain.TransitiveConflictFinding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/** Store behaviour not already driven through the HTTP server tests: settings discovery and enforcer results. */
class StoreTest {
    private static final String SETTINGS = """
            <settings>
              <servers><server><id>corp</id><username>u</username><password>p</password></server></servers>
              <mirrors><mirror><id>corp</id><mirrorOf>*</mirrorOf><url>%s</url></mirror></mirrors>
            </settings>
            """;

    @TempDir
    Path home;

    private String savedHome;
    private String savedRepos;

    @BeforeEach
    void isolateSettings() throws Exception {
        savedHome = System.getProperty("user.home");
        savedRepos = System.getProperty("redkite.maven.repositories");
        System.clearProperty("redkite.maven.repositories");
        System.setProperty("user.home", home.toString());
        Files.createDirectories(home.resolve(".m2"));
        Files.writeString(home.resolve(".m2/settings.xml"), SETTINGS.formatted("http://127.0.0.1:1/home-mirror"));
    }

    @AfterEach
    void restore() {
        System.setProperty("user.home", savedHome);
        if (savedRepos == null) System.clearProperty("redkite.maven.repositories");
        else System.setProperty("redkite.maven.repositories", savedRepos);
    }

    private static Store newStore() {
        return Store.connect("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1", "sa", "");
    }

    @Test
    void repositoriesComeFromHomeSettingsThenFromTheProject() throws Exception {
        Store store = newStore();
        assertEquals(home.resolve(".m2/settings.xml").toAbsolutePath().toString(), store.mavenSettingsPath);
        assertEquals(List.of("http://127.0.0.1:1/home-mirror"), store.effectiveMavenRepos);

        // A project with no settings of its own keeps the home settings.
        Path plain = Files.createDirectories(home.resolve("plain"));
        store.reconfigureForProject(plain);
        assertEquals(List.of("http://127.0.0.1:1/home-mirror"), store.effectiveMavenRepos);

        Path project = Files.createDirectories(home.resolve("project/.m2"));
        Files.writeString(project.resolve("settings.xml"), SETTINGS.formatted("http://127.0.0.1:1/project-mirror"));
        store.reconfigureForProject(project.getParent());
        assertEquals(project.resolve("settings.xml").toAbsolutePath().toString(), store.mavenSettingsPath);
        assertEquals(List.of("http://127.0.0.1:1/project-mirror"), store.effectiveMavenRepos);
    }

    @Test
    void anExplicitRepositoryListOverridesSettings() {
        System.setProperty("redkite.maven.repositories", "http://127.0.0.1:1/explicit");
        Store store = newStore();
        assertNull(store.mavenSettingsPath);
        assertEquals(List.of("http://127.0.0.1:1/explicit"), store.effectiveMavenRepos);
        store.reconfigureForProject(home);
        assertEquals(List.of("http://127.0.0.1:1/explicit"), store.effectiveMavenRepos);
    }

    /** Enforcer results belong to a scan; a bare row is enough to satisfy the foreign key. */
    private static String insertScan(Store store) throws Exception {
        String projectId = UUID.randomUUID().toString(), scanId = UUID.randomUUID().toString();
        try (var c = store.connection(); var st = c.createStatement()) {
            st.executeUpdate("insert into projects (id, name, root_path) values ('" + projectId + "', 'p', '/p/" + projectId + "')");
            st.executeUpdate("insert into scans (id, project_id, project_name, repo_path, branch_name, head_commit, working_tree_clean,"
                    + " raw_input_json, report_json, complete, completeness_message) values ('" + scanId + "', '" + projectId
                    + "', 'p', '/p', 'main', 'abc', true, '', '', true, 'ok')");
        }
        return scanId;
    }

    @Test
    void enforcerResultsRoundTrip() throws Exception {
        Store store = newStore();
        String s1 = insertScan(store), s2 = insertScan(store);
        TransitiveConflictFinding finding = new TransitiveConflictFinding("g", "a", "1.0", List.of("0.9"), List.of("p"),
                "dependencyConvergence", null, List.of());
        store.saveEnforcerResult(s1, EnforcerStatus.ENFORCER_RUN_PASSED, null, List.of(finding),
                List.of("x:y", "quote\"d", "back\\slash, comma"), null, 2, List.of(), List.of("g:a:1.0"));

        Store.EnforcerResultEntry entry = store.getEnforcerResult(s1);
        assertEquals(EnforcerStatus.ENFORCER_RUN_PASSED, entry.status());
        assertEquals("", entry.rawOutput());
        assertEquals(List.of(finding), entry.findings());
        assertEquals(List.of("x:y", "quote\"d", "back\\slash, comma"), entry.staleExclusions());
        assertNull(entry.phase2Findings());
        assertEquals(2, entry.exclusionsStripped());
        assertEquals(List.of(), entry.depMgmtRemoved());
        assertEquals(List.of("g:a:1.0"), entry.phase2Pins());

        store.saveEnforcerResult(s2, EnforcerStatus.ENFORCER_NOT_CONFIGURED, "out", List.of(), null, List.of(finding), 0, null, null);
        assertEquals(List.of(finding), store.getEnforcerResult(s2).phase2Findings());

        String missing = UUID.randomUUID().toString();
        assertNull(store.getEnforcerResult(missing));
        assertEquals(Map.of(), store.getEnforcerResults(List.of()));
        assertEquals(List.of(s1, s2), List.copyOf(store.getEnforcerResults(List.of(s1, missing, s2)).keySet()));

        // Saving against an unknown scan is logged, not thrown.
        store.saveEnforcerResult(missing, EnforcerStatus.ENFORCER_RUN_PASSED, "", List.of(), List.of(), null, 0, List.of(), List.of());
        assertNull(store.getEnforcerResult(missing));
    }

    @Test
    void withoutAnySettingsMavenCentralIsUsed() throws Exception {
        Files.delete(home.resolve(".m2/settings.xml"));
        Store store = newStore();
        assertNull(store.mavenSettingsPath);
        assertEquals(List.of("https://repo1.maven.org/maven2"), store.effectiveMavenRepos);
        store.reconfigureForProject(home);
        assertNull(store.mavenSettingsPath);
    }

    @Test
    void theFirstMirrorWithAUsernameSuppliesCredentials() throws Exception {
        Files.writeString(home.resolve(".m2/settings.xml"), """
                <settings>
                  <servers>
                    <server><id>blank</id><username> </username></server>
                    <server><id>named</id><username>u</username><password>p</password></server>
                  </servers>
                  <mirrors>
                    <mirror><id>anonymous</id><mirrorOf>central</mirrorOf><url>http://127.0.0.1:1/a</url></mirror>
                    <mirror><id>blank</id><mirrorOf>central</mirrorOf><url>http://127.0.0.1:1/b</url></mirror>
                    <mirror><id>named</id><mirrorOf>central</mirrorOf><url>http://127.0.0.1:1/c</url></mirror>
                  </mirrors>
                </settings>
                """);
        assertEquals(List.of("http://127.0.0.1:1/a", "http://127.0.0.1:1/b", "http://127.0.0.1:1/c"), newStore().effectiveMavenRepos);
    }

    @Test
    void unknownProjectsAndUnreadableEnforcerRows() throws Exception {
        Store store = newStore();
        String missing = UUID.randomUUID().toString();
        assertThrows(IllegalArgumentException.class, () -> store.getProject(missing));
        assertFalse(store.getProjectEnforcerUseVerify(missing));

        String scan = insertScan(store);
        store.saveEnforcerResult(scan, EnforcerStatus.ENFORCER_RUN_PASSED, "", List.of(), List.of(), null, 0, List.of(), List.of());
        try (var c = store.connection(); var st = c.createStatement()) {
            st.executeUpdate("update enforcer_results set status = 'NO_SUCH_STATUS', stale_exclusions_json = '' where scan_id = '" + scan + "'");
        }
        assertNull(store.getEnforcerResult(scan), "an unreadable row is treated as absent");
    }

    @Test
    void ingestPersistsTheFinalReportMetadataRowsAndPrunesOldScans() throws Exception {
        String savedOsv = System.getProperty("redkite.osv.url");
        System.setProperty("redkite.osv.url", "http://127.0.0.1:1");
        try {
            Store store = newStore();
            store.licenseResolver = new com.redkite.maven.LicenseResolver((g, a, v) -> new com.redkite.maven.PomFetchResult.NotFound());
            Path project = Files.createDirectories(home.resolve("proj"));
            Files.writeString(project.resolve("pom.xml"), "<project/>");
            com.redkite.core.domain.ScanComponent lib = new com.redkite.core.domain.ScanComponent(1,
                    new com.redkite.core.domain.ComponentCoordinate("g", "lib"), "1.0", com.redkite.core.domain.DependencyScope.COMPILE,
                    true, com.redkite.core.domain.VersionSource.LITERAL, "pom.xml", null, Map.of(), false, null, "pom.xml");
            com.redkite.core.domain.ScanComponent unfiled = new com.redkite.core.domain.ScanComponent(2,
                    new com.redkite.core.domain.ComponentCoordinate("g", "unfiled"), "2.0", com.redkite.core.domain.DependencyScope.COMPILE,
                    false, com.redkite.core.domain.VersionSource.UNKNOWN, " ", null, Map.of(), false, null, "pom.xml");
            com.redkite.core.domain.ScanInput input = new com.redkite.core.domain.ScanInput("proj", project.toString(), project.toString(),
                    "main", "abc", true, false, java.time.Instant.now(), List.of(lib, unfiled), List.of(), Map.of(), List.of());

            List<String> scanIds = new java.util.ArrayList<>();
            for (int i = 0; i < 9; i++) scanIds.add(store.ingest(input).scanId());
            String last = scanIds.get(8);

            assertEquals(last, store.getScan(last).report().scanId(), "the stored report is the final one, not the draft");
            assertEquals(Map.of("pom.xml", "<project/>"), store.loadSourcePoms(last), "blank source paths are not snapshotted");
            try (var c = store.connection(); var st = c.createStatement();
                 var rs = st.executeQuery("select component_group_id, component_artifact_id, component_version, latest_version, metadata_type"
                         + " from metadata_cache_entries where scan_id = '" + last + "' order by component_id, metadata_type")) {
                List<String> rows = new java.util.ArrayList<>();
                while (rs.next()) rows.add(rs.getString(1) + ":" + rs.getString(2) + ":" + rs.getString(3) + ":" + rs.getString(4) + ":" + rs.getString(5));
                assertEquals(List.of("g:lib:1.0:unknown:LICENSE", "g:lib:1.0:unknown:VERSION", "g:lib:1.0:unknown:VULNERABILITY",
                        "g:unfiled:2.0:unknown:LICENSE", "g:unfiled:2.0:unknown:VERSION", "g:unfiled:2.0:unknown:VULNERABILITY"), rows);
            }
            String projectId = store.getScan(last).projectId();
            assertEquals(7, store.listScansForProject(projectId).size(), "only the seven most recent scans are kept");
        } finally {
            if (savedOsv == null) System.clearProperty("redkite.osv.url"); else System.setProperty("redkite.osv.url", savedOsv);
        }
    }
}
