package com.redkite.server;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.redkite.server.ServerFixture.field;
import static com.redkite.server.ServerFixture.json;
import static com.redkite.server.ServerPagesTest.text;
import static org.junit.jupiter.api.Assertions.*;

/** APIs that change something — the project's POMs, preferences, configuration or stored data.
 *  Each test gets its own server, database and freshly analysed demo project. */
class ServerMutationsTest {
    @TempDir
    Path tempDir;

    private ServerFixture fx;
    private String scanId;

    @BeforeEach
    void setUp() throws Exception {
        fx = new ServerFixture(tempDir);
        scanId = fx.analyseDemo();
    }

    @AfterEach
    void tearDown() {
        fx.close();
    }

    private String projectId() throws Exception {
        Matcher m = Pattern.compile("href=\"/projects/([^\"]+)\"").matcher(fx.get("/").body());
        assertTrue(m.find());
        return m.group(1);
    }

    private String applyBody(String actionType, String extra) {
        return "{\"scanId\":\"" + scanId + "\",\"actionType\":\"" + actionType + "\",\"groupId\":\"com.fasterxml.jackson.core\","
                + "\"artifactId\":\"jackson-core\"" + extra + "}";
    }

    private Path workDir() {
        return fx.project.resolve(".redkite/work");
    }

    // ---------------------------------------------------------------- single remediation

    @Test
    void applyDependencyManagementPinWritesThePomWithASummary() throws Exception {
        ServerFixture.Response r = fx.post("/api/scans/remediation/apply", applyBody("ADD_DEPENDENCY_MANAGEMENT", ",\"version\":\"2.13.0\""));

        assertEquals("{\"status\":\"ok\"}", r.body());
        String pom = fx.projectPom();
        assertTrue(pom.contains("redkite:dependency-management pin groupId=\"com.fasterxml.jackson.core\" artifactId=\"jackson-core\" version=\"2.13.0\""), pom);
        assertTrue(pom.contains("redkite:pin-summary 1 redkite pin(s) (0 user pinned)"), pom);
    }

    @Test
    void applyExclusionWritesThePom() throws Exception {
        ServerFixture.Response r = fx.post("/api/scans/remediation/apply", applyBody("ADD_EXCLUSION",
                ",\"parentGroupId\":\"org.other\",\"parentArtifactId\":\"uses-old-core\",\"pomFile\":" + json(fx.project.resolve("pom.xml").toString())));

        assertEquals(200, r.status(), r.body());
        String pom = fx.projectPom();
        assertTrue(pom.contains("<exclusion>"), pom);
        assertTrue(pom.contains("redkite:exclusion"), pom);
    }

    @Test
    void applyRejectsIncompleteOrUnsafeRequests() throws Exception {
        assertEquals(400, fx.post("/api/scans/remediation/apply", "{\"scanId\":\"" + scanId + "\"}").status());
        assertEquals(400, fx.post("/api/scans/remediation/apply", applyBody("ADD_EXCLUSION", "")).status());
        assertEquals(400, fx.post("/api/scans/remediation/apply", applyBody("ADD_DEPENDENCY_MANAGEMENT", "")).status());
        ServerFixture.Response unknown = fx.post("/api/scans/remediation/apply", applyBody("DELETE_EVERYTHING", ""));
        assertEquals(400, unknown.status());
        assertEquals("Unknown actionType: DELETE_EVERYTHING", unknown.body());
        ServerFixture.Response outside = fx.post("/api/scans/remediation/apply",
                applyBody("ADD_DEPENDENCY_MANAGEMENT", ",\"version\":\"1\",\"pomFile\":" + json(tempDir.resolve("elsewhere/pom.xml").toString())));
        assertEquals(400, outside.status());
        assertEquals("POM path outside project root", outside.body());
        assertEquals(500, fx.post("/api/scans/remediation/apply",
                "{\"scanId\":\"" + UUID.randomUUID() + "\",\"actionType\":\"X\",\"groupId\":\"g\",\"artifactId\":\"a\"}").status());
        assertEquals(ServerFixture.DEMO_POM, fx.projectPom());
    }

    // ---------------------------------------------------------------- batch apply

    private String startBatch(String actions, String patches) throws Exception {
        String body = "{\"scanId\":\"" + scanId + "\",\"remediationActions\":[" + actions + "]"
                + (patches == null ? "" : ",\"pomPatches\":" + patches) + "}";
        ServerFixture.Response r = fx.post("/api/scans/remediation/apply-batch", body);
        assertEquals(200, r.status(), r.body());
        return field(r.body(), "jobId");
    }

    private static final String PIN_DATABIND = "{\"actionType\":\"ADD_DEPENDENCY_MANAGEMENT\",\"groupId\":\"com.fasterxml.jackson.core\","
            + "\"artifactId\":\"jackson-databind\",\"version\":\"2.13.4\",\"pomFile\":\"pom.xml\"}";

    @Test
    void batchApplyValidatesWritesAndCleansUp() throws Exception {
        String exclusion = "{\"actionType\":\"ADD_EXCLUSION\",\"parentGroupId\":\"org.other\",\"parentArtifactId\":\"uses-old-core\","
                + "\"groupId\":\"com.fasterxml.jackson.core\",\"artifactId\":\"jackson-core\"}";
        String skipped = "{\"actionType\":\"ADD_EXCLUSION\",\"groupId\":\"g\"},{\"actionType\":\"OTHER\"},{\"actionType\":\"ADD_DEPENDENCY_MANAGEMENT\",\"groupId\":\"g\"}";

        String status = fx.awaitApply(startBatch(PIN_DATABIND + "," + exclusion + "," + skipped, null));

        assertEquals("{\"status\":\"done\",\"baselinePassed\":true,\"noChanges\":false}", status);
        String pom = fx.projectPom();
        assertTrue(pom.contains("artifactId=\"jackson-databind\" version=\"2.13.4\""), pom);
        assertTrue(pom.contains("<exclusion>"), pom);
        long builds = fx.mvnCalls().stream().filter(c -> c.contains(" install ")).count();
        assertEquals(2, builds, "validated before and after writing");
        assertTrue(Files.exists(workDir().resolve("build.log")));
        assertFalse(Files.exists(workDir().resolve("pristine")), "backups are removed after a successful apply");
    }

    @Test
    void batchApplyWritesPomPatchesInsideTheProjectOnly() throws Exception {
        String patched = ServerFixture.DEMO_POM.replace("<version>3.12.0</version>", "<version>3.14.0</version>");
        String patches = "{\"pom.xml\":" + json(patched) + ",\"../escape/pom.xml\":\"<project/>\"}";

        String status = fx.awaitApply(startBatch("", patches));

        assertTrue(status.contains("\"status\":\"done\""), status);
        assertTrue(fx.projectPom().contains("<version>3.14.0</version>"));
        assertFalse(Files.exists(tempDir.resolve("escape/pom.xml")));
    }

    @Test
    void batchApplyWithNothingToChangeSkipsTheBuild() throws Exception {
        // The pin-summary refresh is itself a change, so seed the POM with the summary it would write.
        String patches = "{\"pom.xml\":" + json(ServerFixture.DEMO_POM) + "}";
        String first = fx.awaitApply(startBatch("", patches));
        assertTrue(first.contains("\"noChanges\":false"), first);

        int buildsBefore = fx.mvnCalls().size();
        String again = fx.awaitApply(startBatch("", "{\"pom.xml\":" + json(fx.projectPom()) + "}"));

        assertEquals("{\"status\":\"done\",\"baselinePassed\":true,\"noChanges\":true}", again);
        assertEquals(buildsBefore, fx.mvnCalls().size());
    }

    @Test
    void failedValidationRevertsAndAttributesTheFailure() throws Exception {
        fx.mvnRule("install", "jackson-databind\" version=\"2.13.4\"", 1,
                "[ERROR] Failed to execute goal on project demo: Could not resolve artifact com.fasterxml.jackson.core:jackson-databind:jar:2.13.4 in central\n");

        String status = fx.awaitApply(startBatch(PIN_DATABIND, null));

        assertTrue(status.startsWith("{\"status\":\"failed\""), status);
        assertEquals("com.fasterxml.jackson.core:jackson-databind", field(status, "attribution"));
        assertEquals("2.13.4", field(status, "failedVersion"));
        assertNull(field(status, "revertedVersion"), "there was no earlier pin to revert to");
        assertTrue(field(status, "message").startsWith("Post-apply validation failed (build): [ERROR] Failed to execute goal"), status);
        assertTrue(field(status, "command").contains("clean install -DskipTests -Denforcer.skip=true"), status);
        assertEquals(workDir().resolve("build.log").toString(), field(status, "logPath"));
        assertEquals(ServerFixture.DEMO_POM, fx.projectPom(), "the original POM is restored");
        assertTrue(Files.readString(workDir().resolve("pom.xml")).contains("version=\"2.13.4\""), "the failing POM is kept for diagnosis");
        assertTrue(Files.exists(workDir().resolve("pristine/pom.xml")));
    }

    @Test
    void failureOnAnAlreadyBrokenProjectIsNotAttributed() throws Exception {
        fx.mvnOutput("install", "[ERROR] Could not find artifact com.fasterxml.jackson.core:jackson-databind:jar:2.13.4\n", 1);

        String status = fx.awaitApply(startBatch(PIN_DATABIND, null));

        assertTrue(status.startsWith("{\"status\":\"failed\""), status);
        assertTrue(field(status, "message").contains("(project was already failing before changes)"), status);
        assertNull(field(status, "attribution"));
    }

    @Test
    void unreadableTargetPomEndsTheJobWithAnError() throws Exception {
        String missing = "{\"actionType\":\"ADD_DEPENDENCY_MANAGEMENT\",\"groupId\":\"g\",\"artifactId\":\"a\",\"version\":\"1\",\"pomFile\":\"missing/pom.xml\"}";

        String status = fx.awaitApply(startBatch(missing, null));

        assertTrue(status.startsWith("{\"status\":\"error\",\"message\":"), status);
        assertTrue(field(status, "message").contains("missing"), status);
    }

    @Test
    void applyStatusReportsTheRunningPhase() throws Exception {
        fx.mvnSleep("install", 1.5);
        String jobId = startBatch(PIN_DATABIND, null);

        String running = fx.get("/api/scans/remediation/apply-status?jobId=" + jobId).body();
        assertTrue(running.startsWith("{\"status\":\"running\",\"phase\":\"pre-validate\",\"log\":["), running);

        assertTrue(fx.awaitApply(jobId).contains("\"status\":\"done\""));
        assertEquals(404, fx.get("/api/scans/remediation/apply-status?jobId=" + jobId).status(), "finished jobs are forgotten");
    }

    @Test
    void batchApplyNeedsAScan() throws Exception {
        assertEquals(400, fx.post("/api/scans/remediation/apply-batch", "{}").status());
        ServerFixture.Response r = fx.post("/api/scans/remediation/apply-batch", "{\"scanId\":\"" + UUID.randomUUID() + "\"}");
        String jobId = field(r.body(), "jobId");
        assertNotNull(jobId, r.body());
        assertEquals(404, fx.get("/api/scans/remediation/apply-status?jobId=" + jobId).status());
    }

    // ---------------------------------------------------------------- writing POMs directly

    @Test
    void pomWriteWritesInsideTheProjectAndRefusesEscapes() throws Exception {
        String patched = ServerFixture.DEMO_POM.replace("3.12.0", "3.13.0");
        ServerFixture.Response ok = fx.post("/api/scans/pom/write?scanId=" + scanId, "{\"pom.xml\":" + json(patched) + "}");
        assertEquals("{\"written\":[\"pom.xml\"]}", ok.body());
        assertEquals(patched, fx.projectPom());

        ServerFixture.Response escape = fx.post("/api/scans/pom/write?scanId=" + scanId, "{\"../x.xml\":\"bad\"}");
        assertEquals(400, escape.status());
        assertFalse(Files.exists(tempDir.resolve("x.xml")));

        assertEquals("{\"written\":[]}", fx.post("/api/scans/pom/write?scanId=" + scanId, "").body());
        assertEquals(400, fx.post("/api/scans/pom/write", "{}").status());
        assertEquals(500, fx.post("/api/scans/pom/write?scanId=" + UUID.randomUUID(), "{\"a\":\"b\"}").status());
    }

    // ---------------------------------------------------------------- preferences and configuration

    @Test
    void themePreferenceIsSavedAndUsed() throws Exception {
        ServerFixture.Response r = fx.post("/api/prefs", "{\"theme\":\"ocean\"}");
        assertEquals("{\"theme\":\"ocean\"}", r.body());
        Properties saved = new Properties();
        try (var reader = Files.newBufferedReader(fx.prefsFile)) { saved.load(reader); }
        assertEquals("ocean", saved.getProperty("theme"));
        assertTrue(fx.get("/").body().contains("data-theme=\"ocean\""));

        assertEquals(400, fx.post("/api/prefs", "{\"theme\":\"neon\"}").status());
        assertEquals(400, fx.post("/api/prefs", "{}").status());
        assertTrue(fx.get("/").body().contains("data-theme=\"ocean\""));
    }

    @Test
    void ttlConfigurationIsValidatedAndSaved() throws Exception {
        ServerFixture.Response r = fx.post("/api/config",
                "cache.ttl.version.fresh=60&cache.ttl.version.local=abc&cache.ttl.version.error=0&unknown.key=5&cache.ttl.license.fresh=45");
        assertEquals(303, r.status());
        assertEquals("/config", r.headers().firstValue("Location").orElse(""));

        String page = fx.get("/config").body();
        assertTrue(page.contains("<option value=\"60\" selected>1 hour</option>"), "fresh TTL saved");
        assertTrue(page.contains("<option value=\"45\" selected>45 minutes (custom)</option>"), "non-preset value kept");
        assertTrue(page.contains("<option value=\"15\" selected>15 minutes</option>"), "invalid values leave the error TTL at its default");
    }

    @Test
    void licenseRanksAreSavedAndNewLicensesAdded() throws Exception {
        ServerFixture.Response r = fx.post("/api/config/license-ranks",
                "license_0=MIT&rank_0=7&license_1=&rank_1=3&license_2=EPL-2.0&rank_2=abc&license_new=WTFPL&rank_new=0");
        assertEquals(303, r.status());

        String t = text(fx.get("/config").body());
        assertTrue(t.contains("WTFPL"), t);
        assertTrue(fx.get("/config").body().contains("value=\"MIT\"><label>MIT</label><div class=\"config-row-input\"><input type=\"number\" name=\"rank_"));
        assertEquals(303, fx.post("/api/config/license-ranks", "license_new=X&rank_new=nope").status());
        assertFalse(text(fx.get("/config").body()).contains(" X "));
    }

    @Test
    void clearingMetadataForcesFreshLookups() throws Exception {
        int before = fx.osvQueries.size();
        assertEquals("{\"cleared\":true}", fx.post("/api/metadata/clear", "").body());

        fx.analyseDemo();

        assertTrue(fx.osvQueries.size() > before, "OSV is queried again after clearing");
    }

    @Test
    void deletingAProjectRemovesItFromTheDashboard() throws Exception {
        String projectId = projectId();
        assertEquals("{\"deleted\":true}", fx.send("DELETE", "/api/projects/" + projectId, null).body());
        assertFalse(fx.get("/").body().contains(projectId));
    }

    @Test
    void reanalysisAddsToTheProjectHistory() throws Exception {
        String second = fx.analyseDemo();
        assertNotEquals(scanId, second);
        String page = fx.get("/projects/" + projectId()).body();
        assertTrue(page.contains("/scans/" + scanId));
        assertTrue(page.contains("/scans/" + second));
    }
}
