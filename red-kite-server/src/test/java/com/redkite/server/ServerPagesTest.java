package com.redkite.server;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipInputStream;

import static org.junit.jupiter.api.Assertions.*;

/** Read-only pages and APIs over one analysis of the demo project. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ServerPagesTest {
    private ServerFixture fx;
    private String scanId;
    private String projectId;
    private String scanPage;

    @BeforeAll
    void analyse(@TempDir Path tempDir) throws Exception {
        fx = new ServerFixture(tempDir);
        scanId = fx.analyseDemo();
        Matcher m = Pattern.compile("href=\"/projects/([^\"]+)\"").matcher(fx.get("/").body());
        assertTrue(m.find());
        projectId = m.group(1);
        scanPage = fx.get("/scans/" + scanId).body();
    }

    @AfterAll
    void stop() {
        fx.close();
    }

    /** The visible text of an HTML page: tags, scripts and styles removed, whitespace collapsed. */
    static String text(String html) {
        String s = html.replaceAll("(?s)<style.*?</style>", " ").replaceAll("(?s)<script.*?</script>", " ");
        s = s.replaceAll("<[^>]+>", " ");
        return decodeEntities(s).replace('\u00a0', ' ').replaceAll("\\s+", " ");
    }

    private static final java.util.Map<String, String> NAMED_ENTITIES = java.util.Map.of(
            "amp", "&", "lt", "<", "gt", ">", "quot", "\"", "rarr", "→", "mdash", "—", "nbsp", " ", "apos", "'", "middot", "·");

    static String decodeEntities(String s) {
        Matcher m = Pattern.compile("&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);").matcher(s);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String e = m.group(1);
            String replacement;
            if (e.startsWith("#x")) replacement = new String(Character.toChars(Integer.parseInt(e.substring(2), 16)));
            else if (e.startsWith("#")) replacement = new String(Character.toChars(Integer.parseInt(e.substring(1))));
            else replacement = NAMED_ENTITIES.getOrDefault(e, m.group());
            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(out);
        return out.toString();
    }

    /** The component card for one coordinate on the scan page, as text. */
    private String card(String coordinate) {
        return card(scanPage, coordinate);
    }

    static String card(String page, String coordinate) {
        int start = page.indexOf("data-coord=\"" + coordinate + "\"");
        assertTrue(start >= 0, coordinate + " not on the page");
        int end = page.indexOf("<div class=\"rem-card\"", start);
        return text(page.substring(page.lastIndexOf('<', start), end < 0 ? page.length() : end));
    }

    private long componentId(String groupId, String artifactId) {
        return componentId(scanPage, groupId, artifactId);
    }

    static long componentId(String page, String groupId, String artifactId) {
        Matcher m = Pattern.compile("data-coord=\"" + Pattern.quote(groupId + ":" + artifactId) + "\"[^>]*?data-comp-id=\"(\\d+)\"")
                .matcher(page);
        assertTrue(m.find(), "no component id for " + groupId + ":" + artifactId);
        return Long.parseLong(m.group(1));
    }

    // ---------------------------------------------------------------- simple routes

    @Test
    void healthAndMethodChecks() throws Exception {
        assertEquals("ok", fx.get("/health").body());
        assertEquals(405, fx.post("/health", "").status());
        assertEquals(405, fx.post("/", "").status());
        assertEquals(405, fx.post("/config", "").status());
        assertEquals(405, fx.send("PUT", "/projects/" + projectId, "").status());
        assertEquals(404, fx.get("/projects").status());
        assertEquals(404, fx.get("/scans").status());
        assertEquals(405, fx.get("/api/scan").status());
        assertEquals(405, fx.get("/api/prefs").status());
        assertEquals(405, fx.get("/api/config").status());
        assertEquals(405, fx.get("/api/config/license-ranks").status());
        assertEquals(405, fx.get("/api/metadata/clear").status());
        assertEquals(405, fx.get("/api/projects/" + projectId).status());
        assertEquals(405, fx.post("/api/scan-status", "").status());
        assertEquals(405, fx.post("/api/scans/enforcer", "").status());
        assertEquals(405, fx.get("/api/scans/remediation/apply").status());
        assertEquals(405, fx.get("/api/scans/remediation/apply-batch").status());
        assertEquals(405, fx.post("/api/scans/remediation/apply-status", "").status());
        assertEquals(405, fx.get("/api/scans/remediation/resolve").status());
        assertEquals(405, fx.get("/api/scans/remediation/plan").status());
        assertEquals(405, fx.get("/api/scans/pom/write?scanId=" + scanId).status());
        assertEquals(405, fx.send("PUT", "/api/scans/pom?scanId=" + scanId, "").status());
    }

    @Test
    void logoIsServedAsSvg() throws Exception {
        ServerFixture.Response logo = fx.get("/logo.svg");
        assertEquals(200, logo.status());
        assertTrue(logo.headers().firstValue("Content-Type").orElse("").contains("svg"));
        assertTrue(logo.body().contains("<svg"));
    }

    @Test
    void handlerFailuresBecome500WithTheCauseChain() throws Exception {
        ServerFixture.Response r = fx.get("/scans/no-such-scan");
        assertEquals(500, r.status());
        assertTrue(r.body().startsWith("RedKite error: "), r.body());
    }

    // ---------------------------------------------------------------- pages

    @Test
    void homeListsTheAnalysedProject() throws Exception {
        String home = fx.get("/").body();
        assertTrue(home.contains("<title>"), home);
        String t = text(home);
        assertTrue(t.contains("Analyse project"));
        assertTrue(t.contains("demo " + fx.project), t);
        assertTrue(home.contains("triggerScan(&#39;") || home.contains("triggerScan('") || home.contains("triggerScan(&apos;"), home);
    }

    @Test
    void projectPageShowsSettingsRepositoriesConfigAndHistory() throws Exception {
        String page = fx.get("/projects/" + projectId).body();
        String t = text(page);
        assertTrue(t.contains("demo " + fx.project), t);
        assertTrue(t.contains("Settings " + fx.home.resolve(".m2/settings.xml")), t);
        assertTrue(t.contains("Repositories " + fx.fileRepo.toUri().toString().replaceAll("/$", "")), t);
        assertTrue(t.contains("Project configuration"), t);
        // The analysis wrote a default .redkite/settings.yml into the project.
        assertTrue(t.contains("File " + fx.project.resolve(".redkite/settings.yml")), t);
        assertTrue(t.contains("Latest analysis"), t);
        assertTrue(t.contains("Components 15"), t);
        assertTrue(t.contains("Status Complete"), t);
        assertTrue(t.contains("Analysis history"), t);
        assertTrue(page.contains("href=\"/scans/" + scanId + "\""));
        assertTrue(t.contains("latest"), t);
    }

    @Test
    void projectPageShowsAConfiguredProfileAndMissingSettings() throws Exception {
        java.nio.file.Path config = fx.project.resolve(".redkite/settings.yml");
        java.nio.file.Path settings = fx.home.resolve(".m2/settings.xml");
        String savedConfig = Files.readString(config), savedSettings = Files.readString(settings);
        try {
            Files.writeString(config, "redkite:\n  maven:\n    args: -X\n    profile: ci\n    spring:\n      profiles: smoke\n");
            Files.delete(settings);
            String t = text(fx.get("/projects/" + projectId).body());
            assertTrue(t.contains("Settings none (using Maven Central)"), t);
            assertTrue(t.contains("Maven arguments -X"), t);
            assertTrue(t.contains("Profile ci"), t);
            assertTrue(t.contains("Spring Boot profiles smoke"), t);
        } finally {
            Files.writeString(config, savedConfig);
            Files.writeString(settings, savedSettings);
        }
    }

    @Test
    void scanPageSummarisesTheAnalysis() {
        String t = text(scanPage);
        assertTrue(t.contains("demo Complete"), t);
        assertTrue(t.contains("15 components 13 need remediation 2 clean"), t);
        assertTrue(t.contains("☢ 1 Critical ☠ 2 High ⚠ 1 Medium ℹ 1 Low ⚡ 1 Snapshot"), t);
        assertTrue(t.contains("CVE Upgrade 2 CVE Downgrade 1 CVE Nofix 1 Conflict 1 Outdated 4 Snapshot 1"), t);
        assertTrue(t.contains("Direct 11 Transitive 4"), t);
    }

    @Test
    void scanPageShowsLicenseBreakdown() {
        String t = text(scanPage);
        assertTrue(t.contains("License information"), t);
        assertTrue(t.contains("📜 10 ASL-2.0"), t);
        assertTrue(t.contains("📜 1 EPL-1.0"), t);
        assertTrue(t.contains("📜 1 GNU General Public License v3.0"), t);
        assertTrue(t.contains("📜 1 No License"), t);
    }

    @Test
    void scanPageShowsCveUpgradeRecommendation() {
        String card = card("com.fasterxml.jackson.core:jackson-databind");
        assertTrue(card.contains("☢ Critical"), card);
        assertTrue(card.contains("Current: 2.13.0 → Recommended: 2.13.4 (Latest: 2.15.2)"), card);
        assertTrue(card.contains("CVE-2099-1000, CVE-2099-1001"), card);
        assertTrue(card.contains("2.13.4 — recommended, fixes CVE, latest same minor"), card);
        assertTrue(card.contains("2.12.7 — critical severity"), card);
    }

    @Test
    void scanPageShowsTransitiveCveFix() {
        String card = card("org.other:transitive-vuln");
        assertTrue(card.contains("☠ High transitive runtime"), card);
        assertTrue(card.contains("Current: 1.0 → Recommended: 1.1 (Latest: 2.0)"), card);
        assertTrue(card.contains("1.1 — recommended, fixes CVE"), card);
    }

    @Test
    void scanPageShowsCveWithoutFixAndDowngrade() {
        String nofix = card("org.yaml:snakeyaml");
        assertTrue(nofix.contains("⚠ Medium"), nofix);
        assertTrue(nofix.contains("MIT ASL-2.0"), nofix);
        assertTrue(nofix.contains("1.33 — latest, medium severity"), nofix);

        String downgrade = card("org.bad:downgrade");
        assertTrue(downgrade.contains("Current: 2.1 → Downgrade to: 2.0"), downgrade);
        assertTrue(downgrade.contains("Downgrade to 2.0"), downgrade);
        assertTrue(downgrade.contains("2.0 — recommended, fixes CVE"), downgrade);
    }

    @Test
    void scanPageShowsOutdatedSnapshotAndUpToDateComponents() {
        assertTrue(card("org.apache.commons:commons-lang3").contains("Current: 3.12.0 → Recommended: 3.13.0 (Latest: 3.14.0)"));
        assertTrue(card("org.slf4j:slf4j-api").contains("Current: 1.7.36 (Latest: 2.0.9)"), "no major upgrade recommended");
        String snapshot = card("org.example:snap");
        assertTrue(snapshot.contains("Snapshot dependency"), snapshot);
        assertTrue(snapshot.contains("1.0 — recommended"), snapshot);
        assertTrue(card("junit:junit").contains("declared test EPL-1.0 Current: 4.13.2 (Latest: 4.13.2)"));
        assertTrue(card("org.apache.maven.plugins:maven-compiler-plugin").contains("plugin build"));
        assertTrue(card("org.springframework.boot:spring-boot-starter-parent").contains("Recommended: 3.1.5"));
        assertTrue(card("org.other:uses-old-core").contains("In dependencies: ☠ 1"));
    }

    @Test
    void scanPageShowsConvergenceConflictAndVerifiedAutoFix() {
        String conflict = card("com.fasterxml.jackson.core:jackson-core");
        assertTrue(conflict.contains("△ Conflict"), conflict);
        assertTrue(conflict.contains("2.12.0 — conflict"), conflict);
        String t = text(scanPage);
        assertTrue(t.contains("Dependency management 1 conflict Auto-fix verified"), t);
        assertTrue(t.contains("com.fasterxml.jackson.core:jackson-core → 2.13.0"), t);
        assertTrue(t.contains("Pristine analysis: 1 dep-management entry removed"), t);
    }

    @Test
    void scanPageHasAnAnalysisLog() {
        String t = text(scanPage);
        assertTrue(t.contains("Analysis log"), t);
        assertTrue(t.contains("Analysis complete. Dependency and vulnerability metadata was checked"), t);
        assertTrue(t.contains("Maven repositories " + fx.httpBase + "/repo"), t);
        assertTrue(t.contains("Dep-management cleared (1 entry): - org.own:managed:1.0"), t);
    }

    @Test
    void configPageListsTtlsAndLicenseRanks() throws Exception {
        String page = fx.get("/config").body();
        String t = text(page);
        assertTrue(t.contains("RedKite version dev"), t);
        assertTrue(t.contains("Vulnerability lookup cache (OSV.dev)"), t);
        assertTrue(t.contains("License lookup cache (POM licenses)"), t);
        assertTrue(page.contains("<option value=\"1440\" selected>1 day</option>"), "the 24h default is preselected");
        assertTrue(t.contains("License permissiveness"), t);
        assertTrue(page.contains("name=\"license_0\""));
        assertTrue(page.contains("name=\"license_new\""));
    }

    // ---------------------------------------------------------------- read-only APIs

    @Test
    void enforcerResultsApi() throws Exception {
        String json = fx.get("/api/scans/enforcer?scanId=" + scanId).body();
        assertTrue(json.startsWith("{\"status\":\"ENFORCER_RUN_FAILED_WITH_FINDINGS\",\"findings\":[{\"groupId\":\"com.fasterxml.jackson.core\""), json);
        assertTrue(json.contains("\"conflictingVersions\":[\"2.12.0\"]"), json);
        assertTrue(json.contains("\"type\":\"ADD_EXCLUSION\""), json);
        assertTrue(json.endsWith("\"staleExclusions\":[]}"), json);

        assertEquals(400, fx.get("/api/scans/enforcer").status());
        assertEquals("{\"status\":\"ENFORCER_NOT_CONFIGURED\",\"findings\":[]}", fx.get("/api/scans/enforcer?scanId=unknown").body());
    }

    @Test
    void scanStatusApiErrors() throws Exception {
        assertEquals(400, fx.get("/api/scan-status").status());
        assertEquals(404, fx.get("/api/scan-status?jobId=nope").status());
        assertEquals(400, fx.get("/api/scans/remediation/apply-status").status());
        assertEquals(404, fx.get("/api/scans/remediation/apply-status?jobId=nope").status());
    }

    @Test
    void scanApiRejectsBadPaths() throws Exception {
        assertEquals(400, fx.post("/api/scan", "{}").status());
        assertEquals(400, fx.post("/api/scan", "{\"path\":\"  \"}").status());
        ServerFixture.Response notDir = fx.post("/api/scan", "{\"path\":" + ServerFixture.json(fx.project.resolve("pom.xml").toString()) + "}");
        assertEquals(400, notDir.status());
        assertTrue(notDir.body().startsWith("Not a directory"));
        ServerFixture.Response noPom = fx.post("/api/scan", "{\"path\":" + ServerFixture.json(fx.home.toString()) + "}");
        assertEquals(400, noPom.status());
        assertTrue(noPom.body().startsWith("No pom.xml found"));
    }

    @Test
    void pomDownloadReturnsTheSourcePom() throws Exception {
        ServerFixture.Response r = fx.get("/api/scans/pom?scanId=" + scanId);
        assertEquals(200, r.status());
        assertEquals("attachment; filename=\"pom.xml\"", r.headers().firstValue("Content-Disposition").orElse(""));
        assertEquals(ServerFixture.DEMO_POM, r.body());
        assertEquals(400, fx.get("/api/scans/pom").status());
        assertEquals(404, fx.get("/api/scans/pom?scanId=" + java.util.UUID.randomUUID()).status());
    }

    @Test
    void pomPatchPreviewNormalisesAndUpgradesVersions() throws Exception {
        long lang = componentId("org.apache.commons", "commons-lang3");
        long databind = componentId("com.fasterxml.jackson.core", "jackson-databind");
        ServerFixture.Response r = fx.post("/api/scans/pom?scanId=" + scanId, lang + "=3.14.0&" + databind + "=2.13.4");
        assertEquals(200, r.status(), r.body());
        String pom = ServerFixture.field(r.body(), "pom.xml");
        assertTrue(pom.contains("<commons-lang3.version>3.14.0</commons-lang3.version>"), pom);
        assertTrue(pom.contains("<version>${commons-lang3.version}</version>"), pom);
        assertTrue(pom.contains("<jackson.version>2.13.4</jackson.version>"), pom);
        assertFalse(pom.contains("stale-thing.version"), "unreferenced *.version properties are dropped");
        assertEquals(ServerFixture.DEMO_POM, fx.projectPom(), "a preview never writes the project");
    }

    @Test
    void pomPatchPreviewPinsAndRequiresUpdates() throws Exception {
        long slf4j = componentId("org.slf4j", "slf4j-api");
        long core = componentId("com.fasterxml.jackson.core", "jackson-core");
        ServerFixture.Response r = fx.post("/api/scans/pom?scanId=" + scanId, "pinned=" + slf4j + "," + core + ",x");
        assertEquals(200, r.status(), r.body());
        String pom = ServerFixture.field(r.body(), "pom.xml");
        assertTrue(pom.contains("redkite:user-pin version=\"1.7.36\""), pom);
        assertTrue(pom.contains("<artifactId>jackson-core</artifactId>"), pom);

        assertEquals(400, fx.post("/api/scans/pom?scanId=" + scanId, "").status());
        assertEquals("{}", fx.post("/api/scans/pom?scanId=" + scanId, "999999=1.0").body());
        assertEquals(500, fx.post("/api/scans/pom?scanId=unknown", "1=2").status());
    }

    @Test
    void resolveApiReturnsCandidateUpdates() throws Exception {
        long databind = componentId("com.fasterxml.jackson.core", "jackson-databind");
        ServerFixture.Response r = fx.post("/api/scans/remediation/resolve", "{\"scanId\":\"" + scanId
                + "\",\"selections\":[{\"componentId\":\"" + databind + "\",\"targetVersion\":\"2.13.4\"},{\"componentId\":\"x\",\"targetVersion\":\"1\"},{\"targetVersion\":\"1\"}]}");
        assertEquals(200, r.status(), r.body());
        assertTrue(r.body().startsWith("[{\"action\":"), r.body());
        assertTrue(r.body().contains("\"proposedValue\":\"2.13.4\""), r.body());
        assertTrue(r.body().contains("\"reason\":\"CVE\"") || r.body().contains("\"findingsAddressed\":[{"), r.body());

        assertEquals(400, fx.post("/api/scans/remediation/resolve", "{}").status());
        assertEquals(400, fx.post("/api/scans/remediation/resolve", "{\"scanId\":\"" + scanId + "\"}").status());
        assertEquals(400, fx.post("/api/scans/remediation/resolve", "{\"scanId\":\"" + scanId
                + "\",\"selections\":[{\"componentId\":\"999999\",\"targetVersion\":\"1\"}]}").status());
        assertEquals(500, fx.post("/api/scans/remediation/resolve", "{\"scanId\":\"unknown\",\"selections\":[{\"componentId\":\"1\",\"targetVersion\":\"1\"}]}").status());
    }

    @Test
    void planApiReturnsAlternatives() throws Exception {
        long databind = componentId("com.fasterxml.jackson.core", "jackson-databind");
        ServerFixture.Response r = fx.post("/api/scans/remediation/plan",
                "{\"scanId\":\"" + scanId + "\",\"componentId\":" + databind + ",\"targetVersion\":\"2.13.4\"}");
        assertEquals(200, r.status(), r.body());
        assertTrue(r.body().startsWith("{\"findingsAddressed\":[{\"componentId\":" + databind), r.body());
        assertTrue(r.body().contains("\"severity\":\"CRITICAL\""), r.body());
        assertTrue(r.body().contains("\"candidates\":[{"), r.body());

        assertEquals(400, fx.post("/api/scans/remediation/plan", "{\"scanId\":\"" + scanId + "\"}").status());
        assertEquals(400, fx.post("/api/scans/remediation/plan", "{\"scanId\":\"" + scanId + "\",\"componentId\":\"x\",\"targetVersion\":\"1\"}").status());
        assertEquals(404, fx.post("/api/scans/remediation/plan", "{\"scanId\":\"" + scanId + "\",\"componentId\":999999,\"targetVersion\":\"1\"}").status());
        assertEquals(500, fx.post("/api/scans/remediation/plan", "{\"scanId\":\"unknown\",\"componentId\":1,\"targetVersion\":\"1\"}").status());
    }

    @Test
    void osvWasQueriedOncePerPackage() {
        List<String> queries = new ArrayList<>(fx.osvQueries);
        assertEquals(queries.stream().distinct().count(), queries.size(), queries.toString());
        assertTrue(queries.contains("com.fasterxml.jackson.core:jackson-databind"));
    }

    @Test
    void zipDownloadWhenSeveralPomsAreStored() throws Exception {
        // A single-module scan stores one POM, so the download is plain XML; the ZIP branch is
        // exercised in the multi-module test. Here: the response really is a POM, not a ZIP.
        byte[] body = fx.getBytes("/api/scans/pom?scanId=" + scanId).body();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(body))) {
            assertNull(zip.getNextEntry());
        }
        assertTrue(Files.exists(fx.project.resolve(".redkite/settings.yml")));
    }
}
