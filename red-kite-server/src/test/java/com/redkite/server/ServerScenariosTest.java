package com.redkite.server;

import com.redkite.maven.MavenExecutable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.redkite.server.ServerFixture.field;
import static com.redkite.server.ServerPagesTest.text;
import static org.junit.jupiter.api.Assertions.*;

/** Analyses of projects in other states than the demo's defaults: build failures, enforcer
 *  outcomes, missing metadata, multi-module layouts and project configuration. */
class ServerScenariosTest {
    @TempDir
    Path tempDir;

    private ServerFixture fx;

    @BeforeEach
    void setUp() throws Exception {
        fx = new ServerFixture(tempDir);
    }

    @AfterEach
    void tearDown() {
        fx.close();
    }

    private String scanText(String scanId) throws Exception {
        return text(fx.get("/scans/" + scanId).body());
    }

    private String projectText() throws Exception {
        Matcher m = Pattern.compile("href=\"/projects/([^\"]+)\"").matcher(fx.get("/").body());
        assertTrue(m.find());
        return text(fx.get("/projects/" + m.group(1)).body());
    }

    static final String PINNED_POM = ServerFixture.DEMO_POM
            .replace("<dependency><groupId>org.own</groupId><artifactId>managed</artifactId><version>1.0</version></dependency>",
                    "<dependency><groupId>org.own</groupId><artifactId>managed</artifactId><version>1.0</version></dependency>\n"
                            + "      <!-- redkite:dependency-management pin groupId=\"org.slf4j\" artifactId=\"slf4j-api\" version=\"1.7.36\" reason=\"x\" -->\n"
                            + "      <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>1.7.36</version></dependency>")
            .replace("<dependency><groupId>org.other</groupId><artifactId>uses-old-core</artifactId><version>1.0</version></dependency>",
                    "<dependency><groupId>org.other</groupId><artifactId>uses-old-core</artifactId><version>1.0</version>"
                            + "<exclusions>\n        <!-- redkite:exclusion groupId=\"org.gone\" artifactId=\"thing\" reason=\"old\" -->\n"
                            + "        <exclusion><groupId>org.gone</groupId><artifactId>thing</artifactId></exclusion></exclusions></dependency>");

    @Test
    void passingEnforcerReportsPristineChanges() throws Exception {
        Files.writeString(fx.project.resolve("pom.xml"), PINNED_POM);
        fx.mvnOutput("enforcer:enforce", "[INFO] BUILD SUCCESS\n", 0);

        String scanId = fx.analyseDemo();

        String t = scanText(scanId);
        assertTrue(t.contains("Passed No dependency conflicts found — pristine analysis ran with 2 dep-management entries removed and 1 exclusion stripped. Existing fixes may be stale."), t);
        String enforcer = fx.get("/api/scans/enforcer?scanId=" + scanId).body();
        assertTrue(enforcer.contains("\"staleExclusions\":[\"org.gone:thing\"]"), enforcer);
        assertTrue(projectText().contains("Complete"));
    }

    @Test
    void passingEnforcerWithNothingStripped() throws Exception {
        Files.writeString(fx.project.resolve("pom.xml"), ServerFixture.DEMO_POM.replace(
                "<dependencyManagement>\n    <dependencies>\n      <dependency><groupId>org.own</groupId><artifactId>managed</artifactId><version>1.0</version></dependency>\n    </dependencies>\n  </dependencyManagement>\n", ""));
        fx.mvnOutput("enforcer:enforce", "[INFO] BUILD SUCCESS\n", 0);

        assertTrue(scanText(fx.analyseDemo()).contains("Passed No dependency conflicts found."));
    }

    @Test
    void conflictWithStaleExclusionsAndUnresolvedAutoFix() throws Exception {
        Files.writeString(fx.project.resolve("pom.xml"), PINNED_POM);
        fx.clearMvnRules("enforcer:enforce"); // phase 2 now fails the same way

        String scanId = fx.analyseDemo();

        String t = scanText(scanId);
        assertTrue(t.contains("1 conflict 1 unresolvable"), t);
        assertTrue(t.contains("Pristine analysis: 1 exclusion stripped · 2 dep-management entries removed"), t);
        assertTrue(t.contains("1 stale exclusion — no longer resolving any conflict org.gone:thing"), t.substring(t.indexOf("Applied - re-analyse")));
        assertTrue(fx.get("/scans/" + scanId).body().contains("&#9888;</span><code style=\"font-size:.78rem\">com.fasterxml.jackson.core:jackson-core</code>"));
    }

    static final String DIRECT_CONFLICTS = """
            [WARNING] Rule 0: org.apache.maven.plugins.enforcer.DependencyConvergence failed with message:
            Failed while enforcing releasability the error(s) are [
            Dependency convergence error for com.fasterxml.jackson.core:jackson-databind:2.13.0 paths to dependency are:
            +-com.example:demo:1.0.0
              +-com.fasterxml.jackson.core:jackson-databind:2.13.0
            +-com.example:demo:1.0.0
              +-org.other:uses-old-core:1.0
                +-com.fasterxml.jackson.core:jackson-databind:2.12.7

            Dependency convergence error for org.yaml:snakeyaml:1.33 paths to dependency are:
            +-com.example:demo:1.0.0
              +-org.yaml:snakeyaml:1.33
            +-com.example:demo:1.0.0
              +-org.other:uses-old-core:1.0
                +-org.yaml:snakeyaml:1.30

            Dependency convergence error for org.apache.commons:commons-lang3:3.12.0 paths to dependency are:
            +-com.example:demo:1.0.0
              +-org.apache.commons:commons-lang3:3.12.0
            +-com.example:demo:1.0.0
              +-org.other:uses-old-core:1.0
                +-org.apache.commons:commons-lang3:3.14.0
            ]
            [INFO] BUILD FAILURE
            """;

    @Test
    void conflictsOnDirectDependenciesDefaultToACleanVersion() throws Exception {
        fx.mvnOutput("enforcer:enforce", DIRECT_CONFLICTS, 1);

        String scanId = fx.analyseDemo();

        String page = fx.get("/scans/" + scanId).body();
        // Vulnerable direct dependency in conflict: defaults to the lowest clean version above
        // every conflicting one, not merely the newest version in the conflict.
        String databind = ServerPagesTest.card(page, "com.fasterxml.jackson.core:jackson-databind");
        assertTrue(databind.contains("△ Conflict"), databind);
        assertTrue(databind.contains("2.12.7 — critical severity, conflict"), databind);
        assertEquals("2.13.4", selectedVersion(page, "com.fasterxml.jackson.core:jackson-databind"));
        // No fixed version exists: stays on the newest conflicting version.
        assertEquals("1.33", selectedVersion(page, "org.yaml:snakeyaml"));
        assertTrue(ServerPagesTest.card(page, "org.yaml:snakeyaml").contains("1.30 — medium severity, conflict"));
        // Clean dependency: the newest version in the conflict wins over the plain recommendation.
        assertEquals("3.14.0", selectedVersion(page, "org.apache.commons:commons-lang3"));
        assertTrue(ServerPagesTest.card(page, "org.apache.commons:commons-lang3").contains("3.14.0 — latest, conflict"));
    }

    private static String selectedVersion(String page, String coordinate) {
        int start = page.indexOf("data-coord=\"" + coordinate + "\"");
        int end = page.indexOf("<div class=\"rem-card\"", start);
        Matcher m = Pattern.compile("<option value=\"([^\"]*)\" selected>").matcher(page.substring(start, end));
        assertTrue(m.find(), coordinate);
        return m.group(1);
    }

    @Test
    void unparseableEnforcerFailure() throws Exception {
        fx.clearMvnRules("enforcer:enforce");
        fx.mvnOutput("enforcer:enforce", "[ERROR] something unexpected\n".repeat(200), 1);

        String scanId = fx.analyseDemo();

        assertTrue(scanText(scanId).contains("produced no parseable conflict output"));
        assertTrue(fx.get("/api/scans/enforcer?scanId=" + scanId).body().startsWith("{\"status\":\"ENFORCER_RUN_FAILED_UNAVAILABLE\""));
    }

    @Test
    void lifecycleBoundRulesFallBackToVerifyAndAreRemembered() throws Exception {
        fx.clearMvnRules("enforcer:enforce");
        fx.mvnOutput("enforcer:enforce", "[WARNING] No rules are configured.\n", 0);
        fx.mvnOutput("verify", ServerFixture.CONVERGENCE_FAILURE, 1);
        fx.mvnRule("verify", "redkite-phase2", 0, "[INFO] BUILD SUCCESS\n");

        String first = fx.analyseDemo();
        assertTrue(scanText(first).contains("Auto-fix verified"));
        List<String> firstCalls = new ArrayList<>(fx.mvnCalls());
        assertTrue(firstCalls.stream().anyMatch(c -> c.endsWith("enforcer:enforce")));

        fx.analyseDemo();
        List<String> secondCalls = fx.mvnCalls().subList(firstCalls.size(), fx.mvnCalls().size());
        assertTrue(secondCalls.stream().noneMatch(c -> c.endsWith("enforcer:enforce")), secondCalls.toString());
        assertTrue(secondCalls.stream().anyMatch(c -> c.endsWith("verify -DskipTests")), secondCalls.toString());
    }

    @Test
    void missingMavenIsReported() throws Exception {
        System.setProperty(MavenExecutable.PROPERTY, tempDir.resolve("no-mvn").toString());

        String scanId = fx.analyseDemo();

        String t = scanText(scanId);
        assertTrue(t.contains("Could not start Maven — ensure mvn is on PATH."), t);
    }

    @Test
    void failedDependencyTreeMarksTheAnalysisFailed() throws Exception {
        fx.mvnOutput("dependency:tree", "[ERROR] Non-resolvable parent POM for com.example:demo:1.0.0\n", 1);

        String scanId = fx.analyseDemo();

        String t = scanText(scanId);
        assertTrue(t.contains("demo Failed"), t);
        assertTrue(t.contains("Build failed. Maven could not resolve the project model"), t);
        assertTrue(t.contains("Non-resolvable parent POM for com.example:demo:1.0.0"), t);
        assertTrue(projectText().contains("Status Failed"));
    }

    @Test
    void unparseableTreeLinesMakeTheAnalysisIncomplete() throws Exception {
        fx.mvnOutput("dependency:tree", ServerFixture.DEMO_TREE.replace("[INFO] BUILD SUCCESS", "[INFO] +- odd:line") , 0);

        String t = scanText(fx.analyseDemo());

        assertTrue(t.contains("demo Incomplete"), t);
        assertTrue(t.contains("1 dependency tree line(s) could not be parsed"), t);
        assertTrue(t.contains("[INFO] +- odd:line"), t);
    }

    @Test
    void missingVersionMetadataMakesTheAnalysisIncomplete() throws Exception {
        fx.hiddenMetadata.add("org.apache.commons:commons-lang3");

        String scanId = fx.analyseDemo();

        String t = scanText(scanId);
        assertTrue(t.contains("demo Incomplete"), t);
        assertTrue(t.contains("Some Maven metadata could not be refreshed or was unavailable"), t);
        assertTrue(t.contains("org.apache.commons:commons-lang3 missing"), t);
        assertTrue(projectText().contains("Status Incomplete"));
    }

    @Test
    void scanOfAnUnreadableProjectReportsTheError() throws Exception {
        Files.writeString(fx.project.resolve("pom.xml"), "<project>");

        String status = fx.analyse(fx.project);

        assertTrue(status.startsWith("{\"status\":\"error\""), status);
        assertTrue(field(status, "message").startsWith("Failed to scan Maven project"), status);
    }

    @Test
    void scanStatusShowsProgressWhileRunning() throws Exception {
        fx.mvnSleep("enforcer:enforce", 1);
        ServerFixture.Response started = fx.post("/api/scan", "{\"path\":" + ServerFixture.json(fx.project.toString()) + "}");
        String jobId = field(started.body(), "jobId");

        String running = fx.get("/api/scan-status?jobId=" + jobId).body();
        assertTrue(running.startsWith("{\"status\":\"running\",\"phases\":[{\"name\":\"Dependency analysis\""), running);
        assertTrue(running.contains("\"log\":["), running);

        String done;
        do {
            Thread.sleep(50);
            done = fx.get("/api/scan-status?jobId=" + jobId).body();
        } while (done.contains("running"));
        assertTrue(done.startsWith("{\"status\":\"done\",\"scanId\":\""), done);
    }

    @Test
    void multiModuleProjectsDownloadAsZipAndLabelModules() throws Exception {
        Files.writeString(fx.project.resolve("pom.xml"), """
                <project>
                  <groupId>com.example</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>
                  <properties><commons-lang3.version>3.12.0</commons-lang3.version></properties>
                  <modules><module>api</module><module>impl</module></modules>
                </project>
                """);
        Files.createDirectories(fx.project.resolve("api"));
        Files.writeString(fx.project.resolve("api/pom.xml"), """
                <project>
                  <parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1</version></parent>
                  <artifactId>api</artifactId>
                  <dependencies>
                    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>${commons-lang3.version}</version></dependency>
                  </dependencies>
                </project>
                """);
        Files.createDirectories(fx.project.resolve("impl"));
        Files.writeString(fx.project.resolve("impl/pom.xml"), """
                <project>
                  <parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1</version></parent>
                  <artifactId>impl</artifactId>
                  <dependencies>
                    <dependency><groupId>com.example</groupId><artifactId>api</artifactId><version>1</version></dependency>
                    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>1.7.36</version></dependency>
                  </dependencies>
                </project>
                """);
        fx.mvnOutput("dependency:tree", """
                [INFO] com.example:impl:jar:1
                [INFO] +- com.example:api:jar:1:compile
                [INFO] |  \\- org.apache.commons:commons-lang3:jar:3.12.0:compile
                [INFO] \\- org.slf4j:slf4j-api:jar:1.7.36:compile
                """, 0);
        fx.mvnOutput("enforcer:enforce", "[INFO] BUILD SUCCESS\n", 0);

        String scanId = fx.analyseDemo();

        String page = fx.get("/scans/" + scanId).body();
        assertTrue(page.contains("data-module=\"api/pom.xml\""), page);
        assertTrue(page.contains("data-module=\"impl/pom.xml\""), page);

        HttpResponse<byte[]> zip = fx.getBytes("/api/scans/pom?scanId=" + scanId);
        assertEquals("application/zip", zip.headers().firstValue("Content-Type").orElse(""));
        List<String> entries = new ArrayList<>();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(zip.body()))) {
            for (ZipEntry e; (e = in.getNextEntry()) != null; ) entries.add(e.getName());
        }
        assertEquals(List.of("api/pom.xml", "impl/pom.xml", "pom.xml"), entries);

        // The api module references a property only its parent declares: the upgrade is written
        // as an override property in the api module itself.
        long lang = ServerPagesTest.componentId(page, "org.apache.commons", "commons-lang3");
        ServerFixture.Response patch = fx.post("/api/scans/pom?scanId=" + scanId, lang + "=3.14.0");
        assertEquals(200, patch.status(), patch.body());
        String api = field(patch.body(), "api/pom.xml");
        assertTrue(api.contains("<commons-lang3.version>3.14.0</commons-lang3.version>"), api);
        assertTrue(api.contains("<version>${commons-lang3.version}</version>"), api);
    }

    @Test
    void projectConfigurationIsShownOnTheProjectPage() throws Exception {
        Files.createDirectories(fx.project.resolve(".redkite"));
        Files.writeString(fx.project.resolve(".redkite/settings.yml"), """
                redkite:
                  maven:
                    mode: [verify, test]
                    fullLogs: true
                    profile: ci
                    args: ["-Dfoo=bar", "--batch-mode"]
                    env:
                      DB_HOST: localhost
                    spring:
                      profiles: smoke
                """);

        fx.analyseDemo();

        String t = projectText();
        assertTrue(t.contains("Maven arguments -Dfoo=bar --batch-mode"), t);
        assertTrue(t.contains("Profile ci"), t);
        assertTrue(t.contains("Mode verify"), t);
        assertTrue(t.contains("Tests enabled true"), t);
        assertTrue(t.contains("Full logs true"), t);
        assertTrue(t.contains("Spring Boot profiles smoke"), t);
        assertTrue(t.contains("Environment variables DB_HOST=localhost"), t);
    }

    @Test
    void projectWithoutConfigurationFileExplainsTheDefault() throws Exception {
        String scanId = fx.analyseDemo();
        Files.delete(fx.project.resolve(".redkite/settings.yml"));

        String t = projectText();
        assertTrue(t.contains("No .redkite/settings.yml found at"), t);
        assertNotNull(scanId);
    }

    /** Home page HTML of a second server started now, sharing the fixture's preferences file. */
    private String homeOfNewServer() throws Exception {
        RedKiteServerMain other = new RedKiteServerMain(
                "jdbc:h2:mem:" + java.util.UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1", "sa", "", 0);
        other.start();
        try {
            return fx.client.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create("http://127.0.0.1:" + other.port() + "/")).build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()).body();
        } finally {
            other.stop();
        }
    }

    @Test
    void newServerReadsThemeFromThePreferencesFile() throws Exception {
        fx.post("/api/prefs", "{\"theme\":\"forest\"}");
        assertTrue(homeOfNewServer().contains("data-theme=\"forest\""));
    }

    @Test
    void unknownThemeFallsBackToDark() throws Exception {
        Files.createDirectories(fx.prefsFile.getParent());
        Files.writeString(fx.prefsFile, "theme=neon\n");
        assertTrue(homeOfNewServer().contains("data-theme=\"dark\""));
    }

    @Test
    void unreadablePreferencesFallBackToDark() throws Exception {
        Files.createDirectories(fx.prefsFile); // a directory where the file should be
        assertTrue(homeOfNewServer().contains("data-theme=\"dark\""));
        assertEquals(200, fx.post("/api/prefs", "{\"theme\":\"dusk\"}").status(), "a failed save is logged, not fatal");
    }
}
