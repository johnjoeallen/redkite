package com.redkite.server;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Snapshot tests of whole rendered pages: each scenario analyses a project, then compares the
 * analysis page, project page and enforcer API output with a checked-in expected copy under
 * {@code src/test/resources/snapshots/}. Values that differ between runs (temp paths, ports, ids,
 * timestamps) and the constant inline CSS/JS are normalised first.
 *
 * <p>After an intended change to the output, regenerate the snapshots with
 * {@code mvn test -pl red-kite-server -Dtest=PageSnapshotTest -Dsnapshots.update=true} and review the diff.
 */
class PageSnapshotTest {
    private static final Path SNAPSHOTS = Path.of("src/test/resources/snapshots");

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

    private static String resource(String path) throws IOException {
        try (InputStream in = PageSnapshotTest.class.getClassLoader().getResourceAsStream(path)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String normalise(String text) throws IOException {
        String s = text.replace(resource("static/styles.css"), "<CSS>").replace(resource("static/scripts.js"), "<JS>");
        s = s.replace(tempDir.toString(), "<TMP>");
        s = s.replace(fx.httpBase, "<REPO-HOST>");
        s = s.replaceAll("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<UUID>");
        s = s.replaceAll("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z", "<INSTANT>");
        s = s.replaceAll("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}", "<DATE>");
        s = s.replaceAll("redkite-(pristine|phase2)-\\d+", "redkite-$1-<N>");
        return s;
    }

    private void assertSnapshot(String name, String actual) throws IOException {
        String normalised = normalise(actual);
        Path file = SNAPSHOTS.resolve(name);
        if (Boolean.getBoolean("snapshots.update")) {
            Files.createDirectories(file.getParent());
            Files.writeString(file, normalised);
            return;
        }
        assertTrue(Files.exists(file), "missing snapshot " + file + " — run with -Dsnapshots.update=true");
        String expected = Files.readString(file);
        if (!expected.equals(normalised)) {
            int i = 0;
            while (i < Math.min(expected.length(), normalised.length()) && expected.charAt(i) == normalised.charAt(i)) i++;
            int from = Math.max(0, i - 200);
            fail(name + " differs at offset " + i + "\nexpected: …" + expected.substring(from, Math.min(expected.length(), i + 200))
                    + "\nactual:   …" + normalised.substring(from, Math.min(normalised.length(), i + 200)));
        }
    }

    private String projectId() throws Exception {
        Matcher m = Pattern.compile("href=\"/projects/([^\"]+)\"").matcher(fx.get("/").body());
        assertTrue(m.find());
        return m.group(1);
    }

    private void snapshotAll(String scenario, String scanId) throws Exception {
        assertSnapshot(scenario + "/scan.html", fx.get("/scans/" + scanId).body());
        assertSnapshot(scenario + "/project.html", fx.get("/projects/" + projectId()).body());
        assertSnapshot(scenario + "/enforcer.json", fx.get("/api/scans/enforcer?scanId=" + scanId).body());
    }

    @Test
    void demoProject() throws Exception {
        String scanId = fx.analyseDemo();
        snapshotAll("demo", scanId);
        assertSnapshot("demo/home.html", fx.get("/").body());
        assertSnapshot("demo/config.html", fx.get("/config").body());
    }

    @Test
    void conflictsOnDirectDependencies() throws Exception {
        fx.mvnOutput("enforcer:enforce", ServerScenariosTest.DIRECT_CONFLICTS, 1);
        snapshotAll("direct-conflicts", fx.analyseDemo());
    }

    @Test
    void pinnedProjectWithStaleExclusionAndUnresolvedAutoFix() throws Exception {
        Files.writeString(fx.project.resolve("pom.xml"), ServerScenariosTest.PINNED_POM);
        fx.clearMvnRules("enforcer:enforce");
        snapshotAll("pinned-unresolved", fx.analyseDemo());
    }

    @Test
    void passingEnforcerOnAPinnedProject() throws Exception {
        Files.writeString(fx.project.resolve("pom.xml"), ServerScenariosTest.PINNED_POM);
        fx.mvnOutput("enforcer:enforce", "[INFO] BUILD SUCCESS\n", 0);
        snapshotAll("pinned-passing", fx.analyseDemo());
    }

    @Test
    void failedDependencyTree() throws Exception {
        fx.mvnOutput("dependency:tree", "[ERROR] Non-resolvable parent POM for com.example:demo:1.0.0\n", 1);
        fx.clearMvnRules("enforcer:enforce");
        fx.mvnOutput("enforcer:enforce", "[ERROR] something unexpected\n", 1);
        snapshotAll("tree-failed", fx.analyseDemo());
    }

    @Test
    void missingMetadataAndUnparseableTreeLines() throws Exception {
        fx.hiddenMetadata.add("org.apache.commons:commons-lang3");
        fx.hiddenMetadata.add("org.other:transitive-vuln");
        fx.mvnOutput("dependency:tree", ServerFixture.DEMO_TREE.replace("[INFO] BUILD SUCCESS", "[INFO] +- odd:line"), 0);
        fx.mvnOutput("enforcer:enforce", "[WARNING] No rules are configured.\n", 0);
        fx.mvnOutput("verify", "[INFO] BUILD SUCCESS\n", 0);
        snapshotAll("incomplete", fx.analyseDemo());
    }

    @Test
    void userPinsAndProjectConfiguration() throws Exception {
        String pom = ServerFixture.DEMO_POM
                .replace("<stale-thing.version>9.9</stale-thing.version>",
                        "<!-- redkite:user-pin version=\"1.7.36\" — user pinned -->\n    <slf4j.version>1.7.36</slf4j.version>")
                .replace("<artifactId>slf4j-api</artifactId><version>1.7.36</version>", "<artifactId>slf4j-api</artifactId><version>${slf4j.version}</version>")
                .replace("<dependency><groupId>org.own</groupId><artifactId>managed</artifactId><version>1.0</version></dependency>",
                        "<!-- redkite:user-pin groupId=\"org.own\" artifactId=\"managed\" version=\"1.0\" -->\n"
                                + "      <dependency><groupId>org.own</groupId><artifactId>managed</artifactId><version>1.0</version></dependency>");
        Files.writeString(fx.project.resolve("pom.xml"), pom);
        Files.createDirectories(fx.project.resolve(".redkite"));
        Files.writeString(fx.project.resolve(".redkite/settings.yml"), "redkite:\n  maven:\n    profile: ci\n    args: [\"-X\"]\n    env: {A: b}\n");
        snapshotAll("user-pins", fx.analyseDemo());
    }
}
