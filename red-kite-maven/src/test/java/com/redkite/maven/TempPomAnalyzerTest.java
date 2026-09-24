package com.redkite.maven;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TempPomAnalyzerTest {
    private static final String ROOT_POM = """
            <project>
              <groupId>com.example</groupId>
              <artifactId>root</artifactId>
              <version>1</version>
              <packaging>pom</packaging>
              <modules><module>app</module></modules>
              <dependencyManagement>
                <dependencies>
                  <!-- redkite:dependency-management pin groupId="org.lib" artifactId="core" version="2.0" reason="fix" -->
                  <dependency><groupId>org.lib</groupId><artifactId>core</artifactId><version>2.0</version></dependency>
                  <dependency><groupId>org.own</groupId><artifactId>kept</artifactId><version>1.1</version></dependency>
                </dependencies>
              </dependencyManagement>
            </project>
            """;

    private static final String APP_POM = """
            <project>
              <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1</version></parent>
              <artifactId>app</artifactId>
              <dependencies>
                <dependency>
                  <groupId>org.web</groupId><artifactId>web</artifactId><version>3.0</version>
                  <exclusions>
                    <!-- redkite:exclusion groupId="org.bad" artifactId="bad" reason="conflict" -->
                    <exclusion><groupId>org.bad</groupId><artifactId>bad</artifactId></exclusion>
                  </exclusions>
                </dependency>
              </dependencies>
            </project>
            """;

    @TempDir
    Path tempDir;

    private FakeMaven mvn;
    private Path project;
    private Path rootPom;

    @BeforeEach
    void setUp() throws Exception {
        mvn = FakeMaven.install(tempDir.resolve("fake-mvn"));
        project = Files.createDirectories(tempDir.resolve("project"));
        rootPom = Files.writeString(project.resolve("pom.xml"), ROOT_POM);
        Path app = Files.createDirectories(project.resolve("app"));
        Files.writeString(app.resolve("pom.xml"), APP_POM);
        Files.createDirectories(app.resolve("src/main/java"));
        Files.createDirectories(app.resolve("target/classes"));
        Files.createDirectories(project.resolve(".git"));
        Files.createDirectories(project.resolve("target/ignored"));
        Files.writeString(project.resolve("target/ignored/pom.xml"), "<project/>");
        Files.writeString(project.resolve("README.md"), "readme");
    }

    @AfterEach
    void tearDown() {
        mvn.close();
    }

    @Test
    void scanPomMetadataReadsDepManagementAndExclusionsWithoutMaven() throws Exception {
        TempPomAnalyzer.PomMetadata metadata = new TempPomAnalyzer().scanPomMetadata(project);

        assertEquals(1, metadata.exclusionsStripped());
        assertEquals(List.of("org.lib:core:2.0", "org.own:kept:1.1"), metadata.depMgmtEntries());
        assertEquals(List.of("org.bad:bad"), metadata.allRedkiteExclusions());
        assertTrue(mvn.calls().isEmpty());
    }

    @Test
    void runPristineStripsEverythingInATempCopyAndLeavesTheProjectAlone() throws Exception {
        mvn.output("enforcer:enforce", "[ERROR] Rule 0 failed\n").exit("enforcer:enforce", 1);

        TempPomAnalyzer.PristineResult result = new TempPomAnalyzer().runPristine(project, rootPom);

        assertFalse(result.enforcerResult().passed());
        assertEquals(1, result.exclusionsStripped());
        assertEquals(List.of("org.lib:core:2.0", "org.own:kept:1.1"), result.depMgmtRemoved());
        assertEquals(List.of("org.bad:bad"), result.allRedkiteExclusions());

        String call = mvn.calls().get(0);
        assertFalse(call.contains(project + "/pom.xml"), "Maven must run against the temp copy: " + call);
        String analysedPom = mvn.lastPom();
        assertFalse(analysedPom.contains("dependencyManagement"));
        List<String> tempEntries = mvn.lastPomDirEntries();
        assertTrue(tempEntries.contains("app"));
        assertTrue(tempEntries.contains("README.md"), "non-POM content is symlinked in: " + tempEntries);
        assertFalse(tempEntries.contains("target"));
        assertFalse(tempEntries.contains(".git"));

        assertEquals(ROOT_POM, Files.readString(rootPom), "the real POM is never modified");
        assertTrue(Files.exists(project.resolve("README.md")), "deleting the temp tree must not follow symlinks");
    }

    @Test
    void runPristineWithoutLineConsumer() throws Exception {
        TempPomAnalyzer.PristineResult result = new TempPomAnalyzer().runPristine(project, rootPom);
        assertTrue(result.enforcerResult().passed());
    }

    @Test
    void runWithPinsKeepsProjectDepManagementAndAddsPinsToTargetPom() throws Exception {
        mvn.output("enforcer:enforce", "[INFO] all rules passed\n");

        EnforcerRunner.EnforcerRunResult result = new TempPomAnalyzer()
                .runWithPins(project, rootPom, Map.of("org.new:thing", "4.5"));

        assertTrue(result.passed());
        String analysedPom = mvn.lastPom();
        assertTrue(analysedPom.contains("<artifactId>kept</artifactId>"), "project's own entries stay");
        assertFalse(analysedPom.contains("<artifactId>core</artifactId>"), "old RedKite pins are stripped");
        assertTrue(analysedPom.contains("<artifactId>thing</artifactId>"));
        assertTrue(analysedPom.contains("<version>4.5</version>"));
        assertEquals(ROOT_POM, Files.readString(rootPom));
    }

    @Test
    void runWithPinsCanSkipDirectEnforce() throws Exception {
        EnforcerRunner.EnforcerRunResult result = new TempPomAnalyzer()
                .runWithPins(project, rootPom, Map.of(), true);

        assertTrue(result.usedVerifyFallback());
        assertTrue(mvn.calls().get(0).contains("verify -DskipTests"));
    }
}
