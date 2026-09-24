package com.redkite.maven;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EnforcerRunnerTest {
    @TempDir
    Path tempDir;

    private FakeMaven mvn;
    private Path project;
    private Path pom;

    @BeforeEach
    void setUp() throws Exception {
        mvn = FakeMaven.install(tempDir.resolve("fake-mvn"));
        project = Files.createDirectories(tempDir.resolve("project"));
        pom = Files.writeString(project.resolve("pom.xml"), "<project/>");
    }

    @AfterEach
    void tearDown() {
        mvn.close();
    }

    private String buildLog() throws Exception {
        return Files.readString(ValidationRunner.redkiteWorkDir(project).resolve("build.log"));
    }

    @Test
    void passingEnforceReturnsPassedWithOutputAndStreamsLines() throws Exception {
        mvn.output("enforcer:enforce", "[INFO] Rule 0 passed\n[INFO] BUILD SUCCESS\n");
        List<String> lines = new ArrayList<>();

        EnforcerRunner.EnforcerRunResult result = new EnforcerRunner().run(project, pom, false, lines::add);

        assertTrue(result.passed());
        assertFalse(result.usedVerifyFallback());
        assertNull(result.errorDetail());
        assertEquals("[INFO] Rule 0 passed\n[INFO] BUILD SUCCESS\n", result.rawOutput());
        assertEquals(List.of("[INFO] Rule 0 passed", "[INFO] BUILD SUCCESS"), lines);
        assertEquals(List.of("-f " + pom + " --no-transfer-progress enforcer:enforce"), mvn.calls());
        assertTrue(buildLog().contains("enforcer (enforcer:enforce)"));
    }

    @Test
    void failingEnforceReturnsFailed() throws Exception {
        mvn.output("enforcer:enforce", "[WARNING] Rule 2: DependencyConvergence failed\n").exit("enforcer:enforce", 1);

        EnforcerRunner.EnforcerRunResult result = new EnforcerRunner().run(project, pom);

        assertFalse(result.passed());
        assertNull(result.errorDetail());
        assertFalse(result.usedVerifyFallback());
        assertTrue(result.rawOutput().contains("DependencyConvergence failed"));
    }

    @Test
    void noRulesConfiguredFallsBackToVerify() throws Exception {
        mvn.output("enforcer:enforce", "[WARNING] No rules are configured.\n")
                .output("verify", "[INFO] verify ran\n");

        EnforcerRunner.EnforcerRunResult result = new EnforcerRunner().run(project, pom, false);

        assertTrue(result.passed());
        assertTrue(result.usedVerifyFallback());
        assertEquals("[INFO] verify ran\n", result.rawOutput());
        assertEquals(2, mvn.calls().size());
        assertTrue(mvn.calls().get(1).endsWith("verify -DskipTests"));
    }

    @Test
    void alternativeNoRulesWordingAlsoFallsBack() throws Exception {
        mvn.output("enforcer:enforce", "no rules configured for this execution\n")
                .output("verify", "[ERROR] Rule failed\n").exit("verify", 1);

        EnforcerRunner.EnforcerRunResult result = new EnforcerRunner().run(project, pom, false);

        assertFalse(result.passed());
        assertTrue(result.usedVerifyFallback());
    }

    @Test
    void skipDirectEnforceGoesStraightToVerify() throws Exception {
        mvn.output("verify", "ok\n");

        EnforcerRunner.EnforcerRunResult result = new EnforcerRunner().run(project, pom, true);

        assertTrue(result.passed());
        assertTrue(result.usedVerifyFallback());
        assertEquals(1, mvn.calls().size());
        assertTrue(mvn.calls().get(0).contains("verify -DskipTests"));
    }

    @Test
    void projectLocalSettingsArePassedExplicitly() throws Exception {
        Path settings = project.resolve(".m2/settings.xml");
        Files.createDirectories(settings.getParent());
        Files.writeString(settings, "<settings/>");

        new EnforcerRunner().run(project, pom);

        assertTrue(mvn.calls().get(0).startsWith("-s " + settings + " -f " + pom));
    }

    @Test
    void missingExecutableIsReportedAsUnavailable() throws Exception {
        System.setProperty(MavenExecutable.PROPERTY, tempDir.resolve("no-such-mvn").toString());

        EnforcerRunner.EnforcerRunResult result = new EnforcerRunner().run(project, pom);

        assertFalse(result.passed());
        assertEquals("", result.rawOutput());
        assertNotNull(result.errorDetail());
        assertTrue(buildLog().contains("no-such-mvn"));
    }

    @Test
    void resultFactories() {
        assertEquals(new EnforcerRunner.EnforcerRunResult(true, "o", null, false), EnforcerRunner.EnforcerRunResult.passed("o"));
        assertEquals(new EnforcerRunner.EnforcerRunResult(false, "o", null, false), EnforcerRunner.EnforcerRunResult.failed("o"));
        assertEquals(new EnforcerRunner.EnforcerRunResult(false, "", "why", false), EnforcerRunner.EnforcerRunResult.unavailable("why"));
    }
}
