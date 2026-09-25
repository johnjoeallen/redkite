package com.redkite.maven;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ValidationRunnerTest {
    private static final String BOOT_POM =
            "<project><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>";

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

    private Path workDir() {
        return ValidationRunner.redkiteWorkDir(project);
    }

    private static ValidationRunner.ValidationOptions options(ValidationRunner.Mode mode, boolean tests, boolean fullLogs,
                                                              String startedPattern) {
        return new ValidationRunner.ValidationOptions(List.of("-Pci"), Map.of("RK_TEST", "1"), mode,
                List.of("-Dspring-boot.run.profiles=smoke"), tests, fullLogs, startedPattern);
    }

    @Test
    void defaultValidateRunsCleanInstallSkippingTests() throws Exception {
        mvn.output("install", "[INFO] BUILD SUCCESS\n");

        ValidationRunner.ValidationResult result = new ValidationRunner().validate(project, pom);

        assertTrue(result.passed());
        assertEquals("build", result.phase());
        assertNull(result.failureSignature());
        assertEquals(List.of("-f", pom.toString(), "--no-transfer-progress", "clean", "install", "-DskipTests",
                "-Denforcer.skip=true"), result.command().subList(1, result.command().size()));
        assertFalse(Files.exists(workDir().resolve("pom.xml")), "a passing build saves no failed POM");
        assertTrue(Files.readString(workDir().resolve("build.log")).contains("build (RUN)"));
    }

    @Test
    void projectLocalSettingsArePassedExplicitly() throws Exception {
        Path settings = Files.createDirectories(project.resolve(".m2")).resolve("settings.xml");
        Files.writeString(settings, "<settings/>");
        mvn.output("install", "[INFO] BUILD SUCCESS\n");
        List<String> command = new ValidationRunner().validate(project, pom).command();
        assertEquals(List.of("-s", settings.toString()), command.subList(1, 3));
    }

    @Test
    void modesMapToGoalsAndTestsFlagControlsSkipTests() throws Exception {
        ValidationRunner runner = new ValidationRunner();

        List<String> verify = runner.validate(project, pom, options(ValidationRunner.Mode.VERIFY, true, true, null)).command();
        assertEquals(List.of("-f", pom.toString(), "clean", "verify", "-Denforcer.skip=true", "-Pci"),
                verify.subList(1, verify.size()));

        List<String> test = runner.validate(project, pom, options(ValidationRunner.Mode.TEST, false, false, null)).command();
        assertEquals(List.of("-f", pom.toString(), "--no-transfer-progress", "clean", "test", "-DskipTests",
                "-Denforcer.skip=true", "-Pci"), test.subList(1, test.size()));
    }

    @Test
    void failedBuildSavesPomAndExtractsErrorSignature() throws Exception {
        mvn.output("install", "[INFO] Building\n[ERROR]\n[ERROR] Failed to execute goal foo\n").exit("install", 1);
        List<String> lines = new ArrayList<>();

        ValidationRunner.ValidationResult result = new ValidationRunner()
                .validate(project, pom, ValidationRunner.ValidationOptions.DEFAULT, lines::add);

        assertFalse(result.passed());
        assertEquals("[ERROR] Failed to execute goal foo", result.failureSignature());
        assertEquals(3, lines.size());
        assertEquals("<project/>", Files.readString(workDir().resolve("pom.xml")));
    }

    @Test
    void unstartableBuildIsAFailureWithTheExceptionMessage() throws Exception {
        System.setProperty(MavenExecutable.PROPERTY, tempDir.resolve("missing-mvn").toString());

        ValidationRunner.ValidationResult result = new ValidationRunner().validate(project, pom);

        assertFalse(result.passed());
        assertEquals("", result.rawOutput());
        assertNotNull(result.failureSignature());
        assertTrue(Files.exists(workDir().resolve("pom.xml")));
    }

    @Test
    void startupSkippedWhenBuildFails() throws Exception {
        Files.writeString(pom, BOOT_POM);
        mvn.exit("install", 1);

        ValidationRunner.ValidationResult result = new ValidationRunner().validateWithStartup(project, pom, 5);

        assertFalse(result.passed());
        assertEquals("build", result.phase());
        assertEquals(1, mvn.calls().size());
    }

    @Test
    void startupSkippedOutsideRunMode() throws Exception {
        Files.writeString(pom, BOOT_POM);

        ValidationRunner.ValidationResult result = new ValidationRunner()
                .validateWithStartup(project, pom, 5, options(ValidationRunner.Mode.VERIFY, false, false, null));

        assertTrue(result.passed());
        assertEquals("build", result.phase());
        assertEquals(1, mvn.calls().size());
    }

    @Test
    void startupSkippedWithoutSpringBootPlugin() throws Exception {
        ValidationRunner.ValidationResult result = new ValidationRunner().validateWithStartup(project, pom, 5);

        assertTrue(result.passed());
        assertEquals("build", result.phase());
        assertEquals(1, mvn.calls().size());
    }

    @Test
    void startupSkippedWhenPomDisappearsAfterBuild() throws Exception {
        Path gone = project.resolve("gone.xml");
        ValidationRunner.ValidationResult result = new ValidationRunner().validateWithStartup(project, gone, 5);
        assertEquals("build", result.phase());
    }

    @Test
    void startupPassesOnDefaultBanner() throws Exception {
        Files.writeString(pom, BOOT_POM);
        mvn.output("spring-boot:run", "booting\nStarted App in 1.5 seconds (JVM running for 2)\n");
        List<String> lines = new ArrayList<>();

        ValidationRunner.ValidationResult result = new ValidationRunner()
                .validateWithStartup(project, pom, 10, ValidationRunner.ValidationOptions.DEFAULT, lines::add);

        assertTrue(result.passed(), result.rawOutput());
        assertEquals("startup", result.phase());
        assertNull(result.failureSignature());
        assertTrue(lines.contains("booting"));
        String startupCall = mvn.calls().get(1);
        assertTrue(startupCall.contains("spring-boot:run -Dspring-boot.run.arguments=--server.port="), startupCall);
    }

    @Test
    void startupUsesCustomPatternAndSpringBootArgs() throws Exception {
        Files.writeString(pom, BOOT_POM);
        mvn.output("spring-boot:run", "RedKite server listening on http://localhost:1\n");

        ValidationRunner.ValidationResult result = new ValidationRunner().validateWithStartup(project, pom, 10,
                options(ValidationRunner.Mode.RUN, false, false, "server listening on"));

        assertTrue(result.passed());
        assertTrue(mvn.calls().get(1).endsWith("-Pci -Dspring-boot.run.profiles=smoke"), mvn.calls().get(1));
    }

    @Test
    void invalidCustomPatternFallsBackToDefaultBanner() throws Exception {
        Files.writeString(pom, BOOT_POM);
        mvn.output("spring-boot:run", "Started App in 3 seconds\n");

        ValidationRunner.ValidationResult result = new ValidationRunner().validateWithStartup(project, pom, 10,
                options(ValidationRunner.Mode.RUN, false, false, "(unclosed"));

        assertTrue(result.passed());
    }

    @Test
    void startupFailsWhenBannerNeverAppears() throws Exception {
        Files.writeString(pom, BOOT_POM);
        mvn.output("spring-boot:run", "[ERROR] APPLICATION FAILED TO START\n").exit("spring-boot:run", 1);

        ValidationRunner.ValidationResult result = new ValidationRunner().validateWithStartup(project, pom, 10);

        assertFalse(result.passed());
        assertEquals("startup", result.phase());
        assertEquals("[ERROR] APPLICATION FAILED TO START", result.failureSignature());
        assertTrue(Files.exists(workDir().resolve("pom.xml")));
        assertTrue(Files.readString(workDir().resolve("build.log")).contains("startup (spring-boot:run)"));
    }

    @Test
    void startupTimesOutAndKillsTheProcess() throws Exception {
        Files.writeString(pom, BOOT_POM);
        mvn.output("spring-boot:run", "still starting\n").sleep("spring-boot:run", 30);

        long start = System.nanoTime();
        ValidationRunner.ValidationResult result = new ValidationRunner().validateWithStartup(project, pom, 1);
        long seconds = (System.nanoTime() - start) / 1_000_000_000L;

        assertFalse(result.passed());
        assertTrue(seconds < 20, "process should be killed at the timeout, took " + seconds + "s");
    }

    // ---------------------------------------------------------------- static helpers

    @Test
    void attributeFailureFindsTheUnresolvableArtifact() {
        assertEquals("org.example:lib", ValidationRunner.attributeFailure(
                "[ERROR] Could not resolve artifact org.example:lib:jar:1.0 in central"));
        assertEquals("org.example:lib", ValidationRunner.attributeFailure(
                "Could not find artifact org.example:lib:pom:2.0"));
        assertNull(ValidationRunner.attributeFailure("Could not find artifact nocolon here"));
        assertNull(ValidationRunner.attributeFailure("BUILD FAILURE for other reasons"));
        assertNull(ValidationRunner.attributeFailure(""));
        assertNull(ValidationRunner.attributeFailure(null));
        assertEquals("a:b", ValidationRunner.attributeFailure("Could not find artifact a:b"), "a coordinate at the very end of the output");
        assertNull(ValidationRunner.attributeFailure("Could not find artifact a:"), "a single part is not a coordinate");
        assertEquals("a:b", ValidationRunner.attributeFailure("Could not resolve artifact a:b:jar:1 in central"), "a marker at the very start");
        assertNull(ValidationRunner.attributeFailure("Could not find artifact nocolon in repo:central"),
                "only the first whitespace-delimited token is the coordinate");
    }

    @Test
    void extractSignaturePrefersErrorLinesThenExceptionsThenTail() {
        assertNull(ValidationRunner.extractSignature(null));
        assertNull(ValidationRunner.extractSignature(""));
        assertEquals("[ERROR] boom", ValidationRunner.extractSignature("[ERROR]\n  [ERROR] boom\n"));
        assertEquals("java.lang.IllegalStateException: bad", ValidationRunner.extractSignature(
                "line\njava.lang.IllegalStateException: bad\nat x"));
        assertEquals("plain output", ValidationRunner.extractSignature("  plain output  "));
        String longOutput = "x".repeat(600) + "END";
        assertEquals(500, ValidationRunner.extractSignature(longOutput).length());
        assertTrue(ValidationRunner.extractSignature(longOutput).endsWith("END"));
        assertEquals("trailing Exception", ValidationRunner.extractSignature("trailing Exception"));
        assertEquals("[ERROR]x\nplain", ValidationRunner.extractSignature("[ERROR]x\nplain"), "an [ERROR] marker needs a message after it");
        assertEquals("Exception first", ValidationRunner.extractSignature("Exception first\nnext"));
    }

    @Test
    void appendLogAccumulatesEntriesAndResetClears() throws Exception {
        ValidationRunner.appendLog(project, "first", List.of("mvn", "a"), "out1\n");
        ValidationRunner.appendLog(project, "second", null, null);
        String log = Files.readString(workDir().resolve("build.log"));
        assertTrue(log.contains("— first ===\n$ mvn a\n\nout1\n\n"), log);
        assertTrue(log.contains("— second ===\n$ (unavailable)\n\n\n\n"), log);

        ValidationRunner.resetLog(project);
        assertEquals("", Files.readString(workDir().resolve("build.log")));
    }

    @Test
    void logHelpersSwallowIoFailures() throws Exception {
        Path file = Files.writeString(tempDir.resolve("a-file"), "x");
        // .redkite cannot be created under a regular file: both helpers must log and carry on.
        ValidationRunner.appendLog(file, "label", List.of("mvn"), "out");
        ValidationRunner.resetLog(file);
        assertEquals(file.resolve(".redkite").resolve("work"), ValidationRunner.redkiteWorkDir(file));
    }
}
