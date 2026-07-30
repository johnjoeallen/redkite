package com.redkite.maven;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ProjectConfigFileTest {

    @Test
    void parsesAllFieldsNestedUnderRedkiteMaven() {
        String yaml = """
                redkite:
                  maven:
                    mode: verify
                    profile: redkite-build
                    args:
                      - "--batch-mode"
                      - "--no-transfer-progress"
                      - "-Dfoo=bar"
                    env:
                      DB_HOST: localhost
                      DB_PASS: pw
                    spring:
                      profiles: redkite-local
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);

        assertEquals(List.of("--batch-mode", "--no-transfer-progress", "-Dfoo=bar"), config.args());
        assertEquals("redkite-build", config.profile());
        assertEquals(ValidationRunner.Mode.VERIFY, config.mode());
        assertEquals(Map.of("DB_HOST", "localhost", "DB_PASS", "pw"), config.env());
        assertEquals("redkite-local", config.springProfiles());
    }

    @Test
    void argsAsListPreservesAnArgumentContainingASpace() {
        // The whole reason the list form exists: a single space-separated scalar could never
        // express an argument whose own value legitimately contains a space.
        String yaml = """
                redkite:
                  maven:
                    args:
                      - "-Dmessage=hello world"
                      - "-Dfoo=bar"
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals(List.of("-Dmessage=hello world", "-Dfoo=bar"), config.args());
    }

    @Test
    void argsAlsoAcceptsAWhitespaceSeparatedScalarString() {
        String yaml = """
                redkite:
                  maven:
                    args: -Dfoo=bar -Dbaz=qux
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals(List.of("-Dfoo=bar", "-Dbaz=qux"), config.args());
    }

    @Test
    void argsAlsoAcceptsAScalarContinuationLine() {
        // Real YAML: "args: -Dfoo=bar" (inline) and "args:\n  -Dfoo=bar" (continuation) mean the
        // same thing, since a bare "-Dfoo=bar" has no space after the leading "-" and so never
        // triggers YAML's block-sequence indicator.
        String yaml = """
                redkite:
                  maven:
                    args:
                      -Dfoo=bar
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals(List.of("-Dfoo=bar"), config.args());
    }

    @Test
    void modeDefaultsToRun() {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse("redkite:\n  maven:\n    profile: dev\n");
        assertEquals(ValidationRunner.Mode.RUN, config.mode());
    }

    @Test
    void modeIsCaseInsensitiveAndCoversAllThreeValues() {
        assertEquals(ValidationRunner.Mode.RUN, ProjectConfigFile.parse("redkite:\n  maven:\n    mode: run\n").mode());
        assertEquals(ValidationRunner.Mode.RUN, ProjectConfigFile.parse("redkite:\n  maven:\n    mode: RUN\n").mode());
        assertEquals(ValidationRunner.Mode.VERIFY, ProjectConfigFile.parse("redkite:\n  maven:\n    mode: verify\n").mode());
        assertEquals(ValidationRunner.Mode.VERIFY, ProjectConfigFile.parse("redkite:\n  maven:\n    mode: Verify\n").mode());
        assertEquals(ValidationRunner.Mode.TEST, ProjectConfigFile.parse("redkite:\n  maven:\n    mode: test\n").mode());
    }

    @Test
    void unrecognizedModeDefaultsToRun() {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse("redkite:\n  maven:\n    mode: nonsense\n");
        assertEquals(ValidationRunner.Mode.RUN, config.mode());
    }

    @Test
    void blankLinesAndCommentsAreIgnored() {
        String yaml = """
                # a comment
                redkite:
                  maven:
                    # another comment
                    profile: dev
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("dev", config.profile());
    }

    @Test
    void quotedValuesAreUnwrapped() {
        String yaml = """
                redkite:
                  maven:
                    profile: 'dev'
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("dev", config.profile());
    }

    @Test
    void envValueContainingAColonIsKeptIntact() {
        String yaml = """
                redkite:
                  maven:
                    env:
                      DB_URL: jdbc:postgresql://localhost:5432/db
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("jdbc:postgresql://localhost:5432/db", config.env().get("DB_URL"));
    }

    @Test
    void springSectionDoesNotLeakIntoEnv() {
        String yaml = """
                redkite:
                  maven:
                    env:
                      DB_HOST: localhost
                    spring:
                      profiles: dev
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals(Map.of("DB_HOST", "localhost"), config.env());
        assertEquals("dev", config.springProfiles());
    }

    @Test
    void fieldsOutsideRedkiteMavenAreIgnored() {
        // A bare top-level "maven:" (missing the "redkite:" wrapper) must not be picked up.
        String yaml = "maven:\n  profile: dev\n";
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertNull(config.profile());
    }

    @Test
    void unrecognizedKeysAreIgnoredNotFatal() {
        String yaml = """
                redkite:
                  maven:
                    somethingFromTheFuture: whatever
                    profile: dev
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("dev", config.profile());
    }

    @Test
    void emptyContentProducesEmptyConfig() {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse("");
        assertTrue(config.args().isEmpty());
        assertNull(config.profile());
        assertEquals(ValidationRunner.Mode.RUN, config.mode());
        assertTrue(config.env().isEmpty());
        assertNull(config.springProfiles());
    }

    @Test
    void missingFileReturnsEmptyConfig(@TempDir Path tempDir) {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.load(tempDir);
        assertEquals(ProjectConfigFile.ProjectConfig.EMPTY, config);
    }

    @Test
    void ensureDefaultExistsCreatesACommentedOutTemplate(@TempDir Path tempDir) throws IOException {
        ProjectConfigFile.ensureDefaultExists(tempDir);

        Path configPath = tempDir.resolve(ProjectConfigFile.RELATIVE_PATH);
        assertTrue(Files.exists(configPath));
        // Fully commented out — its mere presence must not change validation behavior.
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.load(tempDir);
        assertEquals(ProjectConfigFile.ProjectConfig.EMPTY, config);
    }

    @Test
    void ensureDefaultExistsNeverOverwritesAnExistingFile(@TempDir Path tempDir) throws IOException {
        Path configDir = tempDir.resolve(".redkite");
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve("config.yml"), "redkite:\n  maven:\n    profile: keep-me\n");

        ProjectConfigFile.ensureDefaultExists(tempDir);

        assertEquals("keep-me", ProjectConfigFile.load(tempDir).profile());
    }

    @Test
    void ensureDefaultExistsIsANoOpOnAnEmptyExistingFile(@TempDir Path tempDir) throws IOException {
        // A project that deliberately left the file empty must not have it silently replaced.
        Path configDir = tempDir.resolve(".redkite");
        Files.createDirectories(configDir);
        Path configPath = configDir.resolve("config.yml");
        Files.writeString(configPath, "");

        ProjectConfigFile.ensureDefaultExists(tempDir);

        assertEquals("", Files.readString(configPath));
    }

    @Test
    void loadsRealFileFromDisk(@TempDir Path tempDir) throws IOException {
        Path configDir = tempDir.resolve(".redkite");
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve("config.yml"), "redkite:\n  maven:\n    profile: ci\n");

        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.load(tempDir);
        assertEquals("ci", config.profile());
    }

    @Test
    void toBuildArgsAppendsProfileFlagAfterArgs() {
        ProjectConfigFile.ProjectConfig config = new ProjectConfigFile.ProjectConfig(
                List.of("-Dfoo=bar"), "dev", ValidationRunner.Mode.RUN, Map.of(), "dev,local");
        assertEquals(List.of("-Dfoo=bar", "-Pdev"), config.toBuildArgs());
    }

    @Test
    void springBootArgsOnlyContainsProfilesFlag() {
        ProjectConfigFile.ProjectConfig config = new ProjectConfigFile.ProjectConfig(
                List.of("-Dfoo=bar"), "dev", ValidationRunner.Mode.RUN, Map.of(), "dev,local");
        assertEquals(List.of("-Dspring-boot.run.profiles=dev,local"), config.springBootArgs());
    }

    @Test
    void springBootArgsEmptyWhenNotSet() {
        assertEquals(List.of(), ProjectConfigFile.ProjectConfig.EMPTY.springBootArgs());
    }

    @Test
    void toBuildArgsSkipsBlankProfile() {
        ProjectConfigFile.ProjectConfig config = new ProjectConfigFile.ProjectConfig(
                List.of(), "", ValidationRunner.Mode.RUN, Map.of(), null);
        assertEquals(List.of(), config.toBuildArgs());
    }

    @Test
    void indentWidthIsNotHardcoded() {
        // 4-space indent throughout, instead of 2 — must still parse correctly.
        String yaml = """
                redkite:
                    maven:
                        mode: test
                        env:
                            DB_HOST: localhost
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals(ValidationRunner.Mode.TEST, config.mode());
        assertEquals("localhost", config.env().get("DB_HOST"));
    }
}
