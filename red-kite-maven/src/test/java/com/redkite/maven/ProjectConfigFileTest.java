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
    void parsesAllFieldsNestedUnderMaven() {
        String yaml = """
                maven:
                  mode: verify
                  profile: dev
                  args:
                    -Dfoo=bar
                  env:
                    SPRING_PROFILES_ACTIVE: dev
                    DB_HOST: localhost
                  spring:
                    profiles: dev,local
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);

        assertEquals("-Dfoo=bar", config.args());
        assertEquals("dev", config.profile());
        assertEquals(ValidationRunner.Mode.VERIFY, config.mode());
        assertEquals(Map.of("SPRING_PROFILES_ACTIVE", "dev", "DB_HOST", "localhost"), config.env());
        assertEquals("dev,local", config.springProfiles());
    }

    @Test
    void argsAlsoAcceptsAnInlineValue() {
        // Real YAML: "args: -Dfoo=bar" (inline) and "args:\n  -Dfoo=bar" (continuation) mean
        // the same thing — both must work.
        String yaml = """
                maven:
                  args: -Dfoo=bar -Dbaz=qux
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("-Dfoo=bar -Dbaz=qux", config.args());
    }

    @Test
    void modeDefaultsToRun() {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse("maven:\n  profile: dev\n");
        assertEquals(ValidationRunner.Mode.RUN, config.mode());
    }

    @Test
    void modeIsCaseInsensitiveAndCoversAllThreeValues() {
        assertEquals(ValidationRunner.Mode.RUN, ProjectConfigFile.parse("maven:\n  mode: run\n").mode());
        assertEquals(ValidationRunner.Mode.RUN, ProjectConfigFile.parse("maven:\n  mode: RUN\n").mode());
        assertEquals(ValidationRunner.Mode.VERIFY, ProjectConfigFile.parse("maven:\n  mode: verify\n").mode());
        assertEquals(ValidationRunner.Mode.VERIFY, ProjectConfigFile.parse("maven:\n  mode: Verify\n").mode());
        assertEquals(ValidationRunner.Mode.TEST, ProjectConfigFile.parse("maven:\n  mode: test\n").mode());
    }

    @Test
    void unrecognizedModeDefaultsToRun() {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse("maven:\n  mode: nonsense\n");
        assertEquals(ValidationRunner.Mode.RUN, config.mode());
    }

    @Test
    void blankLinesAndCommentsAreIgnored() {
        String yaml = """
                # a comment
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
                maven:
                  args: "-Dfoo=bar -Dbaz=qux"
                  profile: 'dev'
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("-Dfoo=bar -Dbaz=qux", config.args());
        assertEquals("dev", config.profile());
    }

    @Test
    void envValueContainingAColonIsKeptIntact() {
        String yaml = """
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
    void fieldsOutsideTheMavenKeyAreIgnored() {
        // Everything lives under "maven:" now — a bare top-level "profile:" (the old flat shape)
        // must not be picked up.
        String yaml = "profile: dev\n";
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertNull(config.profile());
    }

    @Test
    void unrecognizedKeysAreIgnoredNotFatal() {
        String yaml = """
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
        assertNull(config.args());
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
    void loadsRealFileFromDisk(@TempDir Path tempDir) throws IOException {
        Path configDir = tempDir.resolve(".redkite");
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve("config.yml"), "maven:\n  profile: ci\n");

        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.load(tempDir);
        assertEquals("ci", config.profile());
    }

    @Test
    void toBuildArgsExcludesSpringProfiles() {
        ProjectConfigFile.ProjectConfig config = new ProjectConfigFile.ProjectConfig(
                "-Dfoo=bar", "dev", ValidationRunner.Mode.RUN, Map.of(), "dev,local");
        assertEquals(List.of("-Dfoo=bar", "-Pdev"), config.toBuildArgs());
    }

    @Test
    void springBootArgsOnlyContainsProfilesFlag() {
        ProjectConfigFile.ProjectConfig config = new ProjectConfigFile.ProjectConfig(
                "-Dfoo=bar", "dev", ValidationRunner.Mode.RUN, Map.of(), "dev,local");
        assertEquals(List.of("-Dspring-boot.run.profiles=dev,local"), config.springBootArgs());
    }

    @Test
    void springBootArgsEmptyWhenNotSet() {
        assertEquals(List.of(), ProjectConfigFile.ProjectConfig.EMPTY.springBootArgs());
    }

    @Test
    void toBuildArgsSkipsBlankFields() {
        ProjectConfigFile.ProjectConfig config = new ProjectConfigFile.ProjectConfig(
                null, "", ValidationRunner.Mode.RUN, Map.of(), null);
        assertEquals(List.of(), config.toBuildArgs());
    }

    @Test
    void indentWidthIsNotHardcoded() {
        // 4-space indent throughout, instead of 2 — must still parse correctly.
        String yaml = """
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
