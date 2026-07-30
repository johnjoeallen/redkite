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
    void parsesAllFields() {
        String yaml = """
                mavenArgs: -Dfoo=bar
                profile: dev
                mode: verify
                env:
                  SPRING_PROFILES_ACTIVE: dev
                  DB_HOST: localhost
                springBoot:
                  profiles: dev,local
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);

        assertEquals("-Dfoo=bar", config.mavenArgs());
        assertEquals("dev", config.profile());
        assertEquals(ValidationRunner.Mode.VERIFY, config.mode());
        assertEquals(Map.of("SPRING_PROFILES_ACTIVE", "dev", "DB_HOST", "localhost"), config.env());
        assertEquals("dev,local", config.springBootProfiles());
    }

    @Test
    void modeDefaultsToRun() {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse("mavenArgs: -Dfoo=bar\n");
        assertEquals(ValidationRunner.Mode.RUN, config.mode());
    }

    @Test
    void modeIsCaseInsensitiveAndCoversAllThreeValues() {
        assertEquals(ValidationRunner.Mode.RUN, ProjectConfigFile.parse("mode: run\n").mode());
        assertEquals(ValidationRunner.Mode.RUN, ProjectConfigFile.parse("mode: RUN\n").mode());
        assertEquals(ValidationRunner.Mode.VERIFY, ProjectConfigFile.parse("mode: verify\n").mode());
        assertEquals(ValidationRunner.Mode.VERIFY, ProjectConfigFile.parse("mode: Verify\n").mode());
        assertEquals(ValidationRunner.Mode.TEST, ProjectConfigFile.parse("mode: test\n").mode());
    }

    @Test
    void unrecognizedModeDefaultsToRun() {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse("mode: nonsense\n");
        assertEquals(ValidationRunner.Mode.RUN, config.mode());
    }

    @Test
    void blankLinesAndCommentsAreIgnored() {
        String yaml = """
                # a comment
                mavenArgs: -Dfoo=bar

                # another comment
                profile: dev
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("-Dfoo=bar", config.mavenArgs());
        assertEquals("dev", config.profile());
    }

    @Test
    void quotedValuesAreUnwrapped() {
        String yaml = """
                mavenArgs: "-Dfoo=bar -Dbaz=qux"
                profile: 'dev'
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("-Dfoo=bar -Dbaz=qux", config.mavenArgs());
        assertEquals("dev", config.profile());
    }

    @Test
    void envValueContainingAColonIsKeptIntact() {
        String yaml = """
                env:
                  DB_URL: jdbc:postgresql://localhost:5432/db
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("jdbc:postgresql://localhost:5432/db", config.env().get("DB_URL"));
    }

    @Test
    void springBootSectionDoesNotLeakIntoEnv() {
        String yaml = """
                env:
                  DB_HOST: localhost
                springBoot:
                  profiles: dev
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals(Map.of("DB_HOST", "localhost"), config.env());
        assertEquals("dev", config.springBootProfiles());
    }

    @Test
    void unrecognizedKeysAreIgnoredNotFatal() {
        String yaml = """
                somethingFromTheFuture: whatever
                mavenArgs: -Dfoo=bar
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);
        assertEquals("-Dfoo=bar", config.mavenArgs());
    }

    @Test
    void emptyContentProducesEmptyConfig() {
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse("");
        assertNull(config.mavenArgs());
        assertNull(config.profile());
        assertEquals(ValidationRunner.Mode.RUN, config.mode());
        assertTrue(config.env().isEmpty());
        assertNull(config.springBootProfiles());
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
        Files.writeString(configDir.resolve("config.yml"), "profile: ci\n");

        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.load(tempDir);
        assertEquals("ci", config.profile());
    }

    @Test
    void toBuildArgsExcludesSpringBootProfiles() {
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
}
