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
                springProfiles: dev,local
                env:
                  SPRING_PROFILES_ACTIVE: dev
                  DB_HOST: localhost
                """;
        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.parse(yaml);

        assertEquals("-Dfoo=bar", config.mavenArgs());
        assertEquals("dev", config.profile());
        assertEquals("dev,local", config.springProfiles());
        assertEquals(Map.of("SPRING_PROFILES_ACTIVE", "dev", "DB_HOST", "localhost"), config.env());
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
        assertNull(config.springProfiles());
        assertTrue(config.env().isEmpty());
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
        Files.writeString(configDir.resolve("project.cfg"), "profile: ci\n");

        ProjectConfigFile.ProjectConfig config = ProjectConfigFile.load(tempDir);
        assertEquals("ci", config.profile());
    }

    @Test
    void toMavenArgsCombinesAllThreeSourcesInOrder() {
        ProjectConfigFile.ProjectConfig config = new ProjectConfigFile.ProjectConfig(
                "-Dfoo=bar -Dbaz=qux", "dev", "dev,local", Map.of());
        assertEquals(List.of("-Dfoo=bar", "-Dbaz=qux", "-Pdev", "-Dspring-boot.run.profiles=dev,local"),
                config.toMavenArgs());
    }

    @Test
    void toMavenArgsSkipsBlankFields() {
        ProjectConfigFile.ProjectConfig config = new ProjectConfigFile.ProjectConfig(null, "", "dev", Map.of());
        assertEquals(List.of("-Dspring-boot.run.profiles=dev"), config.toMavenArgs());
    }
}
