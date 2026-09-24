package com.redkite.maven;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MavenSettingsReaderTest {
    private static final String CENTRAL = "https://repo1.maven.org/maven2";

    @TempDir
    Path tempDir;

    private String originalHome;
    private Path home;

    @BeforeEach
    void isolateUserHome() throws Exception {
        originalHome = System.getProperty("user.home");
        home = Files.createDirectories(tempDir.resolve("home"));
        System.setProperty("user.home", home.toString());
    }

    @AfterEach
    void restoreUserHome() {
        System.setProperty("user.home", originalHome);
    }

    private Path writeHomeSettings(String xml) throws Exception {
        Path settings = home.resolve(".m2/settings.xml");
        Files.createDirectories(settings.getParent());
        Files.writeString(settings, xml);
        return settings;
    }

    private Path writeFile(Path path, String content) throws Exception {
        Files.createDirectories(path.getParent());
        Files.writeString(path, content);
        return path;
    }

    // ---------------------------------------------------------------- resolveSettingsFile

    @Test
    void resolveReturnsNullWhenNoSettingsAnywhere() {
        assertNull(MavenSettingsReader.resolveSettingsFile(null));
        assertNull(MavenSettingsReader.resolveSettingsFile());
        assertNull(MavenSettingsReader.resolveSettingsFile(tempDir.resolve("project")));
    }

    @Test
    void resolveFallsBackToHomeSettings() throws Exception {
        Path settings = writeHomeSettings("<settings/>");
        assertEquals(settings, MavenSettingsReader.resolveSettingsFile(tempDir.resolve("project")));
        assertEquals(settings, MavenSettingsReader.resolveSettingsFile());
    }

    @Test
    void resolvePrefersProjectLocalSettingsOverHome() throws Exception {
        writeHomeSettings("<settings/>");
        Path project = tempDir.resolve("project");
        Path local = writeFile(project.resolve(".m2/settings.xml"), "<settings/>");
        assertEquals(local, MavenSettingsReader.resolveSettingsFile(project));
    }

    @Test
    void resolveReadsRelativeSettingsPathFromMavenConfig() throws Exception {
        writeHomeSettings("<settings/>");
        Path project = tempDir.resolve("project");
        Path custom = writeFile(project.resolve("config/custom-settings.xml"), "<settings/>");
        writeFile(project.resolve(".mvn/maven.config"), "-B -s config/custom-settings.xml -U");
        assertEquals(custom.toAbsolutePath(), MavenSettingsReader.resolveSettingsFile(project));
    }

    @Test
    void resolveReadsAbsoluteLongFormSettingsPathFromMavenConfig() throws Exception {
        Path project = tempDir.resolve("project");
        Path custom = writeFile(tempDir.resolve("elsewhere/settings.xml"), "<settings/>");
        writeFile(project.resolve(".mvn/maven.config"), "--settings " + custom.toAbsolutePath());
        assertEquals(custom.toAbsolutePath(), MavenSettingsReader.resolveSettingsFile(project));
    }

    @Test
    void resolveIgnoresMavenConfigPointingAtMissingFileOrWithoutSettingsFlag() throws Exception {
        Path home = writeHomeSettings("<settings/>");
        Path project = tempDir.resolve("project");
        writeFile(project.resolve(".mvn/maven.config"), "-s missing.xml");
        assertEquals(home, MavenSettingsReader.resolveSettingsFile(project));

        Files.writeString(project.resolve(".mvn/maven.config"), "-B -U -s");
        assertEquals(home, MavenSettingsReader.resolveSettingsFile(project));
    }

    @Test
    void isProjectLocalSettings() {
        Path project = tempDir.resolve("project");
        assertTrue(MavenSettingsReader.isProjectLocalSettings(project.resolve(".m2/settings.xml"), project));
        assertFalse(MavenSettingsReader.isProjectLocalSettings(home.resolve(".m2/settings.xml"), project));
        assertFalse(MavenSettingsReader.isProjectLocalSettings(null, project));
        assertFalse(MavenSettingsReader.isProjectLocalSettings(project.resolve("x"), null));
    }

    // ---------------------------------------------------------------- discoverRepositoryConfigs

    @Test
    void configsFallBackToCentralWithoutSettings() {
        assertEquals(List.of(new MavenSettingsReader.RepoConfig(CENTRAL, null, null)),
                MavenSettingsReader.discoverRepositoryConfigs());
    }

    @Test
    void configsFallBackToCentralOnUnparseableSettings() throws Exception {
        writeHomeSettings("this is not xml");
        assertEquals(List.of(new MavenSettingsReader.RepoConfig(CENTRAL, null, null)),
                MavenSettingsReader.discoverRepositoryConfigs(null));
    }

    @Test
    void configsWithEmptySettingsStillIncludeCentral() throws Exception {
        writeHomeSettings("<settings/>");
        assertEquals(List.of(new MavenSettingsReader.RepoConfig(CENTRAL, null, null)),
                MavenSettingsReader.discoverRepositoryConfigs(null));
    }

    @Test
    void mirrorOfStarReplacesCentralAndCarriesMatchingServerCredentials() throws Exception {
        writeHomeSettings("""
                <settings>
                  <servers>
                    <server><id>corp</id><username>alice</username><password>secret</password></server>
                    <server><username>no-id</username></server>
                  </servers>
                  <mirrors>
                    <mirror><id>corp</id><mirrorOf>*</mirrorOf><url>https://repo.corp/maven/</url></mirror>
                    <mirror><id>dup</id><mirrorOf>central</mirrorOf><url>https://repo.corp/maven</url></mirror>
                    <mirror><id>other</id><mirrorOf>snapshots</mirrorOf><url>https://ignored</url></mirror>
                    <mirror><id>nourl</id><mirrorOf>*</mirrorOf></mirror>
                  </mirrors>
                  <profiles>
                    <profile>
                      <id>extra</id>
                      <repositories><repository><url>https://bypass.example/</url></repository></repositories>
                    </profile>
                  </profiles>
                  <activeProfiles><activeProfile>extra</activeProfile></activeProfiles>
                </settings>
                """);
        List<MavenSettingsReader.RepoConfig> configs = MavenSettingsReader.discoverRepositoryConfigs(null);
        // Profile repos are skipped because mirrorOf=* routes everything through the mirror,
        // and Central is not appended because the mirror covers it.
        assertEquals(List.of(new MavenSettingsReader.RepoConfig("https://repo.corp/maven", "alice", "secret")), configs);
    }

    @Test
    void centralOnlyMirrorKeepsActiveAndDefaultProfileRepositories() throws Exception {
        writeHomeSettings("""
                <settings>
                  <mirrors>
                    <mirror><id>m</id><mirrorOf>central, other</mirrorOf><url>https://mirror.example</url></mirror>
                  </mirrors>
                  <profiles>
                    <profile>
                      <id>explicit</id>
                      <repositories>
                        <repository><url>https://explicit.example/</url></repository>
                        <repository><url>  </url></repository>
                      </repositories>
                    </profile>
                    <profile>
                      <id>by-default</id>
                      <activation><activeByDefault>TRUE</activeByDefault></activation>
                      <repositories><repository><url>https://default.example</url></repository></repositories>
                    </profile>
                    <profile>
                      <id>inactive</id>
                      <activation><activeByDefault>false</activeByDefault></activation>
                      <repositories><repository><url>https://inactive.example</url></repository></repositories>
                    </profile>
                    <profile>
                      <id>no-repos</id>
                      <activation><activeByDefault>true</activeByDefault></activation>
                    </profile>
                  </profiles>
                  <activeProfiles><activeProfile>explicit</activeProfile><activeProfile> </activeProfile></activeProfiles>
                </settings>
                """);
        List<MavenSettingsReader.RepoConfig> configs = MavenSettingsReader.discoverRepositoryConfigs(null);
        assertEquals(List.of(
                new MavenSettingsReader.RepoConfig("https://mirror.example", null, null),
                new MavenSettingsReader.RepoConfig("https://explicit.example", null, null),
                new MavenSettingsReader.RepoConfig("https://default.example", null, null)), configs);
    }

    @Test
    void externalStarMirrorCountsAsMirroringEverything() throws Exception {
        writeHomeSettings("""
                <settings>
                  <mirrors><mirror><id>m</id><mirrorOf>external:*</mirrorOf><url>https://ext.example</url></mirror></mirrors>
                  <profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault></activation>
                    <repositories><repository><url>https://skipped.example</url></repository></repositories></profile></profiles>
                </settings>
                """);
        assertEquals(List.of(new MavenSettingsReader.RepoConfig("https://ext.example", null, null)),
                MavenSettingsReader.discoverRepositoryConfigs(null));
    }

    @Test
    void profileRepositoriesWithoutMirrorAreFollowedByCentral() throws Exception {
        writeHomeSettings("""
                <settings>
                  <mirrors><mirror><mirrorOf>snapshots</mirrorOf><url>https://snap.example</url></mirror></mirrors>
                  <profiles><profile><id>p</id>
                    <repositories><repository><url>https://p.example</url></repository>
                      <repository><url>https://repo1.maven.org/maven2/</url></repository></repositories></profile></profiles>
                  <activeProfiles><activeProfile>p</activeProfile></activeProfiles>
                </settings>
                """);
        assertEquals(List.of(
                new MavenSettingsReader.RepoConfig("https://p.example", null, null),
                new MavenSettingsReader.RepoConfig(CENTRAL, null, null)),
                MavenSettingsReader.discoverRepositoryConfigs(null));
    }

    @Test
    void mirrorWithoutMatchingServerHasNoCredentials() throws Exception {
        writeHomeSettings("""
                <settings>
                  <servers><server><id>someone-else</id><username>u</username><password>p</password></server></servers>
                  <mirrors><mirror><id>m</id><mirrorOf>*</mirrorOf><url>https://m.example</url></mirror></mirrors>
                </settings>
                """);
        assertEquals(List.of(new MavenSettingsReader.RepoConfig("https://m.example", null, null)),
                MavenSettingsReader.discoverRepositoryConfigs(null));
    }

    @Test
    void mirrorWithoutIdStillUsed() throws Exception {
        writeHomeSettings("""
                <settings><mirrors><mirror><mirrorOf>*</mirrorOf><url>https://anon.example</url></mirror></mirrors></settings>
                """);
        assertEquals(List.of(new MavenSettingsReader.RepoConfig("https://anon.example", null, null)),
                MavenSettingsReader.discoverRepositoryConfigs(null));
    }

    @Test
    void projectLocalSettingsWinForConfigs() throws Exception {
        writeHomeSettings("""
                <settings><mirrors><mirror><mirrorOf>*</mirrorOf><url>https://home.example</url></mirror></mirrors></settings>
                """);
        Path project = tempDir.resolve("project");
        writeFile(project.resolve(".m2/settings.xml"), """
                <settings><mirrors><mirror><mirrorOf>*</mirrorOf><url>https://project.example</url></mirror></mirrors></settings>
                """);
        assertEquals("https://project.example", MavenSettingsReader.discoverRepositoryConfigs(project).get(0).url());
    }

    // ---------------------------------------------------------------- discoverRepositoryUrls

    @Test
    void urlsFallBackToCentral() throws Exception {
        assertEquals(CENTRAL, MavenSettingsReader.discoverRepositoryUrls());
        writeHomeSettings("not xml");
        assertEquals(CENTRAL, MavenSettingsReader.discoverRepositoryUrls());
    }

    @Test
    void urlsJoinMirrorsProfilesAndCentral() throws Exception {
        writeHomeSettings("""
                <settings>
                  <mirrors>
                    <mirror><mirrorOf>snapshots</mirrorOf><url>https://ignored.example</url></mirror>
                    <mirror><mirrorOf>private</mirrorOf></mirror>
                  </mirrors>
                  <profiles><profile><id>p</id>
                    <repositories><repository><url>https://p.example/</url></repository></repositories></profile></profiles>
                  <activeProfiles><activeProfile>p</activeProfile></activeProfiles>
                </settings>
                """);
        assertEquals("https://p.example," + CENTRAL, MavenSettingsReader.discoverRepositoryUrls());
    }

    @Test
    void urlsWithCentralMirrorOmitCentral() throws Exception {
        writeHomeSettings("""
                <settings>
                  <mirrors><mirror><mirrorOf>central</mirrorOf><url>https://m.example/</url></mirror></mirrors>
                  <profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault></activation>
                    <repositories><repository><url>https://m.example</url></repository>
                    <repository><url>https://p.example</url></repository></repositories></profile></profiles>
                </settings>
                """);
        assertEquals("https://m.example,https://p.example", MavenSettingsReader.discoverRepositoryUrls());
    }

    @Test
    void parseReturnsEmptyListOnlyWhenNothingUsableAndCentralMirrored() throws Exception {
        Path settings = writeFile(tempDir.resolve("s.xml"), "<settings/>");
        assertEquals(List.of(CENTRAL), MavenSettingsReader.parse(settings));
    }

    // ---------------------------------------------------------------- resolveCredential

    @Test
    void credentialsResolveEnvironmentPlaceholders() {
        String path = System.getenv("PATH");
        assertNotNull(path, "test needs PATH in the environment");
        assertEquals("pre-" + path + "-post", MavenSettingsReader.resolveCredential("username", "pre-${env.PATH}-post", "id"));
    }

    @Test
    void credentialsWithMissingEnvironmentVariableAreDropped() {
        assertNull(MavenSettingsReader.resolveCredential("password", "${env.REDKITE_TEST_SURELY_UNSET_VARIABLE}", "id"));
    }

    @Test
    void credentialsWithOtherUnresolvedPlaceholdersAreDropped() {
        assertNull(MavenSettingsReader.resolveCredential("password", "${settings.secret}", "id"));
    }

    @Test
    void blankOrNullCredentialsAreNull() {
        assertNull(MavenSettingsReader.resolveCredential("username", null, "id"));
        assertNull(MavenSettingsReader.resolveCredential("username", "   ", "id"));
        assertEquals("plain", MavenSettingsReader.resolveCredential("username", "plain", "id"));
    }

    @Test
    void serverCredentialsUsingUnsetEnvironmentAreNotSent() throws Exception {
        writeHomeSettings("""
                <settings>
                  <servers><server><id>m</id><username>${env.REDKITE_TEST_SURELY_UNSET_VARIABLE}</username><password>p</password></server></servers>
                  <mirrors><mirror><id>m</id><mirrorOf>*</mirrorOf><url>https://m.example</url></mirror></mirrors>
                </settings>
                """);
        assertEquals(List.of(new MavenSettingsReader.RepoConfig("https://m.example", null, "p")),
                MavenSettingsReader.discoverRepositoryConfigs(null));
    }
}
