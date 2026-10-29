package com.redkite.metadata;

import com.redkite.core.domain.CacheState;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.MetadataStatus;
import com.redkite.core.domain.VersionMetadata;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class HttpVersionMetadataProviderTest {
    private static final ComponentCoordinate LIB = new ComponentCoordinate("org.example", "lib");
    private static final String LIB_PATH = "/repo/org/example/lib/maven-metadata.xml";
    private static final String LIB_METADATA = """
            <metadata>
              <groupId>org.example</groupId><artifactId>lib</artifactId>
              <versioning>
                <latest>2.1-SNAPSHOT</latest>
                <release>2.0.0</release>
                <versions>
                  <version>1.0</version>
                  <version>1.1</version>
                  <version>1.2.0</version>
                  <version>2.0.0-RC1</version>
                  <version>2.0.0</version>
                  <version> </version>
                </versions>
              </versioning>
            </metadata>
            """;

    private record Response(int status, String body) {}

    @TempDir
    Path tempDir;

    private HttpServer server;
    private String base;
    private final Map<String, Response> responses = Collections.synchronizedMap(new LinkedHashMap<>());
    private final List<String> requests = Collections.synchronizedList(new ArrayList<>());
    private TestDb db;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String uri = exchange.getRequestURI().toString();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            requests.add(exchange.getRequestMethod() + " " + uri + (auth == null ? "" : " auth=" + auth));
            Response r = responses.get(exchange.getRequestMethod() + " " + uri);
            if (r == null) r = responses.get(uri);
            if (r != null && r.status() == 401 && auth != null) {
                r = responses.get("authorized " + uri);
            }
            if (r == null) r = new Response(404, "");
            byte[] body = r.body().getBytes(StandardCharsets.UTF_8);
            boolean head = exchange.getRequestMethod().equals("HEAD");
            exchange.sendResponseHeaders(r.status(), body.length == 0 || head ? -1 : body.length);
            if (body.length > 0 && !head) exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        System.setProperty(HttpVersionMetadataProvider.CENTRAL_URL_PROPERTY, base + "/central");
        db = new TestDb();
    }

    @AfterEach
    void tearDown() throws Exception {
        server.stop(0);
        System.clearProperty(HttpVersionMetadataProvider.CENTRAL_URL_PROPERTY);
        db.close();
    }

    private HttpVersionMetadataProvider provider(String urls) {
        return new HttpVersionMetadataProvider(urls, null, null, db);
    }

    private long expiresInMinutes(String key) throws Exception {
        long expires = Long.parseLong(db.query("select expires_at_epoch_ms from rk_version_cache where cache_key = '" + key + "'"));
        return Duration.between(Instant.now(), Instant.ofEpochMilli(expires)).toMinutes();
    }

    @Test
    void parsesMavenMetadataAndComputesRecommendations() throws Exception {
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));

        VersionMetadata metadata = provider(base + "/repo/").latestVersion(LIB, "1.1");

        assertEquals("2.0.0", metadata.latestVersion(), "pre-releases and snapshots are not recommendation targets");
        assertEquals("1.1", metadata.latestSameMajorVersion());
        assertEquals(List.of("1.2.0", "2.1-SNAPSHOT"), metadata.upgradePathVersions());
        assertEquals(List.of("1.0", "1.1", "1.2.0", "2.0.0"), metadata.allStableVersions());
        assertTrue(metadata.release());
        assertTrue(metadata.complete());
        assertEquals(MetadataStatus.FRESH, metadata.status());
        assertEquals(CacheState.FRESH, metadata.cacheState());
        assertEquals(base + LIB_PATH, metadata.source());
        assertEquals("1.0,1.1,1.2.0,2.0.0-RC1,2.0.0,2.1-SNAPSHOT",
                db.query("select all_versions from rk_version_cache where cache_key = 'org.example:lib'"));
        // Not on Central (the HEAD check 404s): the short "local" TTL applies.
        assertTrue(requests.contains("HEAD /central/org/example/lib/maven-metadata.xml"));
        assertEquals(59, expiresInMinutes("org.example:lib"), 1);
    }

    @Test
    void artifactOnCentralGetsTheLongTtlAndConfigOverridesIt() throws Exception {
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));
        responses.put("HEAD /central/org/example/lib/maven-metadata.xml", new Response(200, ""));
        db.exec("insert into rk_config(config_key, config_value) values ('cache.ttl.version.fresh', ' 90 ')");

        provider(base + "/repo").latestVersion(LIB, "1.0");

        assertEquals(89, expiresInMinutes("org.example:lib"), 1);
    }

    @Test
    void unparseableTtlConfigFallsBackToTheDefault() throws Exception {
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));
        responses.put("HEAD /central/org/example/lib/maven-metadata.xml", new Response(200, ""));
        db.exec("insert into rk_config(config_key, config_value) values ('cache.ttl.version.fresh', 'soon')");

        provider(base + "/repo").latestVersion(LIB, "1.0");

        assertEquals(24 * 60 - 1, expiresInMinutes("org.example:lib"), 1);
    }

    @Test
    void latestSameMajorFallsBackWhenNoVersionInTheFamilyOrNoCurrentVersion() {
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));
        HttpVersionMetadataProvider provider = provider(base + "/repo");

        assertEquals("2.0.0", provider.latestVersion(LIB, "7.3").latestSameMajorVersion());
        VersionMetadata noCurrent = provider.latestVersion(LIB);
        assertEquals("2.0.0", noCurrent.latestSameMajorVersion());
        // Without a current version, every major is its own family.
        assertEquals(List.of("1.2.0", "2.1-SNAPSHOT"), noCurrent.upgradePathVersions());
    }

    @Test
    void servesRepeatLookupsFromMemoryThenFromTheDatabase() throws Exception {
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));
        provider(base + "/repo").latestVersion(LIB, "1.0");
        int afterFirst = requests.size();

        HttpVersionMetadataProvider second = provider(base + "/repo");
        VersionMetadata fromDb = second.latestVersion(LIB, "1.2.0");
        VersionMetadata fromMemory = second.latestVersion(LIB, "1.2.0");

        assertEquals(afterFirst, requests.size(), "no further HTTP requests");
        assertEquals("2.0.0", fromDb.latestVersion());
        assertEquals("1.2.0", fromDb.latestSameMajorVersion());
        assertEquals(List.of("2.1-SNAPSHOT"), fromDb.upgradePathVersions());
        assertEquals(List.of("1.0", "1.1", "1.2.0", "2.0.0"), fromDb.allStableVersions());
        assertEquals(CacheState.FRESH, fromDb.cacheState());
        assertEquals(fromDb.latestVersion(), fromMemory.latestVersion());
    }

    @Test
    void staleDatabaseEntryIsRefreshed() throws Exception {
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));
        db.exec("insert into rk_version_cache(cache_key, all_versions, latest_version, source, expires_at_epoch_ms, status, complete) "
                + "values ('org.example:lib', '0.9', '0.9', 'old', 1, 'FRESH', true)");

        VersionMetadata metadata = provider(base + "/repo").latestVersion(LIB, "1.0");

        assertEquals("2.0.0", metadata.latestVersion());
        assertTrue(requests.stream().anyMatch(r -> r.startsWith("GET " + LIB_PATH)));
    }

    @Test
    void cachedEntryWithUnknownStatusAndBlankLatestIsStillUsable() throws Exception {
        long future = Instant.now().plus(Duration.ofHours(1)).toEpochMilli();
        db.exec("insert into rk_version_cache(cache_key, all_versions, latest_version, source, expires_at_epoch_ms, status, complete) "
                + "values ('org.example:lib', ' ', '', 'src', " + future + ", 'NOT_A_STATUS', false)");

        VersionMetadata metadata = provider(base + "/repo").latestVersion(LIB, "1.0");

        assertEquals("unknown", metadata.latestVersion());
        assertEquals(MetadataStatus.PROVIDER_ERROR, metadata.status());
        assertFalse(metadata.complete());
        assertEquals(List.of(), metadata.upgradePathVersions());
        assertTrue(requests.isEmpty());
    }

    @Test
    void cachedSnapshotOnlyEntryIsNotARelease() throws Exception {
        long future = Instant.now().plus(Duration.ofHours(1)).toEpochMilli();
        db.exec("insert into rk_version_cache(cache_key, all_versions, latest_version, source, expires_at_epoch_ms, status, complete) "
                + "values ('org.example:lib', '1.0-SNAPSHOT,,1.1-SNAPSHOT', '1.1-SNAPSHOT', 'src', " + future + ", 'FRESH', true)");

        VersionMetadata metadata = provider(base + "/repo").latestVersion(LIB, "1.0-SNAPSHOT");

        assertFalse(metadata.release());
        assertEquals(List.of("1.0-SNAPSHOT", "1.1-SNAPSHOT"), metadata.allStableVersions());
    }

    @Test
    void notFoundIsCachedAsMissingAndClearedByClearErrorCache() throws Exception {
        HttpVersionMetadataProvider provider = provider(base + "/repo");

        VersionMetadata missing = provider.latestVersion(LIB, "1.0");
        assertEquals(MetadataStatus.MISSING, missing.status());
        assertEquals(CacheState.MISSING, missing.cacheState());
        assertEquals("unknown", missing.latestVersion());
        assertEquals(base + "/repo", missing.source());
        assertEquals("MISSING", db.query("select status from rk_version_cache"));
        assertEquals(6 * 60 - 1, expiresInMinutes("org.example:lib"), 1);

        int before = requests.size();
        assertEquals(MetadataStatus.MISSING, provider.latestVersion(LIB, "1.0").status());
        assertEquals(before, requests.size(), "the negative result is cached");

        provider.clearErrorCache();
        assertEquals(0, db.count("rk_version_cache"));
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));
        assertEquals("2.0.0", provider.latestVersion(LIB, "1.0").latestVersion());
    }

    @Test
    void clearErrorCacheKeepsFreshEntriesAndClearAllRemovesEverything() throws Exception {
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));
        HttpVersionMetadataProvider provider = provider(base + "/repo");
        provider.latestVersion(LIB, "1.0");
        provider.latestVersion(new ComponentCoordinate("org.other", "gone"), "1.0");
        assertEquals(2, db.count("rk_version_cache"));

        provider.clearErrorCache();
        assertEquals(1, db.count("rk_version_cache"));

        provider.clearAll();
        assertEquals(0, db.count("rk_version_cache"));
        int before = requests.size();
        provider.latestVersion(LIB, "1.0");
        assertTrue(requests.size() > before, "cleared entries are fetched again");
    }

    @Test
    void serverErrorIsCachedBrieflyAsProviderError() throws Exception {
        responses.put(LIB_PATH, new Response(500, "boom"));

        VersionMetadata metadata = provider(base + "/repo").latestVersion(LIB, "1.0");

        assertEquals(MetadataStatus.PROVIDER_ERROR, metadata.status());
        assertEquals("PROVIDER_ERROR", db.query("select status from rk_version_cache"));
        assertEquals(14, expiresInMinutes("org.example:lib"), 1);
    }

    @Test
    void rateLimitIsReportedAndCached() throws Exception {
        responses.put(LIB_PATH, new Response(429, ""));

        VersionMetadata metadata = provider(base + "/repo").latestVersion(LIB, "1.0");

        assertEquals(MetadataStatus.RATE_LIMITED, metadata.status());
        assertEquals(base + LIB_PATH, metadata.source());
        assertEquals("RATE_LIMITED", db.query("select status from rk_version_cache"));
    }

    @Test
    void emptyMetadataIsMissing() {
        responses.put(LIB_PATH, new Response(200, "<metadata><groupId>org.example</groupId></metadata>"));
        assertEquals(MetadataStatus.MISSING, provider(base + "/repo").latestVersion(LIB, "1.0").status());
    }

    @Test
    void metadataWithOnlyReleaseAndLatestElements() {
        responses.put(LIB_PATH, new Response(200,
                "<metadata><versioning><release>3.0</release><latest>3.0</latest></versioning></metadata>"));
        VersionMetadata metadata = provider(base + "/repo").latestVersion(LIB, "2.0");
        assertEquals("3.0", metadata.latestVersion());
        assertEquals(List.of("3.0"), metadata.upgradePathVersions());
    }

    @Test
    void longUnparseableBodyIsAProviderError() {
        responses.put(LIB_PATH, new Response(200, "x".repeat(1000)));
        assertEquals(MetadataStatus.PROVIDER_ERROR, provider(base + "/repo").latestVersion(LIB, "1.0").status());
    }

    @Test
    void longMetadataWithoutVersionsIsMissing() {
        responses.put(LIB_PATH, new Response(200, "<metadata><!--" + "x".repeat(1000) + "--></metadata>"));
        assertEquals(MetadataStatus.MISSING, provider(base + "/repo").latestVersion(LIB, "1.0").status());
    }

    @Test
    void retriesWithCredentialsAfterAnonymous401() {
        responses.put(LIB_PATH, new Response(401, ""));
        responses.put("authorized " + LIB_PATH, new Response(200, LIB_METADATA));

        VersionMetadata metadata = new HttpVersionMetadataProvider(base + "/repo", "user", null, db).latestVersion(LIB, "1.0");

        assertEquals("2.0.0", metadata.latestVersion());
        String expectedAuth = "Basic " + Base64.getEncoder().encodeToString("user:".getBytes(StandardCharsets.UTF_8));
        assertTrue(requests.contains("GET " + LIB_PATH + " auth=" + expectedAuth), requests.toString());
    }

    @Test
    void unauthorizedWithoutCredentialsOrWithRejectedOnes() {
        responses.put(LIB_PATH, new Response(401, ""));
        assertEquals(MetadataStatus.PROVIDER_ERROR, provider(base + "/repo").latestVersion(LIB, "1.0").status());

        responses.put("authorized " + LIB_PATH, new Response(401, ""));
        VersionMetadata rejected = new HttpVersionMetadataProvider(base + "/repo", "u", "p").latestVersion(LIB, "1.0");
        assertEquals(MetadataStatus.PROVIDER_ERROR, rejected.status());

        VersionMetadata blankUser = new HttpVersionMetadataProvider(base + "/repo", " ", "p").latestVersion(LIB, "1.0");
        assertEquals(MetadataStatus.PROVIDER_ERROR, blankUser.status());
    }

    @Test
    void laterRepositoryIsTriedAfterAMiss() {
        responses.put("/second/org/example/lib/maven-metadata.xml", new Response(200, LIB_METADATA));

        VersionMetadata metadata = provider(base + "/repo, ," + base + "/second/").latestVersion(LIB, "1.0");

        assertEquals("2.0.0", metadata.latestVersion());
        assertEquals(List.of(base + "/repo", base + "/second"), provider(base + "/repo, ," + base + "/second/").getRepositoryBaseUrls());
    }

    @Test
    void artifactoryUsesTheVersionSearchApiAndSkipsIntegrationBuilds() {
        String query = "/artifactory/api/search/versions?g=org.example&a=lib";
        responses.put(query, new Response(200, """
                {"results":[
                  {"version":"1.0","integration":false},
                  {"integration": true, "version":"1.1-SNAPSHOT"},
                  {"version":"1.2","integration":false},
                  {"version":"1.0","integration":false},
                  {"version":"","integration":false}
                ]}"""));

        VersionMetadata metadata = provider(base + "/artifactory/libs-release").latestVersion(LIB, "1.0");

        assertEquals("1.2", metadata.latestVersion());
        assertEquals(List.of("1.0", "1.2"), metadata.allStableVersions());
        assertTrue(requests.contains("GET " + query), requests.toString());
    }

    @Test
    void artifactoryWithNoResultsIsMissing() {
        responses.put("/Artifactory/api/search/versions?g=org.example&a=lib", new Response(200, "{\"results\":[]}"));
        assertEquals(MetadataStatus.MISSING, provider(base + "/Artifactory/repo").latestVersion(LIB, "1.0").status());
    }

    @Test
    void truncatedArtifactoryJsonStopsParsing() {
        String query = "/artifactory/api/search/versions?g=org.example&a=lib";
        for (String body : List.of("{\"version\"", "{\"version\": ", "{\"version\": \"1.0")) {
            responses.put(query, new Response(200, body));
            HttpVersionMetadataProvider provider = provider(base + "/artifactory");
            assertEquals(MetadataStatus.MISSING, provider.latestVersion(LIB, "1.0").status(), body);
            provider.clearAll();
        }
    }

    @Test
    void unreachableRepositoryIsAProviderError() {
        server.stop(0);
        VersionMetadata metadata = new HttpVersionMetadataProvider(base + "/repo").latestVersion(LIB, "1.0");
        assertEquals(MetadataStatus.PROVIDER_ERROR, metadata.status());
    }

    @Test
    void readsLocalFileRepositories() throws Exception {
        Path repo = tempDir.resolve("repo");
        Path metadataFile = repo.resolve("org/example/lib/maven-metadata.xml");
        Files.createDirectories(metadataFile.getParent());
        Files.writeString(metadataFile, LIB_METADATA);

        VersionMetadata metadata = provider(repo.toUri().toString()).latestVersion(LIB, "1.0");

        assertEquals("2.0.0", metadata.latestVersion());
        assertEquals(MetadataStatus.FRESH, metadata.status());
    }

    @Test
    void localFileRepositoryMissOrParseErrorFallsThrough() throws Exception {
        Path empty = Files.createDirectories(tempDir.resolve("empty"));
        Path broken = tempDir.resolve("broken");
        Files.createDirectories(broken.resolve("org/example/lib"));
        Files.writeString(broken.resolve("org/example/lib/maven-metadata.xml"), "<metadata>");

        assertEquals(MetadataStatus.MISSING, new HttpVersionMetadataProvider(empty.toUri().toString()).latestVersion(LIB, "1.0").status());
        assertEquals(MetadataStatus.PROVIDER_ERROR, new HttpVersionMetadataProvider(broken.toUri().toString()).latestVersion(LIB, "1.0").status());
    }

    @Test
    void worksWithoutADatabaseAndSurvivesABrokenOne() {
        responses.put(LIB_PATH, new Response(200, LIB_METADATA));
        assertEquals("2.0.0", new HttpVersionMetadataProvider(base + "/repo").latestVersion(LIB, "1.0").latestVersion());

        db.breakConnections();
        HttpVersionMetadataProvider provider = provider(base + "/repo");
        assertEquals("2.0.0", provider.latestVersion(LIB, "1.0").latestVersion());
        responses.remove(LIB_PATH);
        assertEquals(MetadataStatus.MISSING, provider.latestVersion(new ComponentCoordinate("a", "b"), "1").status());
        provider.clearErrorCache();
        provider.clearAll();
    }

    @Test
    void defaultsToMavenCentralWhenNoUrlGiven() {
        assertEquals(List.of("https://repo1.maven.org/maven2"), new HttpVersionMetadataProvider(null).getRepositoryBaseUrls());
        assertEquals(List.of("https://repo1.maven.org/maven2"), new HttpVersionMetadataProvider(" ").getRepositoryBaseUrls());
        assertEquals(List.of("https://repo1.maven.org/maven2"), new HttpVersionMetadataProvider(" , ").getRepositoryBaseUrls());
        assertEquals(List.of("https://a"), new HttpVersionMetadataProvider("https://a/", "u", "p").getRepositoryBaseUrls());
    }

    @Test
    void compareVersionsOrdersNumericallyAndQualifiersBelowNumbers() {
        assertEquals(0, HttpVersionMetadataProvider.compareVersions("1.0", "1.0"));
        assertEquals(0, HttpVersionMetadataProvider.compareVersions("1.0", "1.0.0"));
        assertTrue(HttpVersionMetadataProvider.compareVersions("1.10", "1.9") > 0);
        assertTrue(HttpVersionMetadataProvider.compareVersions("1.9", "1.10") < 0);
        assertTrue(HttpVersionMetadataProvider.compareVersions("2.0", "2.0-RC1") > 0, "numeric beats qualifier");
        assertTrue(HttpVersionMetadataProvider.compareVersions("2.0-RC1", "2.0") < 0);
        assertTrue(HttpVersionMetadataProvider.compareVersions("1.0-beta", "1.0-alpha") > 0);
        assertTrue(HttpVersionMetadataProvider.compareVersions("1_2", "1.1") > 0);
        assertTrue(HttpVersionMetadataProvider.compareVersions("1..2", "1.1") > 0);
        assertEquals(0, HttpVersionMetadataProvider.compareVersions(null, ""));
        assertEquals(0, HttpVersionMetadataProvider.compareVersions("-", "0"));
        assertTrue(HttpVersionMetadataProvider.compareVersions("99999999999999999999", "1") < 0,
                "an overflowing number compares as text");
    }

    @Test
    void stableVersionPattern() {
        for (String v : List.of("1.0", "1.2.3", "1.2.3.4", "5.6.15.Final", "5.3.1.RELEASE", "1.0-GA", "2.1.SP2", "3.0.SR1", " 1.0 ", "33.7.2-jre", "33.4.8-android"))
            assertTrue(HttpVersionMetadataProvider.isStableVersion(v), v);
        for (String v : List.of("1", "1.0-SNAPSHOT", "2.0.0-RC1", "1.2.3.4.5", "", "  "))
            assertFalse(HttpVersionMetadataProvider.isStableVersion(v), v);
        assertFalse(HttpVersionMetadataProvider.isStableVersion(null));
    }

    @Test
    void sameFlavorKeepsGuavaJreAndAndroidApart() {
        List<String> versions = List.of("23.0", "33.4.8-jre", "33.4.8-android", "33.5.0-jre", "33.5.0-android");
        assertEquals(List.of("33.4.8-jre", "33.5.0-jre"), HttpVersionMetadataProvider.sameFlavor(versions, "33.4.0-jre"));
        assertEquals(List.of("33.4.8-android", "33.5.0-android"), HttpVersionMetadataProvider.sameFlavor(versions, "33.4.0-android"));
        assertEquals(versions, HttpVersionMetadataProvider.sameFlavor(versions, "23.0"));
        assertEquals(versions, HttpVersionMetadataProvider.sameFlavor(versions, null));
        assertEquals(List.of("23.0"), HttpVersionMetadataProvider.sameFlavor(List.of("23.0"), "33.4.0-jre"));
    }

    @Test
    void preReleaseDetection() {
        for (String v : List.of("1.0-SNAPSHOT", "1.0-alpha", "1.0-beta2", "1.0-RC1", "1.0.rc", "2.0-M3", "2.0-milestone",
                "1.0-preview", "1.0-incubating", "1.0-CR2", "1.0-rc1-x"))
            assertTrue(HttpVersionMetadataProvider.isPreRelease(v), v);
        for (String v : List.of("1.0", "1.0.Final", "1.0-m", "", " "))
            assertFalse(HttpVersionMetadataProvider.isPreRelease(v), v);
        assertFalse(HttpVersionMetadataProvider.isPreRelease(null));
    }

    @Test
    void familiesIgnoreNonNumericSuffixes() {
        responses.put(LIB_PATH, new Response(200, """
                <metadata><versioning><versions>
                  <version>4</version><version>4.1b</version><version>4.1.2</version><version>x.y</version><version>5.0</version>
                </versions></versioning></metadata>"""));
        VersionMetadata metadata = provider(base + "/repo").latestVersion(LIB, "4.1c");
        assertEquals("4.1.2", metadata.latestSameMajorVersion());
        // "4" sorts above "4.1c" because a textual token ("1c") ranks below the implicit 0.
        assertEquals(List.of("4", "4.1.2", "5.0"), metadata.upgradePathVersions());
    }

    private VersionMetadata lookup(String metadataXml, String currentVersion) {
        responses.put(LIB_PATH, new Response(200, metadataXml));
        return provider(base + "/repo").latestVersion(LIB, currentVersion);
    }

    private static String versions(String... versions) {
        StringBuilder xml = new StringBuilder("<metadata><versioning><versions>");
        for (String v : versions) xml.append("<version>").append(v).append("</version>");
        return xml.append("</versions><release> </release><latest></latest></versioning></metadata>").toString();
    }

    @Test
    void withoutACurrentVersionEveryFamilysLatestIsOnThePath() {
        VersionMetadata metadata = lookup(versions("1.0", "1.1", "2.0", "2.1"), " ");
        assertEquals("2.1", metadata.latestVersion());
        assertEquals("2.1", metadata.latestSameMajorVersion());
        assertEquals(List.of("1.1", "2.1"), metadata.upgradePathVersions());
    }

    @Test
    void onlyPreReleasesAreStillUsableAndSnapshotsAreNotReleases() {
        VersionMetadata metadata = lookup(versions("1.0-rc1", "1.1-SNAPSHOT"), "1.0-rc1");
        assertEquals("1.1-SNAPSHOT", metadata.latestVersion());
        assertFalse(metadata.release());
    }

    @Test
    void singleSegmentCurrentVersionIsItsMajorsZeroFamily() {
        VersionMetadata metadata = lookup(versions("3.9", "5.0", "5.0.1", "5.2", "6.0"), "5");
        assertEquals("5.0.1", metadata.latestSameMajorVersion());
        assertEquals(List.of("5.0.1", "5.2", "6.0"), metadata.upgradePathVersions(), "older majors are never on the path");
    }

    @Test
    void nonNumericCurrentVersionIsTreatedAsZero() {
        VersionMetadata metadata = lookup(versions("0.0.1", "0.2", "1.0"), "abc");
        assertEquals("0.0.1", metadata.latestSameMajorVersion(), metadata.toString());
    }

    @Test
    void noVersionInTheCurrentFamilyFallsBackToTheLatest() {
        VersionMetadata metadata = lookup(versions("2.0", "2.1"), "1.5");
        assertEquals("2.1", metadata.latestSameMajorVersion());
    }

    @Test
    void artifactoryIntegrationFlagWithASpaceIsSkipped() {
        responses.put("/artifactory/api/search/versions?g=org.example&a=lib", new Response(200,
                "{\"results\":[{\"version\":\"1.0\",\"integration\": true},{\"version\":\"1.1\"}]}"));
        assertEquals(List.of("1.1"), provider(base + "/artifactory/r").latestVersion(LIB, "1.0").allStableVersions());
    }

    @Test
    void repositoriesThatAreCentralMirrorsSkipTheCentralCheck() {
        for (String host : List.of("repo1.maven.org", "central.maven.org", "repo.maven.apache.org")) {
            requests.clear();
            responses.put("/" + host + "/org/example/" + host + "/maven-metadata.xml", new Response(200, versions("1.0")));
            provider(base + "/" + host).latestVersion(new ComponentCoordinate("org.example", host), "1.0");
            assertFalse(requests.stream().anyMatch(r -> r.startsWith("HEAD ")), host + " " + requests);
        }
    }

    @Test
    void versionsAreSortedAndEqualSpellingsKeepTheFirstSeen() {
        VersionMetadata metadata = lookup(versions("2.0", "1.5", "1.2.0", "1.2", "1.0"), "1.0");
        assertEquals(List.of("1.0", "1.2.0", "1.2", "1.5", "2.0"), metadata.allStableVersions());
        assertEquals(List.of("1.2.0", "1.5", "2.0"), metadata.upgradePathVersions(), "1.2 and 1.2.0 are the same release: the first listed stands");
    }

    @Test
    void latestInTheFamilyKeepsTheFirstOfEqualSpellings() {
        assertEquals("1.2", lookup(versions("1.2", "1.2.0", "1.1"), "1.2.0").latestSameMajorVersion());
    }

    @Test
    void clearErrorCacheKeepsAFreshInMemoryEntry() {
        responses.put(LIB_PATH, new Response(200, versions("1.0", "1.1")));
        HttpVersionMetadataProvider noDb = new HttpVersionMetadataProvider(base + "/repo", null, null);
        noDb.latestVersion(LIB, "1.0");
        long gets = requests.stream().filter(r -> r.startsWith("GET ")).count();
        noDb.clearErrorCache();
        assertEquals("1.1", noDb.latestVersion(LIB, "1.0").latestVersion());
        assertEquals(gets, requests.stream().filter(r -> r.startsWith("GET ")).count(), "served from memory: " + requests);
    }
}
