package com.redkite.metadata;

import com.redkite.core.domain.CacheState;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.MetadataStatus;
import com.redkite.core.domain.VersionMetadata;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Logger;

public class HttpVersionMetadataProvider implements VersionMetadataProvider {
    private static final Logger LOGGER = Logger.getLogger(HttpVersionMetadataProvider.class.getName());
    private static final java.net.http.HttpClient CLIENT = java.net.http.HttpClient.newBuilder()
            .followRedirects(java.net.http.HttpClient.Redirect.NORMAL)
            .build();
    private static final Duration FRESH_TTL = Duration.ofHours(24);
    private static final Duration LOCAL_TTL = Duration.ofHours(1);
    private static final Duration NEGATIVE_TTL = Duration.ofHours(6);
    private static final Duration ERROR_TTL = Duration.ofMinutes(15);
    private static final String MAVEN_CENTRAL_BASE = "https://repo1.maven.org/maven2";

    private final List<String> repositoryBaseUrls;
    private final Map<String, CacheEntry> cache = new LinkedHashMap<>();
    private final String username;
    private final String password;
    /** Nullable — when null, no persistent DB cache is used. */
    private final Supplier<Connection> dbConnectionFactory;

    public HttpVersionMetadataProvider(String baseUrl) {
        this(baseUrl, null, null, null);
    }

    public HttpVersionMetadataProvider(String baseUrl, String username, String password) {
        this(baseUrl, username, password, null);
    }

    public HttpVersionMetadataProvider(String baseUrl, String username, String password,
                                       Supplier<Connection> dbConnectionFactory) {
        this.repositoryBaseUrls = parseRepositoryBases(baseUrl);
        this.username = username;
        this.password = password;
        this.dbConnectionFactory = dbConnectionFactory;
    }

    public List<String> getRepositoryBaseUrls() {
        return repositoryBaseUrls;
    }

    /** Remove PROVIDER_ERROR and MISSING cache entries so they are re-fetched after a configuration change. */
    public synchronized void clearErrorCache() {
        cache.entrySet().removeIf(e -> {
            MetadataStatus s = e.getValue().status();
            return s == MetadataStatus.PROVIDER_ERROR || s == MetadataStatus.MISSING;
        });
        dbDeleteErrors();
    }

    /** Clear the entire version metadata cache, forcing a full re-fetch on the next scan. */
    public synchronized void clearAll() {
        cache.clear();
        dbDeleteAll();
        LOGGER.info("Version metadata cache cleared");
    }

    // ---- persistent cache helpers ----

    private boolean putCache(String cacheKey, CacheEntry entry) {
        cache.put(cacheKey, entry);
        return dbWrite(cacheKey, entry);
    }

    private CacheEntry tryLoadFromDb(String cacheKey) {
        if (dbConnectionFactory == null) return null;
        try (Connection c = dbConnectionFactory.get();
             PreparedStatement ps = c.prepareStatement(
                     "select all_versions, latest_version, source, expires_at_epoch_ms, status, complete " +
                     "from rk_version_cache where cache_key = ?")) {
            ps.setString(1, cacheKey);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                List<String> versions = csvToVersions(rs.getString("all_versions"));
                String latestVersion = rs.getString("latest_version");
                String source = rs.getString("source");
                Instant expiresAt = Instant.ofEpochMilli(rs.getLong("expires_at_epoch_ms"));
                MetadataStatus status = parseStatus(rs.getString("status"));
                boolean complete = rs.getBoolean("complete");
                return new CacheEntry(versions, latestVersion, source, expiresAt, status, complete);
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "DB version cache read failed for " + cacheKey + ": " + e.getMessage());
            return null;
        }
    }

    private boolean dbWrite(String cacheKey, CacheEntry entry) {
        if (dbConnectionFactory == null) return true;
        try (Connection c = dbConnectionFactory.get();
             PreparedStatement ps = c.prepareStatement(
                     "merge into rk_version_cache " +
                     "(cache_key, all_versions, latest_version, source, expires_at_epoch_ms, status, complete, updated_at) " +
                     "key (cache_key) " +
                     "values (?, ?, ?, ?, ?, ?, ?, current_timestamp)")) {
            ps.setString(1, cacheKey);
            ps.setString(2, versionsToCsv(entry.versions()));
            ps.setString(3, entry.latestVersion());
            ps.setString(4, entry.source());
            ps.setLong(5, entry.expiresAt().toEpochMilli());
            ps.setString(6, entry.status().name());
            ps.setBoolean(7, entry.complete());
            ps.executeUpdate();
            return true;
        } catch (Exception e) {
            LOGGER.warning(() -> "DB version cache write failed for " + cacheKey + ": " + e.getMessage());
            return false;
        }
    }

    private void dbDeleteAll() {
        if (dbConnectionFactory == null) return;
        try (Connection c = dbConnectionFactory.get();
             PreparedStatement ps = c.prepareStatement("delete from rk_version_cache")) {
            ps.executeUpdate();
        } catch (Exception e) {
            LOGGER.warning(() -> "DB version cache clear failed: " + e.getMessage());
        }
    }

    private void dbDeleteErrors() {
        if (dbConnectionFactory == null) return;
        try (Connection c = dbConnectionFactory.get();
             PreparedStatement ps = c.prepareStatement(
                     "delete from rk_version_cache where status in ('PROVIDER_ERROR', 'MISSING')")) {
            ps.executeUpdate();
        } catch (Exception e) {
            LOGGER.warning(() -> "DB version cache error-clear failed: " + e.getMessage());
        }
    }

    private static String versionsToCsv(List<String> versions) {
        return versions == null ? "" : String.join(",", versions);
    }

    private static List<String> csvToVersions(String csv) {
        List<String> result = new ArrayList<>();
        if (csv == null || csv.isBlank()) return result;
        for (String v : csv.split(",")) {
            if (!v.isBlank()) result.add(v);
        }
        return result;
    }

    private static MetadataStatus parseStatus(String s) {
        try { return MetadataStatus.valueOf(s); } catch (Exception e) { return MetadataStatus.PROVIDER_ERROR; }
    }

    @Override
    public VersionMetadata latestVersion(ComponentCoordinate coordinate) {
        return latestVersion(coordinate, null);
    }

    @Override
    public VersionMetadata latestVersion(ComponentCoordinate coordinate, String currentVersion) {
        Instant now = Instant.now();
        String cacheKey = coordinate.groupId() + ":" + coordinate.artifactId();
        CacheEntry memCached = cache.get(cacheKey);
        if (memCached == null) {
            CacheEntry dbCached = tryLoadFromDb(cacheKey);
            if (dbCached != null) {
                cache.put(cacheKey, dbCached);
                LOGGER.info(() -> "Version metadata DB cache hit for " + cacheKey + " status=" + dbCached.status() + " expires=" + dbCached.expiresAt());
                memCached = dbCached;
            }
        }
        CacheEntry cached = memCached;
        if (cached != null) {
            LOGGER.info(() -> "Version metadata cache hit for " + cacheKey + " from " + cached.source() + " status=" + cached.status() + " complete=" + cached.complete());
            if (cached.isFresh(now)) {
                return cached.toMetadata(coordinate, currentVersion, now);
            }
            LOGGER.info(() -> "Version metadata cache entry for " + cacheKey + " is stale; refreshing from repository");
        } else {
            LOGGER.info(() -> "Version metadata cache miss for " + cacheKey + "; querying configured Maven repository");
        }
        MetadataStatus lastStatus = MetadataStatus.PROVIDER_ERROR;
        for (String repositoryBaseUrl : repositoryBaseUrls) {
            // Local file: repository — read maven-metadata.xml directly from disk
            if (repositoryBaseUrl.startsWith("file:")) {
                try {
                    List<String> allVersions = readLocalMetadata(repositoryBaseUrl, coordinate);
                    if (allVersions.isEmpty()) { lastStatus = MetadataStatus.MISSING; continue; }
                    VersionMetadata result = succeedWithVersions(allVersions, repositoryBaseUrl, coordinate, currentVersion, now, cacheKey);
                    if (result != null) return result;
                } catch (Exception e) {
                    LOGGER.warning(() -> "Failed to read local Maven metadata from " + repositoryBaseUrl + ": " + e.getMessage());
                }
                lastStatus = MetadataStatus.PROVIDER_ERROR;
                continue;
            }
            boolean artif = isArtifactoryUrl(repositoryBaseUrl);
            String metadataUrl = artif
                    ? artifactoryVersionsUrl(repositoryBaseUrl, coordinate)
                    : metadataUrl(repositoryBaseUrl, coordinate);
            try {
                String accept = artif ? "application/json" : "application/xml,text/xml,*/*";
                // Always try anonymous first. Only add credentials on 401.
                java.net.http.HttpResponse<String> response = CLIENT.send(
                        java.net.http.HttpRequest.newBuilder(java.net.URI.create(metadataUrl))
                                .GET().header("Accept", accept)
                                .timeout(java.time.Duration.ofSeconds(20)).build(),
                        java.net.http.HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (response.statusCode() == 401 && username != null && !username.isBlank()) {
                    LOGGER.info(() -> "Anonymous 401; retrying with credentials — URI: " + metadataUrl);
                    String encoded = java.util.Base64.getEncoder().encodeToString(
                            (username + ":" + (password != null ? password : "")).getBytes(StandardCharsets.UTF_8));
                    response = CLIENT.send(
                            java.net.http.HttpRequest.newBuilder(java.net.URI.create(metadataUrl))
                                    .GET().header("Accept", accept)
                                    .header("Authorization", "Basic " + encoded)
                                    .timeout(java.time.Duration.ofSeconds(20)).build(),
                            java.net.http.HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                }
                int status = response.statusCode();
                if (status == 200) {
                    List<String> allVersions = artif
                            ? parseArtifactoryVersions(response.body())
                            : parseVersions(response.body());
                    if (allVersions.isEmpty()) {
                        String body = response.body();
                        LOGGER.warning(() -> "0 versions returned for "
                                + coordinate.groupId() + ":" + coordinate.artifactId()
                                + " — URI: " + metadataUrl
                                + " — body: " + (body.length() > 800 ? body.substring(0, 800) + "…" : body));
                        lastStatus = MetadataStatus.MISSING;
                        continue;
                    }
                    VersionMetadata result = succeedWithVersions(allVersions, metadataUrl, coordinate, currentVersion, now, cacheKey);
                    if (result != null) return result;
                    // Had versions but none passed the stable filter
                    int count = allVersions.size();
                    LOGGER.warning(() -> count + " versions found for "
                            + coordinate.groupId() + ":" + coordinate.artifactId()
                            + " but none are stable releases — URI: " + metadataUrl
                            + " — versions: " + allVersions.subList(0, Math.min(10, count)));
                    lastStatus = MetadataStatus.PROVIDER_ERROR;
                    continue;
                }
                if (status == 401) {
                    LOGGER.warning(() -> "401 Unauthorized" + (username != null && !username.isBlank() ? " (credentials rejected)" : " (no credentials configured)") + " — URI: " + metadataUrl);
                    lastStatus = MetadataStatus.PROVIDER_ERROR;
                    continue;
                }
                if (status == 404) {
                    LOGGER.info(() -> "404 not found — URI: " + metadataUrl);
                    lastStatus = MetadataStatus.MISSING;
                    continue;
                }
                if (status == 429) {
                    LOGGER.warning(() -> "Rate-limited — URI: " + metadataUrl);
                    VersionMetadata metadata = new VersionMetadata(
                            coordinate,
                            "unknown",
                            "unknown",
                            List.of(),
                            true,
                            now,
                            metadataUrl,
                            false,
                            CacheState.MISSING,
                            MetadataStatus.RATE_LIMITED);
                    putCache(cacheKey, CacheEntry.negative(List.of(), "unknown", metadataUrl, now.plus(NEGATIVE_TTL), MetadataStatus.RATE_LIMITED, false));
                    return metadata;
                }
                LOGGER.warning(() -> "Unexpected HTTP " + status + " — URI: " + metadataUrl);
                lastStatus = MetadataStatus.PROVIDER_ERROR;
            } catch (Exception e) {
                LOGGER.warning(() -> "Request failed — URI: " + metadataUrl + " — " + e.getMessage());
                lastStatus = MetadataStatus.PROVIDER_ERROR;
            }
        }

        String source = repositoryBaseUrls.isEmpty() ? "maven-central" : repositoryBaseUrls.get(0);
        VersionMetadata metadata = new VersionMetadata(
                coordinate,
                "unknown",
                "unknown",
                List.of(),
                true,
                now,
                source,
                false,
                CacheState.MISSING,
                lastStatus);
        if (lastStatus == MetadataStatus.MISSING) {
            putCache(cacheKey, CacheEntry.negative(List.of(), "unknown", source, now.plus(NEGATIVE_TTL), lastStatus, false));
            LOGGER.info(() -> "Stored negative Maven version cache entry for " + cacheKey + " from " + source);
        } else {
            MetadataStatus errorStatus = lastStatus;
            putCache(cacheKey, CacheEntry.error(List.of(), "unknown", source, now.plus(ERROR_TTL), errorStatus, false));
            LOGGER.info(() -> "Stored error Maven version cache entry for " + cacheKey + " from " + source + " status=" + errorStatus);
        }
        return metadata;
    }

    private VersionMetadata succeedWithVersions(List<String> allVersions, String source,
            ComponentCoordinate coordinate, String currentVersion, Instant now, String cacheKey) {
        // Only plain numeric releases are eligible as recommendation targets.
        // Timestamped snapshots, qualifiers (-alpha, -RC, etc.) are excluded here even
        // if the version comparator would rank them above the current version.
        List<String> stableVersions = allVersions.stream()
                .filter(HttpVersionMetadataProvider::isStableVersion)
                .collect(java.util.stream.Collectors.toList());
        // Fall back to all if the library publishes only non-stable versions (edge case).
        List<String> versionsForRec = stableVersions.isEmpty() ? allVersions : stableVersions;
        String latest = versionsForRec.stream().max(HttpVersionMetadataProvider::compareVersions).orElse(null);
        if (latest == null || latest.isBlank()) return null;
        String latestSameMajor = latestSameMajorVersion(versionsForRec, currentVersion, latest);
        // Dropdown retains all versions (including non-stable) for manual selection.
        List<String> upgradePathVersions = upgradePathVersions(allVersions, currentVersion);
        VersionMetadata metadata = new VersionMetadata(
                coordinate, latest, latestSameMajor, upgradePathVersions,
                !latest.contains("SNAPSHOT"), now, source, true, CacheState.FRESH, MetadataStatus.FRESH);
        // Use a short TTL for artifacts not on Maven Central (internal/local); they can change frequently.
        Duration ttl = isCentralUrl(source) || existsOnCentral(coordinate) ? FRESH_TTL : LOCAL_TTL;
        boolean persisted = putCache(cacheKey, CacheEntry.fresh(allVersions, latest, source, now.plus(ttl), MetadataStatus.FRESH, true));
        if (persisted) {
            LOGGER.info(() -> "Cached Maven version metadata for " + cacheKey + " => " + latest + " ttl=" + ttl.toHours() + "h");
        } else {
            LOGGER.warning(() -> "Retrieved Maven version metadata but failed to persist cache for " + cacheKey + " => " + latest);
        }
        return metadata;
    }

    private static List<String> readLocalMetadata(String fileUrl, ComponentCoordinate coordinate) throws Exception {
        java.net.URI base = java.net.URI.create(fileUrl);
        java.nio.file.Path metadataPath = java.nio.file.Path.of(base);
        for (String part : coordinate.groupId().split("\\.")) {
            metadataPath = metadataPath.resolve(part);
        }
        java.nio.file.Path finalPath = metadataPath.resolve(coordinate.artifactId()).resolve("maven-metadata.xml");
        if (!java.nio.file.Files.exists(finalPath)) {
            LOGGER.info(() -> "No local Maven metadata at " + finalPath);
            return List.of();
        }
        LOGGER.info(() -> "Reading local Maven metadata from " + finalPath);
        metadataPath = finalPath;
        String xml = java.nio.file.Files.readString(metadataPath, StandardCharsets.UTF_8);
        return parseVersions(xml);
    }

    private static List<String> parseRepositoryBases(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return List.of("https://repo1.maven.org/maven2");
        }
        List<String> bases = new ArrayList<>();
        for (String candidate : baseUrl.split(",")) {
            String trimmed = candidate.trim();
            if (!trimmed.isEmpty()) {
                bases.add(trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed);
            }
        }
        return bases.isEmpty() ? List.of("https://repo1.maven.org/maven2") : List.copyOf(bases);
    }

    // Matches plain numeric versions (1.2.3) plus well-known stable qualifiers
    // (.Final, .RELEASE, .GA, .SPn, .SRn) used by Hibernate, Spring, JBoss etc.
    private static final java.util.regex.Pattern STABLE_VERSION_PATTERN =
            java.util.regex.Pattern.compile(
                    "^\\d+(?:\\.\\d+){1,3}(?:[.\\-](?:Final|RELEASE|GA|SP\\d*|SR\\d*))?$",
                    java.util.regex.Pattern.CASE_INSENSITIVE);

    static boolean isStableVersion(String version) {
        if (version == null || version.isBlank()) return false;
        return STABLE_VERSION_PATTERN.matcher(version.trim()).matches();
    }

    static boolean isPreRelease(String version) {
        if (version == null || version.isBlank()) return false;
        String v = version.toLowerCase();
        return v.contains("snapshot") || v.contains("alpha") || v.contains("beta")
                || v.matches(".*[.\\-]rc\\d*([.\\-].*)?") // -RC1, .rc2
                || v.matches(".*[.\\-]m\\d+([.\\-].*)?")  // -M1, milestone
                || v.contains("milestone") || v.contains("preview") || v.contains("incubat")
                || v.matches(".*[.\\-]cr\\d*([.\\-].*)?"); // candidate release
    }

    private static String metadataUrl(String repositoryBaseUrl, ComponentCoordinate coordinate) {
        String groupPath = coordinate.groupId().replace('.', '/');
        return repositoryBaseUrl + "/" + groupPath + "/" + coordinate.artifactId() + "/maven-metadata.xml";
    }

    private static boolean isArtifactoryUrl(String url) {
        return url.toLowerCase().contains("/artifactory");
    }

    private static boolean isCentralUrl(String url) {
        return url.contains("repo1.maven.org") || url.contains("central.maven.org")
                || url.contains("repo.maven.apache.org");
    }

    /** HEAD against Maven Central; returns true if the artifact exists there. Defaults to false on error. */
    private static boolean existsOnCentral(ComponentCoordinate coordinate) {
        String url = metadataUrl(MAVEN_CENTRAL_BASE, coordinate);
        try {
            java.net.http.HttpResponse<Void> resp = CLIENT.send(
                    java.net.http.HttpRequest.newBuilder(java.net.URI.create(url))
                            .method("HEAD", java.net.http.HttpRequest.BodyPublishers.noBody())
                            .timeout(Duration.ofSeconds(10)).build(),
                    java.net.http.HttpResponse.BodyHandlers.discarding());
            return resp.statusCode() == 200;
        } catch (Exception e) {
            LOGGER.fine(() -> "Central HEAD check failed for " + coordinate.groupId() + ":" + coordinate.artifactId() + ": " + e.getMessage());
            return false;
        }
    }

    private static String artifactoryVersionsUrl(String repoUrl, ComponentCoordinate coordinate) {
        String lower = repoUrl.toLowerCase();
        int idx = lower.indexOf("/artifactory");
        String base = idx >= 0 ? repoUrl.substring(0, idx + "/artifactory".length()) : repoUrl;
        // Omit repos= so the search covers all accessible repositories — both internal
        // and external cached ones. Passing a virtual repo name (e.g. maven-all) restricts
        // results to that repo's index and misses internal artifacts not present in it.
        return base + "/api/search/versions?g=" + urlEncode(coordinate.groupId())
                + "&a=" + urlEncode(coordinate.artifactId());
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    /**
     * Parses the Artifactory /api/search/versions JSON response.
     * Response format: {"results":[{"version":"1.0.0","integration":false},...]}
     * Entries with "integration":true are SNAPSHOT/integration builds and are excluded here;
     * the downstream isStableVersion filter handles any remaining non-stable strings.
     */
    private static List<String> parseArtifactoryVersions(String json) {
        List<String> versions = new ArrayList<>();
        java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
        int i = 0;
        while (true) {
            i = json.indexOf("\"version\"", i);
            if (i < 0) break;
            // Locate the enclosing result object to check both fields regardless of field order
            int objStart = json.lastIndexOf('{', i);
            int colon = json.indexOf(':', i + 9);
            if (colon < 0) break;
            int q1 = json.indexOf('"', colon + 1);
            if (q1 < 0) break;
            int q2 = json.indexOf('"', q1 + 1);
            if (q2 < 0) break;
            String version = json.substring(q1 + 1, q2);
            int objEnd = json.indexOf('}', q2);
            boolean integration = false;
            if (objStart >= 0 && objEnd > objStart) {
                String obj = json.substring(objStart, objEnd + 1);
                integration = obj.contains("\"integration\":true") || obj.contains("\"integration\": true");
            }
            if (!version.isBlank() && !integration && seen.add(version)) {
                versions.add(version);
            }
            i = q2 + 1;
        }
        return versions;
    }

    private static List<String> parseVersions(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        Document document;
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))) {
            document = factory.newDocumentBuilder().parse(inputStream);
        }
        Element versioning = child(document.getDocumentElement(), "versioning");
        if (versioning == null) {
            return List.of();
        }
        Element versions = child(versioning, "versions");
        List<String> versionList = new ArrayList<>();
        if (versions != null) {
            NodeList nodes = versions.getElementsByTagName("version");
            for (int i = 0; i < nodes.getLength(); i++) {
                String value = nodes.item(i).getTextContent();
                if (value != null && !value.isBlank()) {
                    versionList.add(value.trim());
                }
            }
        }
        String release = text(versioning, "release");
        if (release != null && !release.isBlank() && versionList.stream().noneMatch(release.trim()::equals)) {
            versionList.add(release.trim());
        }
        String latest = text(versioning, "latest");
        if (latest != null && !latest.isBlank() && versionList.stream().noneMatch(latest.trim()::equals)) {
            versionList.add(latest.trim());
        }
        return versionList;
    }

    private static String latestSameMajorVersion(List<String> versions, String currentVersion, String fallbackLatest) {
        if (versions == null || versions.isEmpty()) {
            return fallbackLatest == null || fallbackLatest.isBlank() ? "unknown" : fallbackLatest;
        }
        if (currentVersion == null || currentVersion.isBlank()) {
            return versions.stream().max(HttpVersionMetadataProvider::compareVersions).orElse("unknown");
        }
        String family = familyKey(currentVersion);
        String latestInFamily = latestVersionForFamily(versions, family);
        if (latestInFamily != null && !latestInFamily.isBlank()) {
            return latestInFamily;
        }
        return fallbackLatest == null || fallbackLatest.isBlank() ? "unknown" : fallbackLatest;
    }

    private static String familyLabel(String version) {
        if (version == null || version.isBlank()) {
            return "unknown";
        }
        String normalized = version.trim().replace('_', '.').replace('-', '.');
        String[] parts = normalized.split("\\.");
        if (parts.length >= 2) {
            return parts[0] + "." + parts[1] + ".x";
        }
        if (parts.length == 1) {
            return parts[0] + ".x";
        }
        return "unknown";
    }

    private static String familyKey(String version) {
        if (version == null || version.isBlank()) {
            return "";
        }
        String normalized = version.trim().replace('_', '.').replace('-', '.');
        String[] parts = normalized.split("\\.");
        if (parts.length >= 2) {
            return numericPrefix(parts[0]) + "." + numericPrefix(parts[1]);
        }
        if (parts.length == 1) {
            return numericPrefix(parts[0]) + ".0";
        }
        return "";
    }

    private static String numericPrefix(String token) {
        try {
            String digits = token.replaceAll("[^0-9].*$", "");
            return digits.isBlank() ? "0" : String.valueOf(Integer.parseInt(digits));
        } catch (NumberFormatException e) {
            return "0";
        }
    }

    private static String latestVersionForFamily(List<String> versions, String family) {
        if (family == null || family.isBlank()) {
            return null;
        }
        String latest = null;
        for (String version : versions) {
            if (version == null || version.isBlank()) {
                continue;
            }
            if (family.equals(familyKey(version)) && (latest == null || compareVersions(version, latest) > 0)) {
                latest = version;
            }
        }
        return latest;
    }

    private static List<String> upgradePathVersions(List<String> versions, String currentVersion) {
        if (versions == null || versions.isEmpty()) {
            return List.of();
        }
        int currentMajor = majorNumber(currentVersion);
        Map<String, String> latestByFamily = new LinkedHashMap<>();
        for (String version : versions) {
            if (version == null || version.isBlank()) {
                continue;
            }
            int major = majorNumber(version);
            if (currentVersion != null && !currentVersion.isBlank() && major < currentMajor) {
                continue;
            }
            String family = major == currentMajor ? familyKey(version) : String.valueOf(major);
            if (family.isBlank()) {
                continue;
            }
            String existing = latestByFamily.get(family);
            if (existing == null || compareVersions(version, existing) > 0) {
                latestByFamily.put(family, version);
            }
        }
        List<String> representatives = new ArrayList<>(latestByFamily.values());
        representatives.sort(HttpVersionMetadataProvider::compareVersions);
        if (currentVersion == null || currentVersion.isBlank()) {
            return List.copyOf(representatives);
        }
        List<String> path = new ArrayList<>();
        for (String representative : representatives) {
            if (compareVersions(representative, currentVersion) > 0) {
                path.add(representative);
            }
        }
        return List.copyOf(path);
    }

    private static int majorNumber(String version) {
        if (version == null || version.isBlank()) {
            return 0;
        }
        String normalized = version.trim().replace('_', '.').replace('-', '.');
        String[] parts = normalized.split("\\.");
        if (parts.length == 0) {
            return 0;
        }
        try {
            String digits = parts[0].replaceAll("[^0-9].*$", "");
            return digits.isBlank() ? 0 : Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static int major(String version) {
        if (version == null || version.isBlank()) {
            return 0;
        }
        String normalized = version.trim().replace('_', '.').replace('-', '.');
        String[] parts = normalized.split("\\.");
        if (parts.length == 0) {
            return 0;
        }
        try {
            String digits = parts[0].replaceAll("[^0-9].*$", "");
            return digits.isBlank() ? 0 : Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static Element child(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagName(name);
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i).getParentNode() == parent) {
                return (Element) nodes.item(i);
            }
        }
        return null;
    }

    private static String text(Element parent, String name) {
        Element child = child(parent, name);
        return child == null ? null : child.getTextContent();
    }

    private record CacheEntry(List<String> versions, String latestVersion, String source, Instant expiresAt, MetadataStatus status, boolean complete) {
        static CacheEntry fresh(List<String> versions, String latestVersion, String source, Instant expiresAt, MetadataStatus status, boolean complete) {
            return new CacheEntry(List.copyOf(versions), latestVersion, source, expiresAt, status, complete);
        }

        static CacheEntry negative(List<String> versions, String latestVersion, String source, Instant expiresAt, MetadataStatus status, boolean complete) {
            return new CacheEntry(List.copyOf(versions), latestVersion, source, expiresAt, status, complete);
        }

        static CacheEntry error(List<String> versions, String latestVersion, String source, Instant expiresAt, MetadataStatus status, boolean complete) {
            return new CacheEntry(List.copyOf(versions), latestVersion, source, expiresAt, status, complete);
        }

        boolean isFresh(Instant now) {
            return now.isBefore(expiresAt) || now.equals(expiresAt);
        }

        VersionMetadata toMetadata(ComponentCoordinate coordinate, String currentVersion, Instant now) {
            // Re-apply stable filter for recommendation — cache stores all versions
            List<String> stable = versions.stream()
                    .filter(HttpVersionMetadataProvider::isStableVersion)
                    .collect(java.util.stream.Collectors.toList());
            List<String> forRec = stable.isEmpty() ? versions : stable;
            String resolvedLatest = latestVersion == null || latestVersion.isBlank() ? "unknown" : latestVersion;
            String latestSameMajor = latestSameMajorVersion(forRec, currentVersion, resolvedLatest);
            return new VersionMetadata(
                    coordinate,
                    resolvedLatest,
                    latestSameMajor,
                    upgradePathVersions(versions, currentVersion), // all versions for dropdown
                    !resolvedLatest.contains("SNAPSHOT"),
                    now,
                    source,
                    complete,
                    isFresh(now) ? CacheState.FRESH : CacheState.STALE,
                    status);
        }
    }

    private static int compareVersions(String left, String right) {
        if (Objects.equals(left, right)) {
            return 0;
        }
        List<VersionToken> leftTokens = tokenize(left);
        List<VersionToken> rightTokens = tokenize(right);
        int max = Math.max(leftTokens.size(), rightTokens.size());
        for (int i = 0; i < max; i++) {
            VersionToken leftToken = i < leftTokens.size() ? leftTokens.get(i) : VersionToken.zero();
            VersionToken rightToken = i < rightTokens.size() ? rightTokens.get(i) : VersionToken.zero();
            int result = leftToken.compareTo(rightToken);
            if (result != 0) {
                return result;
            }
        }
        return 0;
    }

    private static List<VersionToken> tokenize(String version) {
        if (version == null || version.isBlank()) {
            return List.of(VersionToken.zero());
        }
        List<VersionToken> tokens = new ArrayList<>();
        for (String part : version.trim().replace('_', '.').split("[.-]")) {
            if (part.isBlank()) {
                continue;
            }
            tokens.add(VersionToken.from(part));
        }
        return tokens.isEmpty() ? List.of(VersionToken.zero()) : tokens;
    }

    private record VersionToken(boolean numeric, long number, String text) implements Comparable<VersionToken> {
        static VersionToken zero() {
            return new VersionToken(true, 0L, "0");
        }

        static VersionToken from(String value) {
            if (value.chars().allMatch(Character::isDigit)) {
                try {
                    return new VersionToken(true, Long.parseLong(value), value);
                } catch (NumberFormatException e) {
                    return new VersionToken(false, 0L, value);
                }
            }
            return new VersionToken(false, 0L, value.toLowerCase());
        }

        @Override
        public int compareTo(VersionToken other) {
            if (numeric && other.numeric) {
                return Long.compare(number, other.number);
            }
            if (numeric) {
                return 1;
            }
            if (other.numeric) {
                return -1;
            }
            return text.compareTo(other.text);
        }
    }
}
