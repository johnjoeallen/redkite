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
import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Map;
import java.util.logging.Logger;

public class HttpVersionMetadataProvider implements VersionMetadataProvider {
    private static final Logger LOGGER = Logger.getLogger(HttpVersionMetadataProvider.class.getName());
    private static final java.net.http.HttpClient CLIENT = java.net.http.HttpClient.newBuilder()
            .followRedirects(java.net.http.HttpClient.Redirect.NORMAL)
            .build();
    private static final Duration FRESH_TTL = Duration.ofHours(24);
    private static final Duration NEGATIVE_TTL = Duration.ofHours(6);
    private static final Duration ERROR_TTL = Duration.ofMinutes(15);

    private final List<String> repositoryBaseUrls;
    private final Map<String, CacheEntry> cache = new LinkedHashMap<>();

    public HttpVersionMetadataProvider(String baseUrl) {
        this.repositoryBaseUrls = parseRepositoryBases(baseUrl);
    }

    @Override
    public VersionMetadata latestVersion(ComponentCoordinate coordinate) {
        return latestVersion(coordinate, null);
    }

    @Override
    public VersionMetadata latestVersion(ComponentCoordinate coordinate, String currentVersion) {
        Instant now = Instant.now();
        String cacheKey = coordinate.groupId() + ":" + coordinate.artifactId();
        CacheEntry cached = cache.get(cacheKey);
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
            String metadataUrl = metadataUrl(repositoryBaseUrl, coordinate);
            LOGGER.info(() -> "Querying Maven repository for version metadata: " + metadataUrl);
            try {
                java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder(java.net.URI.create(metadataUrl))
                        .GET()
                        .header("Accept", "application/xml,text/xml,*/*")
                        .timeout(java.time.Duration.ofSeconds(20))
                        .build();
                java.net.http.HttpResponse<String> response = CLIENT.send(request, java.net.http.HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                int status = response.statusCode();
                LOGGER.info(() -> "Maven repository response for " + metadataUrl + " => HTTP " + status);
                if (status == 200) {
                    List<String> versions = parseVersions(response.body());
                    String latest = versions.stream().max(HttpVersionMetadataProvider::compareVersions).orElse(null);
                    if (latest == null || latest.isBlank()) {
                        lastStatus = MetadataStatus.PROVIDER_ERROR;
                        LOGGER.warning(() -> "Maven metadata at " + metadataUrl + " did not contain a usable latest/release version");
                        continue;
                    }
                    List<String> upgradePathVersions = upgradePathVersions(versions, currentVersion);
                    String latestSameMajor = latestSameMajorVersion(versions, currentVersion, latest);
                    VersionMetadata metadata = new VersionMetadata(
                            coordinate,
                            latest,
                            latestSameMajor,
                            upgradePathVersions,
                            !latest.contains("SNAPSHOT"),
                            now,
                            metadataUrl,
                            true,
                            CacheState.FRESH,
                            MetadataStatus.FRESH);
                    cache.put(cacheKey, CacheEntry.fresh(versions, latest, metadataUrl, now.plus(FRESH_TTL), MetadataStatus.FRESH, true));
                    LOGGER.info(() -> "Cached Maven version metadata for " + cacheKey + " => " + latest);
                    return metadata;
                }
                if (status == 404) {
                    lastStatus = MetadataStatus.MISSING;
                    continue;
                }
                if (status == 429) {
                    LOGGER.warning(() -> "Maven metadata request rate-limited by " + metadataUrl);
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
                    cache.put(cacheKey, CacheEntry.negative(List.of(), "unknown", metadataUrl, now.plus(NEGATIVE_TTL), MetadataStatus.RATE_LIMITED, false));
                    return metadata;
                }
                lastStatus = MetadataStatus.PROVIDER_ERROR;
            } catch (Exception e) {
                LOGGER.warning(() -> "Maven metadata fetch failed for " + metadataUrl + ": " + e.getMessage());
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
            cache.put(cacheKey, CacheEntry.negative(List.of(), "unknown", source, now.plus(NEGATIVE_TTL), lastStatus, false));
            LOGGER.info(() -> "Stored negative Maven version cache entry for " + cacheKey + " from " + source);
        } else {
            MetadataStatus errorStatus = lastStatus;
            cache.put(cacheKey, CacheEntry.error(List.of(), "unknown", source, now.plus(ERROR_TTL), errorStatus, false));
            LOGGER.info(() -> "Stored error Maven version cache entry for " + cacheKey + " from " + source + " status=" + errorStatus);
        }
        return metadata;
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

    private static String metadataUrl(String repositoryBaseUrl, ComponentCoordinate coordinate) {
        String groupPath = coordinate.groupId().replace('.', '/');
        return repositoryBaseUrl + "/" + groupPath + "/" + coordinate.artifactId() + "/maven-metadata.xml";
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
            String latestSameMajor = latestSameMajorVersion(versions, currentVersion, latestVersion);
            String resolvedLatest = latestVersion == null || latestVersion.isBlank() ? "unknown" : latestVersion;
            return new VersionMetadata(
                    coordinate,
                    resolvedLatest,
                    latestSameMajor,
                    upgradePathVersions(versions, currentVersion),
                    resolvedLatest.contains("SNAPSHOT") ? false : true,
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
