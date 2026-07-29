package com.redkite.maven;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Answers "does this exact coordinate actually exist" before RedKite recommends or applies a
 * candidate version — using {@link PomSource#fetchPom} (a POM's presence is the availability
 * proxy, the same signal {@link ManagedVersionResolver} already relies on) rather than checking
 * only the family/BOM's own version. Caches both positive and negative results, each under its
 * own TTL — mirroring {@code HttpVersionMetadataProvider}'s fresh/negative/error split by value
 * (not by sharing its DB-backed cache; this is in-memory, process-lifetime, the same tier as
 * {@link ManagedVersionResolver}'s own per-instance cache).
 */
public final class PomAvailabilityChecker {

    public enum Availability { AVAILABLE, CONFIRMED_ABSENT, UNKNOWN_ERROR }

    public record CheckResult(Availability status, String detail) {}

    static final Duration POSITIVE_TTL = Duration.ofHours(24);
    static final Duration NEGATIVE_TTL = Duration.ofHours(6);
    static final Duration ERROR_TTL = Duration.ofMinutes(15);

    private record CacheEntry(CheckResult result, Instant expiresAt) {}

    private final ConcurrentMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public CheckResult check(PomSource source, String groupId, String artifactId, String version) {
        String key = groupId + ":" + artifactId + ":" + version;
        CacheEntry cached = cache.get(key);
        Instant now = Instant.now();
        if (cached != null && now.isBefore(cached.expiresAt())) {
            return cached.result();
        }

        PomFetchResult fetched = source.fetchPom(groupId, artifactId, version);
        CheckResult result;
        if (fetched instanceof PomFetchResult.Found) {
            result = new CheckResult(Availability.AVAILABLE, null);
        } else if (fetched instanceof PomFetchResult.NotFound) {
            result = new CheckResult(Availability.CONFIRMED_ABSENT,
                    groupId + ":" + artifactId + ":" + version + " was not found in any configured repository");
        } else {
            PomFetchResult.FetchError error = (PomFetchResult.FetchError) fetched;
            result = new CheckResult(Availability.UNKNOWN_ERROR, error.repositoryUrl() + ": " + error.message());
        }

        Duration ttl = switch (result.status()) {
            case AVAILABLE -> POSITIVE_TTL;
            case CONFIRMED_ABSENT -> NEGATIVE_TTL;
            case UNKNOWN_ERROR -> ERROR_TTL;
        };
        cache.put(key, new CacheEntry(result, now.plus(ttl)));
        return result;
    }
}
