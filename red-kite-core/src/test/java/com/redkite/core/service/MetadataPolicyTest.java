package com.redkite.core.service;

import com.redkite.core.domain.CacheState;
import com.redkite.core.domain.MetadataStatus;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class MetadataPolicyTest {
    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final Instant CHECKED = NOW.minus(Duration.ofHours(2));
    private static final Instant FUTURE = NOW.plusSeconds(1);
    private static final Instant PAST = NOW.minusSeconds(1);

    private static void assertFreshness(MetadataFreshness f, boolean complete, CacheState cache, MetadataStatus status, boolean stale) {
        assertEquals(new MetadataFreshness(complete, cache, status, stale), f);
    }

    @Test
    void successfulRefreshIsAlwaysFresh() {
        assertFreshness(MetadataPolicy.evaluate(NOW, null, null, true, true, true), true, CacheState.FRESH, MetadataStatus.FRESH, false);
    }

    @Test
    void nothingCachedDependsOnWhyTheRefreshFailed() {
        assertFreshness(MetadataPolicy.evaluate(NOW, null, FUTURE, false, true, true),
                false, CacheState.MISSING, MetadataStatus.OFFLINE_MISSING, false);
        assertFreshness(MetadataPolicy.evaluate(NOW, CHECKED, null, false, true, false),
                false, CacheState.MISSING, MetadataStatus.RATE_LIMITED, false);
        assertFreshness(MetadataPolicy.evaluate(NOW, null, null, false, false, false),
                false, CacheState.MISSING, MetadataStatus.PROVIDER_ERROR, false);
    }

    @Test
    void unexpiredCacheIsFreshOnlineOrOffline() {
        assertFreshness(MetadataPolicy.evaluate(NOW, CHECKED, FUTURE, false, false, false), true, CacheState.FRESH, MetadataStatus.FRESH, false);
        assertFreshness(MetadataPolicy.evaluate(NOW, CHECKED, FUTURE, false, false, true), true, CacheState.FRESH, MetadataStatus.FRESH, false);
        assertFreshness(MetadataPolicy.evaluate(NOW, CHECKED, NOW, false, false, false), true, CacheState.FRESH, MetadataStatus.FRESH, false);
    }

    @Test
    void expiredCacheIsUsedStale() {
        assertFreshness(MetadataPolicy.evaluate(NOW, CHECKED, PAST, false, true, true),
                false, CacheState.STALE, MetadataStatus.OFFLINE_STALE_USED, true);
        assertFreshness(MetadataPolicy.evaluate(NOW, CHECKED, PAST, false, true, false),
                false, CacheState.STALE, MetadataStatus.RATE_LIMITED, true);
        assertFreshness(MetadataPolicy.evaluate(NOW, CHECKED, PAST, false, false, true),
                false, CacheState.STALE, MetadataStatus.OFFLINE_STALE_USED, true);
        assertFreshness(MetadataPolicy.evaluate(NOW, CHECKED, PAST, false, false, false),
                false, CacheState.STALE, MetadataStatus.STALE_USED, true);
    }

    @Test
    void staleUntilAddsBothWindows() {
        assertNull(MetadataPolicy.staleUntil(null, Duration.ofHours(1), Duration.ofDays(1)));
        assertEquals(CHECKED.plus(Duration.ofHours(1)).plus(Duration.ofDays(1)),
                MetadataPolicy.staleUntil(CHECKED, Duration.ofHours(1), Duration.ofDays(1)));
    }
}
