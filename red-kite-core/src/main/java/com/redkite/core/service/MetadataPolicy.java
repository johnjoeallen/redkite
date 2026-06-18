package com.redkite.core.service;

import com.redkite.core.domain.CacheState;
import com.redkite.core.domain.MetadataStatus;

import java.time.Duration;
import java.time.Instant;

public final class MetadataPolicy {
    private MetadataPolicy() {
    }

    public static MetadataFreshness evaluate(
            Instant now,
            Instant lastSuccessfulCheckAt,
            Instant cacheExpiryAt,
            boolean providerRefreshSucceeded,
            boolean providerRateLimited,
            boolean offlineMode) {
        if (providerRefreshSucceeded) {
            return new MetadataFreshness(true, CacheState.FRESH, MetadataStatus.FRESH, false);
        }
        if (lastSuccessfulCheckAt == null || cacheExpiryAt == null) {
            if (offlineMode) {
                return new MetadataFreshness(false, CacheState.MISSING, MetadataStatus.OFFLINE_MISSING, false);
            }
            if (providerRateLimited) {
                return new MetadataFreshness(false, CacheState.MISSING, MetadataStatus.RATE_LIMITED, false);
            }
            return new MetadataFreshness(false, CacheState.MISSING, MetadataStatus.PROVIDER_ERROR, false);
        }

        boolean fresh = now.isBefore(cacheExpiryAt) || now.equals(cacheExpiryAt);
        if (fresh) {
            if (offlineMode) {
                return new MetadataFreshness(true, CacheState.FRESH, MetadataStatus.FRESH, false);
            }
            return new MetadataFreshness(true, CacheState.FRESH, MetadataStatus.FRESH, false);
        }

        if (providerRateLimited) {
            if (offlineMode) {
                return new MetadataFreshness(false, CacheState.STALE, MetadataStatus.OFFLINE_STALE_USED, true);
            }
            return new MetadataFreshness(false, CacheState.STALE, MetadataStatus.RATE_LIMITED, true);
        }
        if (offlineMode) {
            return new MetadataFreshness(false, CacheState.STALE, MetadataStatus.OFFLINE_STALE_USED, true);
        }
        return new MetadataFreshness(false, CacheState.STALE, MetadataStatus.STALE_USED, true);
    }

    public static Instant staleUntil(Instant checkedAt, Duration freshnessTtl, Duration staleDisplayLimit) {
        if (checkedAt == null) {
            return null;
        }
        return checkedAt.plus(freshnessTtl).plus(staleDisplayLimit);
    }
}
