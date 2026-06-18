package com.redkite.core.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

public record MetadataResult(
        long scanId,
        long componentId,
        MetadataType metadataType,
        String provider,
        String currentVersion,
        String latestVersion,
        String latestSameMajorVersion,
        List<String> upgradePathVersions,
        boolean complete,
        MetadataStatus status,
        CacheState cacheState,
        Instant lastSuccessfulCheckAt,
        Instant cacheExpiryAt,
        Instant attemptedRefreshAt,
        Instant suggestedRetryAt,
        String message) implements Serializable {
}
