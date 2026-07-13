package com.redkite.core.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

public record MetadataResult(
        String scanId,
        long componentId,
        MetadataType metadataType,
        String provider,
        String currentVersion,
        String latestVersion,
        String latestSameMajorVersion,
        List<String> upgradePathVersions,
        /** Every known stable version, ascending — including versions below currentVersion,
         *  which upgradePathVersions omits. Lets the version-selector dropdown always offer a
         *  manual downgrade choice, even when no automated recommendation suggests one. */
        List<String> allStableVersions,
        boolean complete,
        MetadataStatus status,
        CacheState cacheState,
        Instant lastSuccessfulCheckAt,
        Instant cacheExpiryAt,
        Instant attemptedRefreshAt,
        Instant suggestedRetryAt,
        String message) implements Serializable {
}
