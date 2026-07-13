package com.redkite.core.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

public record VersionMetadata(
        ComponentCoordinate coordinate,
        String latestVersion,
        String latestSameMajorVersion,
        List<String> upgradePathVersions,
        boolean release,
        Instant checkedAt,
        String source,
        boolean complete,
        CacheState cacheState,
        MetadataStatus status,
        /** Every known stable version, ascending — including versions below the currently
         *  scanned version, which {@link #upgradePathVersions} omits. Used to search for a
         *  downgrade that resolves a CVE with no available upgrade fix. */
        List<String> allStableVersions) implements Serializable {
}
