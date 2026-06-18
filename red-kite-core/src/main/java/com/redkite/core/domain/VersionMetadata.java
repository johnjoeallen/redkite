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
        MetadataStatus status) implements Serializable {
}
