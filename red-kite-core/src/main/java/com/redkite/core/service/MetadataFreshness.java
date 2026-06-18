package com.redkite.core.service;

import com.redkite.core.domain.CacheState;
import com.redkite.core.domain.MetadataStatus;

public record MetadataFreshness(
        boolean complete,
        CacheState cacheState,
        MetadataStatus status,
        boolean staleEvidence) {
}
