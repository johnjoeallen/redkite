package com.redkite.core.domain;

public enum MetadataStatus {
    FRESH,
    STALE_USED,
    MISSING,
    RATE_LIMITED,
    PROVIDER_ERROR,
    OFFLINE_MISSING,
    OFFLINE_STALE_USED,
    NOT_APPLICABLE
}
