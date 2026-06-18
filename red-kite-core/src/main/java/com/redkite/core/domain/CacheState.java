package com.redkite.core.domain;

public enum CacheState {
    FRESH,
    STALE,
    MISSING,
    NEGATIVE_FRESH,
    NEGATIVE_STALE,
    ERROR_CACHED
}
