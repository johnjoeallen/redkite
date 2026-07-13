package com.redkite.core.domain;

public enum RecommendationReason {
    /** A CVE is resolved by upgrading to a newer version. */
    CVE_FIX,
    /** No upgrade resolves the CVE, but downgrading to an older, pre-introduction version does. */
    CVE_FIX_DOWNGRADE,
    /** Neither an upgrade nor a downgrade fully resolves the CVE; this is the best available
     *  version (lowest residual severity, ties broken toward the highest version). */
    CVE_BEST_EFFORT,
    PATCH_AVAILABLE,
    MINOR_AVAILABLE,
    MAJOR_AVAILABLE,
    SNAPSHOT_REPLACEMENT
}
