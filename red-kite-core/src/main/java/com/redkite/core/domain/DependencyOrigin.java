package com.redkite.core.domain;

/**
 * How a dependency entered the resolved graph — independent of what controls its version
 * ({@link VersionController}) and independent of why it needs attention
 * ({@link DependencyFindingReason}). "Direct" and "transitive" are values of this axis, not
 * top-level categories the rest of the analysis should be organized around.
 *
 * <p>{@link #IMPORTED_BOM}, {@link #PLATFORM}, and {@link #PROFILE_DERIVED} are reserved for a
 * later stage: today's scanner does not parse BOM imports or activate/track profiles, so
 * {@link com.redkite.core.service.DependencyOriginClassifier} never produces them yet.
 */
public enum DependencyOrigin {
    DIRECT,
    TRANSITIVE,
    PLUGIN,
    PARENT,
    IMPORTED_BOM,
    PLATFORM,
    PROFILE_DERIVED
}
