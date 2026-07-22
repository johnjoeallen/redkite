package com.redkite.core.domain;

/** Why a dependency needs attention. A dependency may carry more than one — see
 *  {@link DependencyFinding}. Not itself an update: several findings can resolve to one
 *  {@link UpdateAction}, and one finding can have several candidate actions. */
public enum DependencyFindingReason {
    CVE,
    VERSION_CONFLICT,
    POLICY_VIOLATION,
    COMPATIBILITY,
    OUTDATED,
    UNMANAGED,
    REDUNDANT_OVERRIDE,
    CLEANUP_OPPORTUNITY,
    INVALID_ALIGNMENT,
    PINNED_BLOCKING_REMEDIATION,
    /** A single project-declared property (a {@link com.redkite.core.domain.ControlSet}'s
     *  controller) affects declarations that belong to more than one distinct
     *  {@link ReleaseFamily} — changing it may move unrelated artifacts together or produce an
     *  unavailable/incompatible combination. See
     *  {@link com.redkite.core.service.ControlSetAnalyzer}. */
    MULTI_FAMILY_PROPERTY
}
