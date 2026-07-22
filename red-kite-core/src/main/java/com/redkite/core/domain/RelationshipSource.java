package com.redkite.core.domain;

/** Where evidence for a relationship between artifacts (a {@link ReleaseFamily}, a
 *  {@link CompatibilityRelationship}, a {@link ControlSet}) came from. Only
 *  {@link #PROJECT_DECLARATION}, {@link #PUBLISHED_BOM}, {@link #UPSTREAM_METADATA}, and
 *  {@link #CURATED_RULE} are strong enough to justify treating a relationship as real rather than
 *  a hint — see {@link GroupingConfidence}. */
public enum RelationshipSource {
    /** Deterministic: read directly off a project's own POM (e.g. a shared property). */
    PROJECT_DECLARATION,
    /** An authoritative upstream-published BOM lists the artifacts together. */
    PUBLISHED_BOM,
    /** Upstream module/reactor or SCM/release metadata ties the artifacts together. */
    UPSTREAM_METADATA,
    /** A hand-maintained RedKite rule, reviewed and curated rather than inferred. */
    CURATED_RULE,
    /** Common project metadata (shared parent/reactor) observed by RedKite itself. */
    COMMON_PROJECT_METADATA,
    /** Structural or name/group-ID inference — a weak hint only, never authoritative. */
    INFERRED
}
