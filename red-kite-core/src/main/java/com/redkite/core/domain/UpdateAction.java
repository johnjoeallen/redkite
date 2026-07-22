package com.redkite.core.domain;

/**
 * A concrete kind of dependency <em>update</em> RedKite can propose — the generalization of
 * "upgrade" that this action replaces as a top-level concept. An upgrade is one of these
 * ({@link #UPGRADE}), not the whole idea: a proposed change might just as validly be a downgrade,
 * a no-op, or the removal of something RedKite itself once added.
 *
 * <p>{@link RecommendationReason} and {@link ConflictCandidateAction.ActionType} predate this
 * enum and remain in place — see the migration notes for how they map onto it. This is additive
 * vocabulary for the update-plan model, not a replacement for either yet.
 */
public enum UpdateAction {
    UPGRADE,
    DOWNGRADE,
    ALIGN_RELEASE_FAMILY,
    UPDATE_PARENT,
    UPDATE_BOM,
    CHANGE_PROPERTY,
    ADD_DEPENDENCY_MANAGEMENT_OVERRIDE,
    REMOVE_DEPENDENCY_MANAGEMENT_OVERRIDE,
    ADD_DIRECT_DEPENDENCY,
    REMOVE_DIRECT_DEPENDENCY,
    REPLACE_DEPENDENCY,
    SPLIT_PROPERTY,
    MERGE_DUPLICATE_VERSION_DECLARATIONS,
    REMOVE_UNUSED_DEPENDENCY,
    NO_CHANGE,
    IGNORE,
    PIN_TEMPORARILY
}
