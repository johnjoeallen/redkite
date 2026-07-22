package com.redkite.core.domain;

/** Distinguishes the different, non-interchangeable ways artifacts can be related — deliberately
 *  not a single generic "group" concept, since conflating them produces wrong actions (e.g.
 *  numerically aligning a {@link #COMPATIBILITY} relationship, or treating a {@link #PLATFORM}'s
 *  entire managed set as one {@link #RELEASE_FAMILY}). */
public enum RelationshipType {
    /** Dependencies whose version moves together because they share one local, editable
     *  declaration (a property, a dependencyManagement entry, a BOM/parent import version). */
    CONTROL_SET,
    /** Artifacts genuinely published as part of the same upstream project/release. */
    RELEASE_FAMILY,
    /** Artifacts that must remain compatible with each other but are not expected to share a
     *  version number. */
    COMPATIBILITY,
    /** Independently versioned artifacts selected and tested together by a platform BOM/parent. */
    PLATFORM,
    /** The concrete dependency movements caused by one proposed update — computed from an update
     *  operation, not an upstream fact. */
    PROPOSED_CHANGE_SET
}
