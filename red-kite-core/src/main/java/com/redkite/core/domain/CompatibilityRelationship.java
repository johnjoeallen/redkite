package com.redkite.core.domain;

import java.util.List;

/**
 * Artifacts that must remain compatible with each other but are not expected to share a version
 * number (e.g. {@code logback-classic 1.5.x} requires {@code slf4j-api 2.0.x}). Linked by a
 * compatibility rule, not by equal versions — RedKite must never try to numerically align
 * members of a compatibility relationship the way it would a {@link ControlSet}.
 */
public record CompatibilityRelationship(
        String description,
        List<ComponentCoordinate> members,
        RelationshipSource source,
        GroupingConfidence confidence) {
}
