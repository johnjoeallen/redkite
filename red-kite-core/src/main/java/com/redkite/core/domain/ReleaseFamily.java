package com.redkite.core.domain;

import java.util.List;

/**
 * Artifacts genuinely published as part of the same upstream project or release family (e.g.
 * {@code logback-core} and {@code logback-classic}). Evidence must come from a stronger source
 * than a shared property, a matching version, similar names, or a shared group ID — see
 * {@link RelationshipSource}. Those weak signals may seed a {@link GroupingConfidence#LOW} or
 * {@link GroupingConfidence#SUGGESTED} guess for review, never an
 * {@link GroupingConfidence#AUTHORITATIVE} or {@link GroupingConfidence#HIGH} one.
 */
public record ReleaseFamily(
        String name,
        List<ComponentCoordinate> members,
        RelationshipSource source,
        GroupingConfidence confidence) {
}
