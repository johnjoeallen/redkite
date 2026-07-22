package com.redkite.core.service;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.GroupingConfidence;
import com.redkite.core.domain.RelationshipSource;
import com.redkite.core.domain.ReleaseFamily;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A small, hand-maintained table of artifacts known to genuinely belong to the same upstream
 * release family — curated evidence ({@link RelationshipSource#CURATED_RULE}), never inferred
 * from a shared property, a matching version, similar names, or a shared group ID. Entries here
 * are reviewed by RedKite maintainers against the upstream project's own module/release
 * structure, not derived automatically.
 *
 * <p>This is deliberately a seed, not a solution: real coverage needs a durable source (an
 * authoritative published-BOM index, or upstream module/SCM metadata) rather than an
 * ever-growing hand-written list. See the design notes' "release-family and compatibility
 * relationships" section for the intended follow-up.
 */
public final class ReleaseFamilyRegistry {
    private ReleaseFamilyRegistry() {
    }

    private static final List<ReleaseFamily> FAMILIES = List.of(
            new ReleaseFamily("Logback", List.of(
                    new ComponentCoordinate("ch.qos.logback", "logback-core"),
                    new ComponentCoordinate("ch.qos.logback", "logback-classic")),
                    RelationshipSource.CURATED_RULE, GroupingConfidence.HIGH),
            new ReleaseFamily("Jackson core", List.of(
                    new ComponentCoordinate("com.fasterxml.jackson.core", "jackson-core"),
                    new ComponentCoordinate("com.fasterxml.jackson.core", "jackson-databind"),
                    new ComponentCoordinate("com.fasterxml.jackson.core", "jackson-annotations")),
                    RelationshipSource.CURATED_RULE, GroupingConfidence.HIGH)
    );

    private static final Map<ComponentCoordinate, ReleaseFamily> BY_COORDINATE = index();

    private static Map<ComponentCoordinate, ReleaseFamily> index() {
        Map<ComponentCoordinate, ReleaseFamily> map = new LinkedHashMap<>();
        for (ReleaseFamily family : FAMILIES) {
            for (ComponentCoordinate member : family.members()) {
                map.put(member, family);
            }
        }
        return Map.copyOf(map);
    }

    public static Optional<ReleaseFamily> familyOf(ComponentCoordinate coordinate) {
        return Optional.ofNullable(BY_COORDINATE.get(coordinate));
    }
}
