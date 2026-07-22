package com.redkite.core.domain;

import java.util.List;

/**
 * Dependencies affected by changing one local, editable declaration — a property, a
 * {@code dependencyManagement} entry, a BOM/parent import version. Deterministic and
 * project-specific: unlike {@link ReleaseFamily}, a control set is never inferred, so it always
 * carries {@link RelationshipSource#PROJECT_DECLARATION} and
 * {@link GroupingConfidence#AUTHORITATIVE}.
 *
 * <p>A control set is proof only that changing {@code controllerDescription} moves every member
 * together — never proof that the members are genuinely related upstream. See
 * {@link com.redkite.core.service.ControlSetAnalyzer}.
 */
public record ControlSet(
        String controllerDescription,
        List<ComponentCoordinate> members) {
}
