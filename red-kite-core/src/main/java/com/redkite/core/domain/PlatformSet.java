package com.redkite.core.domain;

import java.util.List;

/**
 * Independently versioned artifacts selected and tested together by a platform BOM or parent
 * (e.g. the Spring Boot BOM managing Logback, Jackson, Netty, Tomcat, Hibernate, Micrometer, and
 * many other unrelated release families). Never treat a platform's whole managed set as one
 * {@link ReleaseFamily} — the platform provides a tested combination of independent projects, not
 * a single upstream release.
 *
 * <p>Reserved for the provenance stage: nothing populates this yet, since detecting a platform
 * requires resolving imported-BOM/parent membership, which {@link VersionController} can't do
 * today either.
 */
public record PlatformSet(
        String platformCoordinate,
        List<ComponentCoordinate> members,
        RelationshipSource source,
        GroupingConfidence confidence) {
}
