package com.redkite.core.domain;

import java.util.List;

/**
 * All the actual dependency-version movements caused by one proposed {@link CandidateUpdate} —
 * computed from that update operation, never an upstream fact the way a {@link ReleaseFamily} or
 * {@link PlatformSet} is. Includes every affected coordinate, not just the ones a user explicitly
 * selected: changing a shared property moves every member of its {@link ControlSet}, whether or
 * not each one individually needed attention.
 */
public record ProposedChangeSet(List<DependencyMovement> movements) {

    public record DependencyMovement(ComponentCoordinate coordinate, String fromVersion, String toVersion) {
    }
}
