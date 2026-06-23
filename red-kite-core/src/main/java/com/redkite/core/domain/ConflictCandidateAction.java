package com.redkite.core.domain;

import java.io.Serializable;

public record ConflictCandidateAction(
        ActionType type,
        String groupId,
        String artifactId,
        String version,
        String parentGroupId,
        String parentArtifactId
) implements Serializable {

    public enum ActionType {
        ADD_DEPENDENCY_MANAGEMENT,
        ADD_EXCLUSION
    }
}
