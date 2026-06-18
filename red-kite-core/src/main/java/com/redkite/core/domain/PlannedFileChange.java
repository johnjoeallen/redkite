package com.redkite.core.domain;

import java.io.Serializable;

public record PlannedFileChange(
        String relativeFilePath,
        String expectedSha256Before,
        ChangeType changeType,
        String groupId,
        String artifactId,
        String propertyName,
        String oldVersion,
        String newVersion,
        String reason,
        long relatedRecommendationId) implements Serializable {
}
