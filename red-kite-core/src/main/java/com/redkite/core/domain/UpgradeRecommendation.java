package com.redkite.core.domain;

import java.io.Serializable;
import java.util.List;

public record UpgradeRecommendation(
        long id,
        ComponentCoordinate coordinate,
        String currentVersion,
        String targetVersion,
        RecommendationReason reason,
        RiskLevel riskLevel,
        RecommendationConfidence confidence,
        List<String> fixedCves,
        List<Long> affectedComponentIds,
        PlannedFileChange plannedFileChange) implements Serializable {
}
