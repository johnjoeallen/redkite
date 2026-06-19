package com.redkite.core.domain;

import java.util.List;

public record RemediationStatus(
        long componentId,
        boolean needsRemediation,
        boolean isSnapshot,
        boolean hasDirectVersionDeclaration,
        boolean hasVulnerability,
        boolean hasUpgradeRecommendation,
        boolean hasStaleMetadata,
        AdvisorySeverity highestSeverity,
        int vulnerabilityCount,
        List<String> reasons) {
}
