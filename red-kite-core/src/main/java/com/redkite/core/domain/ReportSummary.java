package com.redkite.core.domain;

import java.util.List;
import java.util.Map;

public record ReportSummary(
        int totalComponents,
        int needsRemediation,
        int clean,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount,
        int unknownCount,
        int snapshotCount,
        int declaredVersionWarningCount,
        int staleMetadataCount,
        int recommendationCount,
        Map<AdvisorySeverity, List<String>> dependenciesBySeverity,
        Map<RemediationReason, List<String>> dependenciesByReason) {
}
