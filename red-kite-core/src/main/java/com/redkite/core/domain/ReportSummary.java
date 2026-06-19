package com.redkite.core.domain;

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
        int directVersionWarningCount,
        int staleMetadataCount) {
}
