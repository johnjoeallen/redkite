package com.redkite.core.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public record UpgradePlan(
        long id,
        long projectId,
        long scanId,
        List<Long> recommendationIds,
        String proposedBranchName,
        String baseBranchAtScanTime,
        String baseHeadAtScanTime,
        String expectedWorkingTreePath,
        Map<String, String> expectedFileHashes,
        List<PlannedFileChange> plannedFileChanges,
        List<String> warnings,
        List<String> metadataCompletenessNotes,
        Instant createdAt,
        PlanStatus status) implements Serializable {
}
