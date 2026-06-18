package com.redkite.core.domain;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

public record PlanCreationRequest(
        long scanId,
        List<Long> recommendationIds,
        Map<Long, String> targetVersions,
        String proposedBranchName,
        String baseBranchAtScanTime,
        String baseHeadAtScanTime,
        String expectedWorkingTreePath) implements Serializable {
}
