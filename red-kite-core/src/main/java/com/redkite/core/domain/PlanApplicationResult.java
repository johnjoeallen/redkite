package com.redkite.core.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

public record PlanApplicationResult(
        long planId,
        String status,
        String message,
        String branchName,
        List<String> changedFiles,
        Instant appliedAt) implements Serializable {
}
