package com.redkite.core.service;

import com.redkite.core.domain.PlannedFileChange;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class PlanSafetyChecker {
    private PlanSafetyChecker() {
    }

    public static List<String> validate(Path repoRoot,
                                        String expectedBranch,
                                        String currentBranch,
                                        String expectedHead,
                                        String currentHead,
                                        boolean workingTreeClean,
                                        Map<String, String> expectedFileHashes,
                                        Map<String, String> currentFileHashes,
                                        List<PlannedFileChange> changes) {
        List<String> problems = new ArrayList<>();
        if (repoRoot == null || !repoRoot.toFile().exists()) {
            problems.add("repository path does not exist");
        }
        if (!expectedBranch.equals(currentBranch)) {
            problems.add("branch changed from scan time");
        }
        if (!expectedHead.equals(currentHead)) {
            problems.add("HEAD changed from scan time");
        }
        if (!workingTreeClean) {
            problems.add("working tree is not clean");
        }
        for (PlannedFileChange change : changes) {
            String expected = expectedFileHashes.get(change.relativeFilePath());
            String current = currentFileHashes.get(change.relativeFilePath());
            if (expected != null && current != null && !expected.equals(current)) {
                problems.add("file hash changed for " + change.relativeFilePath());
            }
        }
        return problems;
    }
}
