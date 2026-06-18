package com.redkite.core.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public record ScanInput(
        String projectName,
        String projectRootPath,
        String workingTreePath,
        String currentBranch,
        String currentHeadCommit,
        boolean workingTreeClean,
        boolean allowMajorUpgrades,
        Instant scannedAt,
        List<ScanComponent> components,
        List<DependencyEdge> dependencyEdges,
        Map<String, String> fileHashes) implements Serializable {
}
