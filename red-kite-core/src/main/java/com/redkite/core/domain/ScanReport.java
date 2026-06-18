package com.redkite.core.domain;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

public record ScanReport(
        long scanId,
        long projectId,
        boolean complete,
        String completenessMessage,
        Instant createdAt,
        List<ScanComponent> components,
        List<DependencyEdge> dependencyEdges,
        List<VulnerabilityFinding> vulnerabilityFindings,
        List<UpgradeRecommendation> recommendations,
        List<SnapshotDependencyRisk> snapshotDependencyRisks,
        List<MetadataResult> metadataResults) implements Serializable {
}
