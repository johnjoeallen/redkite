package com.redkite.server;

import com.redkite.core.domain.*;
import java.util.List;

// ---- Stage 6: Remediation-first single-column view ----

record ComponentView(
        ScanComponent component,
        RemediationStatus status,
        MetadataResult versionMetadata,
        UpgradeRecommendation recommendation,
        List<VulnerabilityFinding> findings,
        boolean canUpgradeViaDirect,
        TransitiveConflictFinding convergenceFinding,
        List<String> licenses,
        ChildVulnerabilityCounts childVulnerabilities) {}
