package com.redkite.core.service;

import com.redkite.core.domain.AdvisorySeverity;
import com.redkite.core.domain.VulnerabilityFinding;

import java.util.List;

public final class AdvisoryClassifier {
    private AdvisoryClassifier() {
    }

    public static AdvisorySeverity severity(VulnerabilityFinding finding) {
        if (finding == null) return AdvisorySeverity.UNKNOWN;
        return AdvisorySeverity.fromString(finding.severity());
    }

    public static AdvisorySeverity highest(List<VulnerabilityFinding> findings) {
        if (findings == null || findings.isEmpty()) return AdvisorySeverity.NONE;
        AdvisorySeverity max = AdvisorySeverity.NONE;
        for (VulnerabilityFinding f : findings) {
            max = max.max(severity(f));
        }
        return max;
    }

    public static int countBySeverity(List<VulnerabilityFinding> findings, AdvisorySeverity target) {
        if (findings == null) return 0;
        int count = 0;
        for (VulnerabilityFinding f : findings) {
            if (severity(f) == target) count++;
        }
        return count;
    }

    public static AdvisorySeverity fromCvssScore(double score) {
        return AdvisorySeverity.fromCvssScore(score);
    }
}
