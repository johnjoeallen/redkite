package com.redkite.core.service;

import com.redkite.core.domain.AdvisorySeverity;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.VulnerabilityFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AdvisoryClassifierTest {

    private static VulnerabilityFinding finding(String severity) {
        return new VulnerabilityFinding("TEST-001", severity,
                new ComponentCoordinate("com.example", "lib"), "1.0.0", null,
                true, null, List.of(), null);
    }

    @Test
    void cvssScoreMapsToNone() {
        assertEquals(AdvisorySeverity.NONE, AdvisorySeverity.fromCvssScore(0.0));
    }

    @Test
    void cvssScoreMapsToLow() {
        assertEquals(AdvisorySeverity.LOW, AdvisorySeverity.fromCvssScore(0.1));
        assertEquals(AdvisorySeverity.LOW, AdvisorySeverity.fromCvssScore(3.9));
    }

    @Test
    void cvssScoreMapsToMedium() {
        assertEquals(AdvisorySeverity.MEDIUM, AdvisorySeverity.fromCvssScore(4.0));
        assertEquals(AdvisorySeverity.MEDIUM, AdvisorySeverity.fromCvssScore(6.9));
    }

    @Test
    void cvssScoreMapsToHigh() {
        assertEquals(AdvisorySeverity.HIGH, AdvisorySeverity.fromCvssScore(7.0));
        assertEquals(AdvisorySeverity.HIGH, AdvisorySeverity.fromCvssScore(8.9));
    }

    @Test
    void cvssScoreMapsToCritical() {
        assertEquals(AdvisorySeverity.CRITICAL, AdvisorySeverity.fromCvssScore(9.0));
        assertEquals(AdvisorySeverity.CRITICAL, AdvisorySeverity.fromCvssScore(10.0));
    }

    @Test
    void unknownStringMapsToUnknown() {
        assertEquals(AdvisorySeverity.UNKNOWN, AdvisorySeverity.fromString(null));
        assertEquals(AdvisorySeverity.UNKNOWN, AdvisorySeverity.fromString(""));
        assertEquals(AdvisorySeverity.UNKNOWN, AdvisorySeverity.fromString("GARBAGE"));
    }

    @Test
    void moderateMapsToMedium() {
        assertEquals(AdvisorySeverity.MEDIUM, AdvisorySeverity.fromString("MODERATE"));
    }

    @Test
    void multipleAdvisoriesToHighestSeverity() {
        List<VulnerabilityFinding> findings = List.of(finding("LOW"), finding("HIGH"), finding("MEDIUM"));
        assertEquals(AdvisorySeverity.HIGH, AdvisoryClassifier.highest(findings));
    }

    @Test
    void criticalBeatsHighInAggregation() {
        List<VulnerabilityFinding> findings = List.of(finding("HIGH"), finding("CRITICAL"));
        assertEquals(AdvisorySeverity.CRITICAL, AdvisoryClassifier.highest(findings));
    }

    @Test
    void unknownSeverityIsPreserved() {
        assertEquals(AdvisorySeverity.UNKNOWN, AdvisoryClassifier.severity(finding("UNKNOWN")));
        assertEquals(AdvisorySeverity.UNKNOWN, AdvisoryClassifier.severity(finding(null)));
    }

    @Test
    void unknownSeverityRequiresRemediation() {
        assertTrue(AdvisorySeverity.UNKNOWN.requiresRemediation());
    }

    @Test
    void noneDoesNotRequireRemediation() {
        assertFalse(AdvisorySeverity.NONE.requiresRemediation());
    }

    @Test
    void unknownSeverityLowerThanLowInOrdering() {
        // UNKNOWN ordinal < LOW ordinal — known low beats unknown in highest-severity aggregation
        assertTrue(AdvisorySeverity.LOW.ordinal() > AdvisorySeverity.UNKNOWN.ordinal());
    }

    @Test
    void countBySeverityWorks() {
        List<VulnerabilityFinding> findings = List.of(finding("HIGH"), finding("HIGH"), finding("LOW"));
        assertEquals(2, AdvisoryClassifier.countBySeverity(findings, AdvisorySeverity.HIGH));
        assertEquals(1, AdvisoryClassifier.countBySeverity(findings, AdvisorySeverity.LOW));
        assertEquals(0, AdvisoryClassifier.countBySeverity(findings, AdvisorySeverity.CRITICAL));
    }

    @Test
    void emptyFindingsReturnNone() {
        assertEquals(AdvisorySeverity.NONE, AdvisoryClassifier.highest(List.of()));
        assertEquals(AdvisorySeverity.NONE, AdvisoryClassifier.highest(null));
    }
}
