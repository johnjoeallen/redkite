package com.redkite.core.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AdvisorySeverityTest {
    @Test
    void fromCvssScoreUsesTheStandardBands() {
        assertEquals(AdvisorySeverity.NONE, AdvisorySeverity.fromCvssScore(0.0));
        assertEquals(AdvisorySeverity.LOW, AdvisorySeverity.fromCvssScore(0.1));
        assertEquals(AdvisorySeverity.LOW, AdvisorySeverity.fromCvssScore(3.9));
        assertEquals(AdvisorySeverity.MEDIUM, AdvisorySeverity.fromCvssScore(4.0));
        assertEquals(AdvisorySeverity.MEDIUM, AdvisorySeverity.fromCvssScore(6.9));
        assertEquals(AdvisorySeverity.HIGH, AdvisorySeverity.fromCvssScore(7.0));
        assertEquals(AdvisorySeverity.HIGH, AdvisorySeverity.fromCvssScore(8.9));
        assertEquals(AdvisorySeverity.CRITICAL, AdvisorySeverity.fromCvssScore(9.0));
        assertEquals(AdvisorySeverity.CRITICAL, AdvisorySeverity.fromCvssScore(10.0));
    }

    @Test
    void fromStringAcceptsOsvAndGhsaLabels() {
        assertEquals(AdvisorySeverity.CRITICAL, AdvisorySeverity.fromString(" critical "));
        assertEquals(AdvisorySeverity.HIGH, AdvisorySeverity.fromString("HIGH"));
        assertEquals(AdvisorySeverity.MEDIUM, AdvisorySeverity.fromString("medium"));
        assertEquals(AdvisorySeverity.MEDIUM, AdvisorySeverity.fromString("MODERATE"));
        assertEquals(AdvisorySeverity.LOW, AdvisorySeverity.fromString("low"));
        assertEquals(AdvisorySeverity.NONE, AdvisorySeverity.fromString("none"));
        assertEquals(AdvisorySeverity.NONE, AdvisorySeverity.fromString("Informational"));
        assertEquals(AdvisorySeverity.UNKNOWN, AdvisorySeverity.fromString("severe"));
        assertEquals(AdvisorySeverity.UNKNOWN, AdvisorySeverity.fromString(" "));
        assertEquals(AdvisorySeverity.UNKNOWN, AdvisorySeverity.fromString(null));
    }

    @Test
    void maxPicksTheMoreSevere() {
        assertEquals(AdvisorySeverity.HIGH, AdvisorySeverity.LOW.max(AdvisorySeverity.HIGH));
        assertEquals(AdvisorySeverity.HIGH, AdvisorySeverity.HIGH.max(AdvisorySeverity.LOW));
        assertEquals(AdvisorySeverity.MEDIUM, AdvisorySeverity.MEDIUM.max(AdvisorySeverity.MEDIUM));
    }

    @Test
    void everythingButNoneNeedsRemediation() {
        assertFalse(AdvisorySeverity.NONE.requiresRemediation());
        assertTrue(AdvisorySeverity.UNKNOWN.requiresRemediation());
        assertTrue(AdvisorySeverity.LOW.requiresRemediation());
    }

    @Test
    void labelsAndIcons() {
        String[][] expected = {
                {"NONE", "None", "✓"}, {"UNKNOWN", "Unknown", "?"}, {"LOW", "Low", "ℹ"},
                {"MEDIUM", "Medium", "⚠"}, {"HIGH", "High", "☠"}, {"CRITICAL", "Critical", "☢"}};
        for (String[] row : expected) {
            AdvisorySeverity s = AdvisorySeverity.valueOf(row[0]);
            assertEquals(row[1], s.label());
            assertEquals(row[2], s.icon());
        }
    }
}
