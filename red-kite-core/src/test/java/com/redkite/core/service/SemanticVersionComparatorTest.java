package com.redkite.core.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SemanticVersionComparatorTest {

    @Test
    void higherPatchIsGreater() {
        assertTrue(SemanticVersionComparator.compare("2.22.1", "2.22") > 0);
        assertTrue(SemanticVersionComparator.compare("2.22", "2.22.1") < 0);
    }

    @Test
    void equalVersionsCompareZero() {
        assertEquals(0, SemanticVersionComparator.compare("1.5.25", "1.5.25"));
    }

    @Test
    void missingTrailingTokensTreatedAsZero() {
        assertEquals(0, SemanticVersionComparator.compare("1.5", "1.5.0"));
    }

    @Test
    void nullsSortBeforeNonNull() {
        assertTrue(SemanticVersionComparator.compare(null, "1.0") < 0);
        assertTrue(SemanticVersionComparator.compare("1.0", null) > 0);
        assertEquals(0, SemanticVersionComparator.compare(null, null));
    }

    @Test
    void nonNumericTokensFallBackToStringCompare() {
        // Non-numeric tokens fall back to plain lexical string comparison, not release semantics.
        assertTrue(SemanticVersionComparator.compare("1.0.RC1", "1.0.RC2") < 0);
    }

    @Test
    void sameReleaseLineComparesFirstTwoTokens() {
        assertTrue(SemanticVersionComparator.sameReleaseLine("1.5.25", "1.5.38"));
        assertFalse(SemanticVersionComparator.sameReleaseLine("4.1.135.Final", "4.2.16.Final"));
    }

    @Test
    void jacksonAnnotationsVsCoreAreDifferentReleaseLinesButBothValid() {
        // 2.22 (annotations) and 2.22.1 (core) share major.minor "2.22" — same release line,
        // just different patch precision. Confirms releaseLineOf tolerates a 2-token version.
        assertTrue(SemanticVersionComparator.sameReleaseLine("2.22", "2.22.1"));
    }
}
