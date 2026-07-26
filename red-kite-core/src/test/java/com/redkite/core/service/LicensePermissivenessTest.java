package com.redkite.core.service;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class LicensePermissivenessTest {

    private static final Map<String, Integer> RANKS = Map.of(
            "MIT", 0,
            "ASL-2.0", 1,
            "GPL-2.0-only", 2
    );

    @Test
    void picksTheLowerRankedOfTwoRankedLicenses() {
        assertEquals("The MIT License", LicensePermissiveness.mostPermissive(
                List.of("The MIT License", "GPL v2"), RANKS));
    }

    @Test
    void orderOfTheInputListDoesNotMatter() {
        assertEquals("MIT", LicensePermissiveness.mostPermissive(
                List.of("GPL v2", "Apache-2.0", "MIT"), RANKS));
    }

    @Test
    void aSingleRankedLicenseIsStillReturned() {
        assertEquals("MIT", LicensePermissiveness.mostPermissive(List.of("MIT"), RANKS));
    }

    @Test
    void aSingleUnrankedLicenseReturnsNull() {
        assertNull(LicensePermissiveness.mostPermissive(List.of("Bouncy Castle Licence"), RANKS));
    }

    @Test
    void emptyOrNullListReturnsNull() {
        assertNull(LicensePermissiveness.mostPermissive(List.of(), RANKS));
        assertNull(LicensePermissiveness.mostPermissive(null, RANKS));
    }

    @Test
    void unrankedLicensesAreNeverPickedEvenWhenNothingElseIsRanked() {
        assertNull(LicensePermissiveness.mostPermissive(
                List.of("Bouncy Castle Licence", "CDDL/GPLv2+CE"), RANKS));
    }

    @Test
    void aRankedLicenseIsPickedOverAnUnrankedOne() {
        assertEquals("MIT", LicensePermissiveness.mostPermissive(
                List.of("Bouncy Castle Licence", "MIT"), RANKS));
    }

    @Test
    void nullRankMapMeansNothingIsPicked() {
        assertNull(LicensePermissiveness.mostPermissive(List.of("MIT", "GPL v2"), null));
    }
}
