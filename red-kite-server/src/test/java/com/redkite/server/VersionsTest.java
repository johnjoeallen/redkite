package com.redkite.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Version classification helpers. */
class VersionsTest {
    @Test
    void preReleaseAndLookback() {
        for (String v : List.of("1-SNAPSHOT", "1-alpha", "1.0-beta", "1.0-RC2", "1.0.rc", "2-M1", "2-milestone", "1-preview", "1-incubating", "1-CR1"))
            assertTrue(Versions.isPreRelease(v), v);
        for (String v : List.of("1.0", "1.0-Final", "", " "))
            assertFalse(Versions.isPreRelease(v), v);
        assertFalse(Versions.isPreRelease(null));

        assertEquals(10, Versions.versionLookbackLimit());
        System.setProperty("redkite.version.lookback", "3");
        try {
            assertEquals(3, Versions.versionLookbackLimit());
            System.setProperty("redkite.version.lookback", "many");
            assertEquals(10, Versions.versionLookbackLimit());
        } finally {
            System.clearProperty("redkite.version.lookback");
        }
    }

    @Test
    void releaseLineMajorAndMinorComparisons() {
        assertTrue(Versions.sameReleaseLine("1.5.2", "1.5.9"));
        assertFalse(Versions.sameReleaseLine("1.5.2", "1.6.0"));

        assertTrue(Versions.sameMajorMinor("1.2.3", "1.2.9"));
        assertTrue(Versions.sameMajorMinor("1.2", "1.2"));
        assertFalse(Versions.sameMajorMinor("1.2", "1.3"));
        assertFalse(Versions.sameMajorMinor("1.2", "2.2"));
        assertFalse(Versions.sameMajorMinor("1", "1"));
        assertFalse(Versions.sameMajorMinor(null, "1.2"));
        assertFalse(Versions.sameMajorMinor("1.2", null));

        assertTrue(Versions.sameMajor("1", "1"));
        assertTrue(Versions.sameMajor("2.0", "2-rc1"));
        assertFalse(Versions.sameMajor("1.0", "2.0"));
        assertFalse(Versions.sameMajor("-1", "-2"));
        assertFalse(Versions.sameMajor(null, "1"));
        assertFalse(Versions.sameMajor("1", null));

        assertEquals(5, Versions.minor("1.5.2"));
        assertEquals(0, Versions.minor("1"));
        assertEquals(3, Versions.major("3_1"));
        assertTrue(Versions.isMajorUpgrade("1.9", "2.0"));
        assertFalse(Versions.isMajorUpgrade("2.0", "2.9"));
    }

    @Test
    void compareVersionsPadsTheShorterVersionWithZeros() {
        assertEquals(-1, Versions.compareVersions("1", "1.2"));
        assertEquals(1, Versions.compareVersions("1.2", "1"));
        assertEquals(0, Versions.compareVersions("1", "1.0"));
        assertEquals(0, Versions.compareVersions("1.0", "1"));
        assertEquals(-1, Versions.compareVersions(null, "1"));
        assertEquals(1, Versions.compareVersions("1.0-2", "1.0.1"));
        assertEquals(0, Versions.compareVersions(" ", "0"));
        assertEquals(0, Versions.compareVersions("1.a", "1.0"), "a non-numeric part counts as 0");
        assertEquals(0, Versions.major(null));
        assertEquals(0, Versions.major("x1"));
    }

    @Test
    void findMatchingConflictPrefersTheOneForTheCurrentVersion() {
        com.redkite.core.domain.TransitiveConflictFinding first = conflict("1.0");
        com.redkite.core.domain.TransitiveConflictFinding second = conflict("2.0");
        Map<String, List<com.redkite.core.domain.TransitiveConflictFinding>> byKey = Map.of("g:a", List.of(first, second), "g:none", List.of());

        assertSame(second, Versions.findMatchingConflict(byKey, component("g", "a", "2.0")));
        assertSame(first, Versions.findMatchingConflict(byKey, component("g", "a", "3.0")));
        assertSame(first, Versions.findMatchingConflict(byKey, component("g", "a", null)));
        assertSame(first, Versions.findMatchingConflict(byKey, component("g", "a", " ")));
        assertNull(Versions.findMatchingConflict(byKey, component("g", "none", "1.0")));
        assertNull(Versions.findMatchingConflict(byKey, component("g", "other", "1.0")));
        assertNull(Versions.findMatchingConflict(null, component("g", "a", "1.0")));
        assertNull(Versions.findMatchingConflict(byKey, null));
    }

    private static com.redkite.core.domain.TransitiveConflictFinding conflict(String resolved) {
        return new com.redkite.core.domain.TransitiveConflictFinding("g", "a", resolved, List.of(), List.of(),
                "dependencyConvergence", null, List.of());
    }

    private static com.redkite.core.domain.ScanComponent component(String g, String a, String version) {
        return new com.redkite.core.domain.ScanComponent(1, new com.redkite.core.domain.ComponentCoordinate(g, a), version,
                null, true, null, "pom.xml", null, Map.of(), false, null, "pom.xml");
    }
}
