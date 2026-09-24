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
}
