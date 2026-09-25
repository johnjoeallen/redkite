package com.redkite.server;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** The scan job's progress arithmetic. */
class ScanApiHandlersTest {
    @Test
    void treeProgressSpreadsEightyPercentOverTheModules() {
        assertEquals(20, ScanApiHandlers.treeProgressPercent(0, 0), "module count not yet known");
        assertEquals(10, ScanApiHandlers.treeProgressPercent(0, 4));
        assertEquals(30, ScanApiHandlers.treeProgressPercent(1, 4));
        assertEquals(50, ScanApiHandlers.treeProgressPercent(2, 4));
        assertEquals(90, ScanApiHandlers.treeProgressPercent(4, 4));
        assertEquals(95, ScanApiHandlers.treeProgressPercent(6, 4), "capped if more trees run than modules were announced");
        assertEquals(26, ScanApiHandlers.treeProgressPercent(1, 5));
    }

    @Test
    void stepProgressReadsCountMessages() {
        assertEquals(25, ScanApiHandlers.stepProgressPercent("Version 1/4", "Version "));
        assertEquals(66, ScanApiHandlers.stepProgressPercent("Vulnerability 2/3", "Vulnerability "));
        assertEquals(100, ScanApiHandlers.stepProgressPercent("Version  3 / 3 ", "Version "));
        assertEquals(0, ScanApiHandlers.stepProgressPercent("Version 1/0", "Version "));
        assertNull(ScanApiHandlers.stepProgressPercent("License 1/4", "Version "));
        assertNull(ScanApiHandlers.stepProgressPercent("Version x/4", "Version "));
        assertNull(ScanApiHandlers.stepProgressPercent("Version 4", "Version "));
    }
}
