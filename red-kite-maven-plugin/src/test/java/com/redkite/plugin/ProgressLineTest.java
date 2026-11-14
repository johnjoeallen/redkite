package com.redkite.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class ProgressLineTest {
    @Test
    void countersShareAPhase() {
        assertEquals("Version", ProgressLine.phase("Version 12/40"));
        assertEquals("Dependency management", ProgressLine.phase("Dependency management 60"));
        assertEquals("Reading git metadata…", ProgressLine.phase("Reading git metadata…"));
    }

    @Test
    void animatesOnlyOnAnInteractiveTerminal() {
        assertTrue(ProgressLine.shouldAnimate(true, false, true, null, "xterm"));
        assertFalse(ProgressLine.shouldAnimate(false, false, true, null, "xterm"), "batch mode");
        assertFalse(ProgressLine.shouldAnimate(true, true, true, null, "xterm"), "debug logging");
        assertFalse(ProgressLine.shouldAnimate(true, false, false, null, "xterm"), "redirected");
        assertFalse(ProgressLine.shouldAnimate(true, false, true, "true", "xterm"), "CI");
        assertFalse(ProgressLine.shouldAnimate(true, false, true, null, "dumb"), "dumb terminal");
    }

    @Test
    void rendersFrameMessageAndElapsedTime() {
        assertEquals("⠋ Version 3/9 (12s)", ProgressLine.render("⠋", "Version 3/9", 12));
    }

    @Test
    void nonInteractiveLogsEachPhaseOnce() {
        List<String> logged = new ArrayList<>();
        try (ProgressLine p = new ProgressLine(false, new PrintStream(new ByteArrayOutputStream()), logged::add, true)) {
            p.start();
            p.update("Reading git metadata…");
            p.update("Version 1/3");
            p.update("Version 2/3");
            p.update("Vulnerability 1/3");
        }
        assertEquals(List.of("Reading git metadata…", "Version 1/3", "Vulnerability 1/3"), logged);
    }

    @Test
    void interactiveDrawsAndThenClearsItsLine() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        List<String> logged = new ArrayList<>();
        try (ProgressLine p = new ProgressLine(true, new PrintStream(bytes, true, "UTF-8"), logged::add, false)) {
            p.start();
            p.update("Version 1/3");
            Thread.sleep(250);
        }
        String drawn = bytes.toString("UTF-8");
        assertTrue(drawn.contains("Version 1/3"), drawn);
        assertTrue(drawn.endsWith("\r\u001B[2K"), "the line is cleared on close");
        assertTrue(logged.isEmpty(), "no log lines while animating");
    }
}
