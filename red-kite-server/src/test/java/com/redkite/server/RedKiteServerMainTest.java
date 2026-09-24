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

/** Startup configuration from ~/.redkite/redkite.properties. */
class RedKiteServerMainTest {
    // ---------------------------------------------------------------- redkite.properties

    @Test
    void configFileFillsUnsetRedkiteProperties(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("redkite.properties");
        Files.writeString(file, "redkite.test.a=${user.home}/data\nredkite.test.b=from-file\nredkite.test.blank= \nother.key=x\n");
        System.setProperty("redkite.test.b", "from-flag");
        try {
            RedKiteServerMain.loadConfigFileDefaults(file);
            assertEquals(System.getProperty("user.home") + "/data", System.getProperty("redkite.test.a"));
            assertEquals("from-flag", System.getProperty("redkite.test.b"), "an explicit -D wins");
            assertNull(System.getProperty("redkite.test.blank"));
            assertNull(System.getProperty("other.key"));
        } finally {
            System.clearProperty("redkite.test.a");
            System.clearProperty("redkite.test.b");
        }
    }

    @Test
    void missingOrUnreadableConfigFileIsIgnored(@TempDir Path dir) {
        RedKiteServerMain.loadConfigFileDefaults(dir.resolve("absent.properties"));
        RedKiteServerMain.loadConfigFileDefaults(dir); // a directory cannot be read as a file
        assertNull(System.getProperty("redkite.test.a"));
    }
}
