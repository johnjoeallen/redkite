package com.redkite.maven;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MavenExecutableTest {
    @Test
    void theConfiguredExecutableWinsOverThePlatformDefault() {
        String saved = System.getProperty(MavenExecutable.PROPERTY);
        try {
            System.setProperty(MavenExecutable.PROPERTY, "/opt/maven/bin/mvn");
            assertEquals("/opt/maven/bin/mvn", MavenExecutable.resolve());
            System.setProperty(MavenExecutable.PROPERTY, " ");
            String fallback = System.getProperty("os.name", "").toLowerCase().contains("win") ? "mvn.cmd" : "mvn";
            assertEquals(fallback, MavenExecutable.resolve());
            System.clearProperty(MavenExecutable.PROPERTY);
            assertEquals(fallback, MavenExecutable.resolve());
        } finally {
            if (saved == null) System.clearProperty(MavenExecutable.PROPERTY);
            else System.setProperty(MavenExecutable.PROPERTY, saved);
        }
    }
}
