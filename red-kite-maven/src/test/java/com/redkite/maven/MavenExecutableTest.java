package com.redkite.maven;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MavenExecutableTest {
    @Test
    void recognisesJvmEnvironmentBanners() {
        assertTrue(MavenExecutable.isJvmBanner("Picked up JAVA_TOOL_OPTIONS: -Djavax.net.ssl.trustStore=x"));
        assertTrue(MavenExecutable.isJvmBanner("Picked up _JAVA_OPTIONS: -Xmx1g"));
        assertTrue(MavenExecutable.isJvmBanner("Picked up JDK_JAVA_OPTIONS: --add-opens a/b"));
    }

    @Test
    void leavesMavenOutputAlone() {
        assertFalse(MavenExecutable.isJvmBanner("[INFO] BUILD SUCCESS"));
        assertFalse(MavenExecutable.isJvmBanner("Picked up something else"));
        assertFalse(MavenExecutable.isJvmBanner(null));
    }
}
