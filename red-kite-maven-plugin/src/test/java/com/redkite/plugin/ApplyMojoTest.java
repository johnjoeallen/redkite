package com.redkite.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

class ApplyMojoTest {
    @Test
    void parsesCoordinatesWithAndWithoutVersions() throws Exception {
        Map<String, String> m = ApplyMojo.parse(" com.a:b:1.2 , org.c:d ,, ");
        assertEquals(2, m.size());
        assertEquals("1.2", m.get("com.a:b"));
        assertTrue(m.containsKey("org.c:d"));
        assertNull(m.get("org.c:d"), "no version means the recommended one");
    }

    @Test
    void nullOrBlankIsEmpty() throws Exception {
        assertTrue(ApplyMojo.parse(null).isEmpty());
        assertTrue(ApplyMojo.parse("  ").isEmpty());
    }

    @Test
    void rejectsMalformedItems() {
        for (String bad : new String[] {"onlyone", "a:b:c:d", "a::1", "a:b:"}) {
            assertThrows(MojoFailureException.class, () -> ApplyMojo.parse(bad), bad);
        }
    }

    @Test
    void parsesPinCoordinatesWithoutVersions() throws Exception {
        assertEquals(java.util.Set.of("a:b", "c:d"), ApplyMojo.parseCoordinates(" a:b, c:d,, "));
        for (String bad : new String[] {"a", "a:b:1", "a:", ":b"}) {
            assertThrows(MojoFailureException.class, () -> ApplyMojo.parseCoordinates(bad), bad);
        }
    }

    @Test
    void upgradingAndDroppingTheSameDependencyIsRefused() {
        ApplyMojo mojo = new ApplyMojo();
        mojo.upgrades = "a:b:1.0";
        mojo.drop = "a:b";
        assertTrue(assertThrows(MojoFailureException.class, mojo::execute).getMessage().contains("both"));
    }

    @Test
    void missingUpgradesFailsBeforeAnyAnalysis() {
        ApplyMojo mojo = new ApplyMojo();
        MojoFailureException e = assertThrows(MojoFailureException.class, mojo::execute);
        assertTrue(e.getMessage().contains("redkite.upgrades"));
    }

    @Test
    void theRecommendedGoalIsApplyWithTheRecommendedVersionsSwitchedOn() {
        assertTrue(new RecommendedMojo().recommended);
        assertTrue(!new ApplyMojo().recommended);
    }
}
