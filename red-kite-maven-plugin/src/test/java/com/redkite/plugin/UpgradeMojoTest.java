package com.redkite.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

class UpgradeMojoTest {
    @Test
    void parsesCoordinatesWithAndWithoutVersions() throws Exception {
        Map<String, String> m = PomChangeMojo.parse(" com.a:b:1.2 , org.c:d ,, ");
        assertEquals(2, m.size());
        assertEquals("1.2", m.get("com.a:b"));
        assertTrue(m.containsKey("org.c:d"));
        assertNull(m.get("org.c:d"), "no version means the recommended one");
        assertTrue(PomChangeMojo.parse(null).isEmpty());
        assertTrue(PomChangeMojo.parse("  ").isEmpty());
    }

    @Test
    void rejectsMalformedUpgrades() {
        for (String bad : new String[] {"onlyone", "a:b:c:d", "a::1", "a:b:"}) {
            assertThrows(MojoFailureException.class, () -> PomChangeMojo.parse(bad), bad);
        }
    }

    @Test
    void parsesPinCoordinatesWithoutVersions() throws Exception {
        assertEquals(Set.of("a:b", "c:d"), PomChangeMojo.parseCoordinates(" a:b, c:d,, "));
        for (String bad : new String[] {"a", "a:b:1", "a:", ":b"}) {
            assertThrows(MojoFailureException.class, () -> PomChangeMojo.parseCoordinates(bad), bad);
        }
    }

    @Test
    void upgradeRequiresAListAndPointsAtTheBulkGoals() {
        MojoFailureException e = assertThrows(MojoFailureException.class, new UpgradeMojo()::execute);
        assertTrue(e.getMessage().contains("redkite.upgrades"));
        assertTrue(e.getMessage().contains("upgrade-all") && e.getMessage().contains("upgrade-cve"));
    }

    @Test
    void dropAndUnpinRequireNamedPins() {
        for (PinGoalMojo mojo : new PinGoalMojo[] {new DropMojo(), new UnpinMojo()}) {
            MojoFailureException e = assertThrows(MojoFailureException.class, mojo::execute);
            assertTrue(e.getMessage().contains("redkite.pins"));
        }
    }
}
