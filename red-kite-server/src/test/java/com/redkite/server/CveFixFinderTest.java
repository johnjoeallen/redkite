package com.redkite.server;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionMetadata;
import com.redkite.core.domain.VulnerabilityFinding;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The upgrade / downgrade / best-effort search for a version that clears a component's CVEs. */
class CveFixFinderTest {
    private static final ComponentCoordinate LIB = new ComponentCoordinate("g", "lib");

    /** Severity of each version's own advisories; versions not listed are clean. */
    private final Map<String, String> severities = new HashMap<>();
    private final List<String> queried = new ArrayList<>();
    private final CveFixFinder finder = new CveFixFinder((coordinate, version) -> {
        queried.add(version);
        String severity = severities.get(version);
        return severity == null ? List.of() : List.of(finding(version, severity, null, null));
    });

    private static VulnerabilityFinding finding(String version, String severity, String fixed, String introduced) {
        return new VulnerabilityFinding("GHSA-" + version, severity, LIB, version, fixed, introduced, false, null, List.of(), null);
    }

    private CveFixFinder.CveFixResult resolve(String current, List<VulnerabilityFinding> vulns, List<String> versions, boolean allowMajor) {
        ScanComponent component = new ScanComponent(1, LIB, current, null, true, null, "pom.xml", null, Map.of(), false, null, "pom.xml");
        VersionMetadata metadata = new VersionMetadata(LIB, null, null, List.of(), true, null, "test", true, null, null, versions);
        return finder.resolveCveFix(component, vulns, metadata, allowMajor);
    }

    private void vulnerable(String severity, String... versions) {
        for (String v : versions) severities.put(v, severity);
    }

    @Test
    void upgradeIsTheSmallestVerifiedCleanVersionPastEveryFix() {
        List<VulnerabilityFinding> vulns = List.of(finding("1.0", "HIGH", "1.5", null), finding("1.0", "HIGH", "1.2", null));
        vulnerable("LOW", "1.5");
        assertEquals(new CveFixFinder.CveFixResult("1.6", RecommendationReason.CVE_FIX),
                resolve("1.0", vulns, List.of("2.0", "1.4", "1.5", "1.6-rc1", "1.6"), true));

        List<VulnerabilityFinding> reversed = List.of(vulns.get(1), vulns.get(0));
        assertEquals("1.6", resolve("1.0", reversed, List.of("2.0", "1.4", "1.5", "1.6"), true).target());
    }

    @Test
    void upgradeMayLandExactlyOnTheFixedVersion() {
        List<VulnerabilityFinding> vulns = List.of(finding("1.0", "HIGH", "1.5", null));
        assertEquals("1.5", resolve("1.0", vulns, List.of("1.4", "1.5", "1.6"), true).target());
    }

    @Test
    void majorUpgradesAreSkippedUnlessAllowed() {
        List<VulnerabilityFinding> vulns = List.of(finding("1.0", "HIGH", "1.5", "0.5"));
        vulnerable("HIGH", "1.0", "1.5", "1.6");
        assertEquals(new CveFixFinder.CveFixResult("2.0", RecommendationReason.CVE_FIX),
                resolve("1.0", vulns, List.of("0.4", "1.5", "1.6", "2.0"), true));
        assertEquals(new CveFixFinder.CveFixResult("0.4", RecommendationReason.CVE_FIX_DOWNGRADE),
                resolve("1.0", vulns, List.of("0.4", "1.5", "1.6", "2.0"), false));
    }

    @Test
    void downgradeIsTheLargestCleanVersionBelowEveryIntroduction() {
        List<VulnerabilityFinding> vulns = List.of(finding("1.2", "HIGH", null, "1.0"), finding("1.2", "HIGH", null, "0.95"));
        assertEquals(new CveFixFinder.CveFixResult("0.9", RecommendationReason.CVE_FIX_DOWNGRADE),
                resolve("1.2", vulns, List.of("0.8", "0.9", "0.95", "1.0", "1.1", "1.3"), true));

        List<VulnerabilityFinding> reversed = List.of(vulns.get(1), vulns.get(0));
        assertEquals("0.9", resolve("1.2", reversed, List.of("0.8", "0.9", "0.95", "1.0"), true).target());
    }

    @Test
    void downgradeNeverOffersTheCurrentVersionOrTheIntroducedOne() {
        // An introduced bound above current: current itself is below it but is not a downgrade.
        List<VulnerabilityFinding> vulns = List.of(finding("1.2", "HIGH", null, "2.0"));
        assertEquals("1.1", resolve("1.2", vulns, List.of("1.1", "1.2"), true).target());

        List<VulnerabilityFinding> atIntroduced = List.of(finding("1.2", "HIGH", null, "1.0"));
        assertEquals("0.9", resolve("1.2", atIntroduced, List.of("0.9", "1.0"), true).target());
    }

    @Test
    void onlySixCandidatesAreVerifiedPerDirection() {
        List<VulnerabilityFinding> vulns = List.of(finding("1.0", "HIGH", "1.1", null));
        vulnerable("HIGH", "1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6");
        // 1.7 is the seventh candidate, so the upgrade search gives up; the best-effort
        // search still finds it because it always checks the latest release.
        assertEquals(new CveFixFinder.CveFixResult("1.7", RecommendationReason.CVE_BEST_EFFORT),
                resolve("1.0", vulns, List.of("1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"), true));
    }

    @Test
    void bestEffortPrefersStrictlyBetterDowngradesOverTiedOrWorseUpgrades() {
        List<VulnerabilityFinding> vulns = List.of(finding("2.0", "HIGH", null, null));
        vulnerable("HIGH", "2.0", "2.1");
        vulnerable("MEDIUM", "2.2", "2.4");
        vulnerable("CRITICAL", "2.3");
        vulnerable("LOW", "1.9");
        assertEquals(new CveFixFinder.CveFixResult("1.9", RecommendationReason.CVE_BEST_EFFORT),
                resolve("2.0", vulns, List.of("1.9", "2.1", "2.2", "2.3", "2.4"), true));
        severities.remove("1.9");
        vulnerable("HIGH", "1.9");
        assertEquals("2.2", resolve("2.0", vulns, List.of("1.9", "2.1", "2.2", "2.3", "2.4"), true).target());
    }

    @Test
    void bestEffortAcceptsATiedUpgradeButNeverATiedDowngrade() {
        List<VulnerabilityFinding> vulns = List.of(finding("2.0", "HIGH", null, null));
        vulnerable("HIGH", "1.9", "2.0", "2.1");
        assertEquals("2.1", resolve("2.0", vulns, List.of("1.9", "2.1"), true).target());
        assertNull(resolve("2.0", vulns, List.of("1.9"), true));
        vulnerable("CRITICAL", "2.1");
        assertNull(resolve("2.0", vulns, List.of("2.1"), true));
    }

    @Test
    void bestEffortBreaksTiesTowardTheClosestVersion() {
        List<VulnerabilityFinding> vulns = List.of(finding("2.0", "HIGH", null, null));
        vulnerable("HIGH", "2.0");
        vulnerable("MEDIUM", "2.2", "2.4");
        assertEquals("2.2", resolve("2.0", vulns, List.of("2.4", "2.2"), true).target());

        vulnerable("CRITICAL", "2.2", "2.4");
        vulnerable("LOW", "1.7", "1.9");
        assertEquals("1.9", resolve("2.0", vulns, List.of("1.7", "1.9", "2.2", "2.4"), true).target());
    }

    @Test
    void bestEffortSearchesABoundedWindowPlusTheLatestRelease() {
        List<VulnerabilityFinding> vulns = List.of(finding("2.0", "HIGH", null, null));
        vulnerable("HIGH", "2.0");
        vulnerable("CRITICAL", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.8", "1.9", "1.8", "1.7");
        // 2.7 (seventh above) and 1.6 (fourth below) are clean but outside the window; 2.9 is the latest.
        assertEquals("2.9", resolve("2.0", vulns,
                List.of("1.6", "1.7", "1.8", "1.9", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "3.0-beta"), true).target());
        vulnerable("CRITICAL", "2.9");
        assertNull(resolve("2.0", vulns,
                List.of("1.6", "1.7", "1.8", "1.9", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "3.0-beta"), true));
        assertFalse(queried.contains("3.0-beta"));
    }
}
