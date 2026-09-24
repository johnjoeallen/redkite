package com.redkite.server;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.RiskLevel;
import com.redkite.core.domain.VersionMetadata;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** How the report picks and classifies a plain (non-CVE) upgrade. */
class ReportBuilderTest {
    private static VersionMetadata metadata(String latest, String latestSameMajor, List<String> upgradePath) {
        return new VersionMetadata(new ComponentCoordinate("g", "a"), latest, latestSameMajor, upgradePath,
                true, null, "test", true, null, null, List.of());
    }

    @Test
    void latestInTheSameMajorWinsWhenItIsAStableUpgrade() {
        assertEquals("1.9", ReportBuilder.selectUpgradeTarget("1.0", metadata("2.0", "1.9", List.of("1.5"))));
        assertNull(ReportBuilder.selectUpgradeTarget("1.0", null));
    }

    @Test
    void withoutAnUpgradePathTheLatestVersionIsUsed() {
        assertEquals("2.0", ReportBuilder.selectUpgradeTarget("1.0", metadata("2.0", "1.9-RC1", null)));
        assertEquals("2.0", ReportBuilder.selectUpgradeTarget("1.0", metadata("2.0", "1.0", List.of())));
    }

    @Test
    void upgradePathPrefersTheSameMinorThenTheSameMajor() {
        List<String> path = Arrays.asList(null, "", "1.2.9-SNAPSHOT", "1.1.0", "2.0.0", "1.2.5", "1.3.0");
        assertEquals("1.2.5", ReportBuilder.selectUpgradeTarget("1.2.0", metadata("3.0.0", null, path)));
        assertEquals("1.3.0", ReportBuilder.selectUpgradeTarget("1.2.0",
                metadata("3.0.0", null, Arrays.asList(null, "", "1.3.0-beta", "1.1.0", "2.0.0", "1.3.0"))));
    }

    @Test
    void anyStableUpgradeOnThePathBeatsTheLatestVersion() {
        assertEquals("2.0.0", ReportBuilder.selectUpgradeTarget("1.2.0",
                metadata("3.0.0", null, Arrays.asList(null, "", "2.1.0-M1", "1.1.0", "2.0.0"))));
    }

    @Test
    void latestIsTheLastResortAndOnlyIfItIsAStableUpgrade() {
        assertEquals("1.5.0", ReportBuilder.selectUpgradeTarget("1.2.0", metadata("1.5.0", null, List.of("1.1.0"))));
        assertNull(ReportBuilder.selectUpgradeTarget("1.2.0", metadata("1.5.0-rc1", null, List.of("1.1.0"))));
        assertNull(ReportBuilder.selectUpgradeTarget("1.2.0", metadata("1.2.0", null, List.of("1.1.0"))));
        assertNull(ReportBuilder.selectUpgradeTarget(" ", metadata("1.5.0", null, List.of("1.1.0"))));
        assertNull(ReportBuilder.selectUpgradeTarget(null, metadata("1.5.0", null, List.of("1.1.0"))));
    }

    @Test
    void reasonAndRiskFollowTheSizeOfTheJump() {
        assertEquals(RecommendationReason.MAJOR_AVAILABLE, ReportBuilder.upgradeReason("1.0", "2.0"));
        assertEquals(RecommendationReason.MINOR_AVAILABLE, ReportBuilder.upgradeReason("1.0", "1.1"));
        assertEquals(RecommendationReason.PATCH_AVAILABLE, ReportBuilder.upgradeReason("1.1", "1.1.5"));
        assertEquals(RiskLevel.MAJOR, ReportBuilder.upgradeRisk("1.0", "2.0"));
        assertEquals(RiskLevel.MINOR, ReportBuilder.upgradeRisk("1.0", "1.1"));
        assertEquals(RiskLevel.PATCH, ReportBuilder.upgradeRisk("1.1", "1.1.5"));
    }
}
