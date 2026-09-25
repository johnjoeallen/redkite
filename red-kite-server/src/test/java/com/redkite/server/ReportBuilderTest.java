package com.redkite.server;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.RiskLevel;
import com.redkite.core.domain.VersionMetadata;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;

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

    @Test
    void buildReportReportsProgressAndDescribesEachComponentsMetadata() {
        String savedRepos = System.getProperty("redkite.maven.repositories"), savedOsv = System.getProperty("redkite.osv.url");
        System.setProperty("redkite.maven.repositories", "http://127.0.0.1:1/repo");
        System.setProperty("redkite.osv.url", "http://127.0.0.1:1");
        try {
            Store store = Store.connect("jdbc:h2:mem:" + java.util.UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1", "sa", "");
            store.licenseResolver = new com.redkite.maven.LicenseResolver((g, a, v) -> "lib".equals(a)
                    ? new com.redkite.maven.PomFetchResult.Found("<project><licenses><license><name>MIT</name></license></licenses></project>")
                    : new com.redkite.maven.PomFetchResult.NotFound());
            ScanComponent lib = component(1, "lib", "1.0", false);
            ScanComponent snap = component(2, "snap", "2.0-SNAPSHOT", true);
            ScanComponent testSnap = component(3, "test-snap", "3.1-SNAPSHOT", true);
            List<String> progress = new java.util.ArrayList<>();
            ScanReport report = store.ingest(new com.redkite.core.domain.ScanInput("p", "/tmp/p", "/tmp/p", "main", "abc", true, false,
                    java.time.Instant.now(), List.of(lib, snap, testSnap), List.of(), Map.of(), List.of()), progress::add);

            assertEquals(List.of("Version 1/3", "Version 2/3", "Version 3/3", "Vulnerability 1/3", "Vulnerability 2/3", "Vulnerability 3/3",
                    "License 1/3", "License 2/3", "License 3/3", "Updates"), progress);
            assertFalse(report.complete(), "the version lookup could not complete");
            assertEquals(List.of("No cached Maven metadata was available; version is unknown.", "No known vulnerabilities.", "Declared: MIT."),
                    report.metadataResults().stream().filter(m -> m.componentId() == 1).map(com.redkite.core.domain.MetadataResult::message).toList());
            assertEquals("No license declared.", report.metadataResults().stream()
                    .filter(m -> m.componentId() == 2 && m.metadataType() == com.redkite.core.domain.MetadataType.LICENSE).findFirst().orElseThrow().message());
            assertEquals(List.of("2.0", "3.1"), report.recommendations().stream().map(com.redkite.core.domain.UpgradeRecommendation::targetVersion).toList(),
                    "a snapshot is recommended its release");
            assertEquals(List.of("HIGH", "LOW"), report.snapshotDependencyRisks().stream().map(com.redkite.core.domain.SnapshotDependencyRisk::severity).toList());
        } finally {
            if (savedRepos == null) System.clearProperty("redkite.maven.repositories"); else System.setProperty("redkite.maven.repositories", savedRepos);
            if (savedOsv == null) System.clearProperty("redkite.osv.url"); else System.setProperty("redkite.osv.url", savedOsv);
        }
    }

    private static ScanComponent component(long id, String artifactId, String version, boolean snapshot) {
        return new ScanComponent(id, new ComponentCoordinate("g", artifactId), version,
                "test-snap".equals(artifactId) ? com.redkite.core.domain.DependencyScope.TEST : com.redkite.core.domain.DependencyScope.COMPILE,
                true, com.redkite.core.domain.VersionSource.LITERAL, "pom.xml", null, Map.of(), snapshot, null, "pom.xml");
    }
}
