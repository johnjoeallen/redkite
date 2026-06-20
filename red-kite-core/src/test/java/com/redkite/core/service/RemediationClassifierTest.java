package com.redkite.core.service;

import com.redkite.core.domain.*;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RemediationClassifierTest {

    private static final ComponentCoordinate COORD = new ComponentCoordinate("com.example", "lib");

    private static ScanComponent component(long id, boolean snapshot, boolean direct, VersionSource source) {
        return new ScanComponent(id, COORD, "1.0.0", DependencyScope.COMPILE,
                direct, source, "pom.xml", null, Map.of(), snapshot, null, null);
    }

    private static ScanComponent releaseComponent(long id) {
        return component(id, false, true, VersionSource.PROPERTY);
    }

    private static VulnerabilityFinding finding(String severity) {
        return new VulnerabilityFinding("ADV-001", severity, COORD, "1.0.0", null,
                true, null, List.of("CVE-2023-1234"), null);
    }

    private static UpgradeRecommendation recommendation(long componentId) {
        return new UpgradeRecommendation(componentId, COORD, "1.0.0", "2.0.0",
                RecommendationReason.PATCH_AVAILABLE, RiskLevel.PATCH,
                RecommendationConfidence.HIGH, List.of(), List.of(componentId));
    }

    private static MetadataResult freshMetadata(long componentId) {
        return new MetadataResult(1L, componentId, MetadataType.VERSION, "maven",
                "1.0.0", "2.0.0", "1.9.9", List.of(), true,
                MetadataStatus.FRESH, CacheState.FRESH, Instant.now(), null, Instant.now(), null, "ok");
    }

    private static MetadataResult staleMetadata(long componentId) {
        return new MetadataResult(1L, componentId, MetadataType.VERSION, "maven",
                "1.0.0", "unknown", "unknown", List.of(), false,
                MetadataStatus.STALE_USED, CacheState.STALE, Instant.now(), null, Instant.now(), null, "stale");
    }

    private static MetadataResult rateLimitedMetadata(long componentId) {
        return new MetadataResult(1L, componentId, MetadataType.VERSION, "maven",
                "1.0.0", "unknown", "unknown", List.of(), false,
                MetadataStatus.RATE_LIMITED, CacheState.MISSING, null, null, Instant.now(), null, "rate limited");
    }

    // --- needsRemediation cases ---

    @Test
    void snapshotNeedsRemediation() {
        ScanComponent comp = component(1L, true, true, VersionSource.LITERAL);
        RemediationStatus status = RemediationClassifier.classify(comp, List.of(), List.of(), List.of());
        assertTrue(status.needsRemediation());
        assertTrue(status.isSnapshot());
    }

    @Test
    void directInlineVersionNeedsRemediation() {
        ScanComponent comp = component(1L, false, true, VersionSource.LITERAL);
        RemediationStatus status = RemediationClassifier.classify(comp, List.of(), List.of(), List.of());
        assertTrue(status.needsRemediation());
        assertTrue(status.hasDirectVersionDeclaration());
    }

    @Test
    void transitiveInlineVersionIsNotFlagged() {
        ScanComponent comp = component(1L, false, false, VersionSource.LITERAL);
        RemediationStatus status = RemediationClassifier.classify(comp, List.of(), List.of(), List.of());
        assertFalse(status.hasDirectVersionDeclaration());
    }

    @Test
    void vulnerabilityNeedsRemediation() {
        ScanComponent comp = releaseComponent(1L);
        RemediationStatus status = RemediationClassifier.classify(
                comp, List.of(finding("HIGH")), List.of(), List.of());
        assertTrue(status.needsRemediation());
        assertTrue(status.hasVulnerability());
        assertEquals(AdvisorySeverity.HIGH, status.highestSeverity());
        assertEquals(1, status.vulnerabilityCount());
    }

    @Test
    void unknownSeverityVulnerabilityNeedsRemediation() {
        ScanComponent comp = releaseComponent(1L);
        RemediationStatus status = RemediationClassifier.classify(
                comp, List.of(finding(null)), List.of(), List.of());
        assertTrue(status.needsRemediation());
        assertTrue(status.hasVulnerability());
        assertEquals(AdvisorySeverity.UNKNOWN, status.highestSeverity());
    }

    @Test
    void upgradeRecommendationNeedsRemediation() {
        ScanComponent comp = releaseComponent(1L);
        RemediationStatus status = RemediationClassifier.classify(
                comp, List.of(), List.of(recommendation(1L)), List.of());
        assertTrue(status.needsRemediation());
        assertTrue(status.hasUpgradeRecommendation());
    }

    @Test
    void staleMetadataNeedsRemediation() {
        ScanComponent comp = releaseComponent(1L);
        RemediationStatus status = RemediationClassifier.classify(
                comp, List.of(), List.of(), List.of(staleMetadata(1L)));
        assertTrue(status.needsRemediation());
        assertTrue(status.hasStaleMetadata());
    }

    @Test
    void rateLimitedMetadataNeedsRemediation() {
        ScanComponent comp = releaseComponent(1L);
        RemediationStatus status = RemediationClassifier.classify(
                comp, List.of(), List.of(), List.of(rateLimitedMetadata(1L)));
        assertTrue(status.needsRemediation());
        assertTrue(status.hasStaleMetadata());
    }

    @Test
    void cleanComponentIsClean() {
        ScanComponent comp = releaseComponent(1L);
        RemediationStatus status = RemediationClassifier.classify(
                comp, List.of(), List.of(), List.of(freshMetadata(1L)));
        assertFalse(status.needsRemediation());
        assertFalse(status.isSnapshot());
        assertFalse(status.hasDirectVersionDeclaration());
        assertFalse(status.hasVulnerability());
        assertFalse(status.hasUpgradeRecommendation());
        assertFalse(status.hasStaleMetadata());
        assertEquals(AdvisorySeverity.NONE, status.highestSeverity());
    }

    // --- ReportSummary tests ---

    private static ScanReport minimalReport(List<ScanComponent> components,
            List<VulnerabilityFinding> findings,
            List<UpgradeRecommendation> recs,
            List<MetadataResult> metadata) {
        return new ScanReport(1L, 1L, true, "ok", Instant.now(),
                components, List.of(), findings, recs, List.of(), metadata);
    }

    private static ScanComponent componentAt(long id, String artifactId, boolean snapshot, boolean direct, VersionSource source) {
        ComponentCoordinate coord = new ComponentCoordinate("com.example", artifactId);
        return new ScanComponent(id, coord, "1.0.0", DependencyScope.COMPILE,
                direct, source, "pom.xml", null, Map.of(), snapshot, null, null);
    }

    @Test
    void summaryCounts() {
        ScanComponent clean = componentAt(1L, "clean-lib", false, true, VersionSource.PROPERTY);
        ScanComponent vuln = componentAt(2L, "vuln-lib", false, true, VersionSource.PROPERTY);
        ScanComponent snap = componentAt(3L, "snap-lib", true, true, VersionSource.LITERAL);
        VulnerabilityFinding vulnFinding = new VulnerabilityFinding("ADV-001", "HIGH",
                new ComponentCoordinate("com.example", "vuln-lib"), "1.0.0", null,
                true, null, List.of("CVE-2023-1234"), null);

        ScanReport report = minimalReport(
                List.of(clean, vuln, snap),
                List.of(vulnFinding),
                List.of(),
                List.of(freshMetadata(1L), freshMetadata(2L)));

        ReportSummary summary = RemediationClassifier.summarize(report);

        assertEquals(3, summary.totalComponents());
        assertEquals(2, summary.needsRemediation()); // vuln + snapshot
        assertEquals(1, summary.clean());
        assertEquals(1, summary.highCount());
        assertEquals(0, summary.criticalCount());
        assertEquals(1, summary.snapshotCount());
    }

    @Test
    void incompleteSummaryCountsStaleComponents() {
        ScanComponent comp = releaseComponent(1L);
        ScanReport report = minimalReport(
                List.of(comp), List.of(), List.of(), List.of(staleMetadata(1L)));
        ReportSummary summary = RemediationClassifier.summarize(report);
        assertEquals(1, summary.staleMetadataCount());
        assertEquals(1, summary.needsRemediation());
        assertEquals(0, summary.clean());
    }

    @Test
    void duplicateComponentsAreDeduplicatedInSummary() {
        ScanComponent comp = releaseComponent(1L);
        // Same component twice (e.g. from multi-module scan)
        ScanReport report = minimalReport(
                List.of(comp, comp), List.of(), List.of(), List.of());
        ReportSummary summary = RemediationClassifier.summarize(report);
        assertEquals(1, summary.totalComponents());
    }
}
