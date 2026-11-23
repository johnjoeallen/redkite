package com.redkite.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.RecommendationConfidence;
import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.RiskLevel;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.core.domain.VulnerabilityFinding;
import com.redkite.server.ReportExporter;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;

class AcceptedRisksTest {
    private static final LocalDate TODAY = LocalDate.of(2026, 12, 1);

    private static VulnerabilityFinding finding(String advisory, String cve, String artifact, String version) {
        return new VulnerabilityFinding(advisory, "CRITICAL", new ComponentCoordinate("g", artifact), version, null, null,
                true, null, cve == null ? List.of() : List.of(cve), null);
    }

    private static ReportExporter.Result result(VulnerabilityFinding... findings) {
        UpgradeRecommendation rec = new UpgradeRecommendation(1, new ComponentCoordinate("g", "a"), "1.0", "1.1",
                RecommendationReason.CVE_FIX, RiskLevel.PATCH, RecommendationConfidence.HIGH, List.of(), List.of());
        UpgradeRecommendation other = new UpgradeRecommendation(2, new ComponentCoordinate("g", "b"), "1.0", "1.1",
                RecommendationReason.CVE_FIX, RiskLevel.PATCH, RecommendationConfidence.HIGH, List.of(), List.of());
        ScanReport r = new ScanReport("s", "p", true, "", Instant.now(), List.of(), List.of(), List.of(findings),
                List.of(rec, other), List.of(), List.of(), List.of());
        return new ReportExporter.Result("s", r, List.of());
    }

    @Test
    void acceptsByAdvisoryOrCveUntilTheDateInclusive() {
        ReportExporter.Result r = result(finding("GHSA-1", "CVE-1", "a", "1.0"));
        AcceptedRisks.Result byGhsa = AcceptedRisks.apply(r.report(), List.of(new AcceptedRisk("ghsa-1", null, "why", "2026-12-01")), TODAY);
        assertEquals(1, byGhsa.accepted().size());
        assertTrue(byGhsa.active().isEmpty());
        AcceptedRisks.Result byCve = AcceptedRisks.apply(r.report(), List.of(new AcceptedRisk("CVE-1", null, null, "2026-12-31")), TODAY);
        assertEquals(1, byCve.accepted().size());
    }

    @Test
    void anExpiredRiskIsReportedAgain() {
        ReportExporter.Result r = result(finding("GHSA-1", null, "a", "1.0"));
        AcceptedRisks.Result res = AcceptedRisks.apply(r.report(), List.of(new AcceptedRisk("GHSA-1", null, null, "2026-11-30")), TODAY);
        assertTrue(res.accepted().isEmpty());
        assertEquals(1, res.active().size());
        assertEquals(1, res.expired().size());
        assertTrue(res.covered().isEmpty());
    }

    @Test
    void aCoordinateWithAVersionStopsApplyingWhenTheVersionChanges() {
        AcceptedRisk risk = new AcceptedRisk("GHSA-1", "g:a:1.0", null, "2027-01-01");
        assertEquals(1, AcceptedRisks.apply(result(finding("GHSA-1", null, "a", "1.0")).report(), List.of(risk), TODAY).accepted().size());
        AcceptedRisks.Result moved = AcceptedRisks.apply(result(finding("GHSA-1", null, "a", "1.1")).report(), List.of(risk), TODAY);
        assertTrue(moved.accepted().isEmpty());
        assertEquals(1, moved.unmatched().size(), "the stale entry is reported so it can be removed");
        AcceptedRisk otherDependency = new AcceptedRisk("GHSA-1", "g:b", null, "2027-01-01");
        assertTrue(AcceptedRisks.apply(result(finding("GHSA-1", null, "a", "1.0")).report(), List.of(otherDependency), TODAY).accepted().isEmpty());
    }

    @Test
    void filteringDropsAcceptedFindingsAndTheirRecommendationsOnly() {
        ReportExporter.Result r = result(finding("GHSA-1", null, "a", "1.0"), finding("GHSA-2", null, "b", "1.0"));
        AcceptedRisks.Result split = AcceptedRisks.apply(r.report(), List.of(new AcceptedRisk("GHSA-1", null, null, "2027-01-01")), TODAY);
        ReportExporter.Result filtered = AcceptedRisks.filter(r, split);
        assertEquals(List.of("GHSA-2"), filtered.report().vulnerabilityFindings().stream().map(VulnerabilityFinding::advisoryId).toList());
        assertEquals(List.of("b"), filtered.report().recommendations().stream().map(u -> u.coordinate().artifactId()).toList());
    }

    @Test
    void aDependencyWithAnotherUnacceptedFindingKeepsItsRecommendation() {
        ReportExporter.Result r = result(finding("GHSA-1", null, "a", "1.0"), finding("GHSA-9", null, "a", "1.0"));
        AcceptedRisks.Result split = AcceptedRisks.apply(r.report(), List.of(new AcceptedRisk("GHSA-1", null, null, "2027-01-01")), TODAY);
        assertTrue(split.covered().isEmpty());
        assertEquals(2, AcceptedRisks.filter(r, split).report().recommendations().size());
    }

    @Test
    void validationNamesWhatIsWrong() {
        assertTrue(AcceptedRisks.validate(null).isEmpty());
        assertTrue(AcceptedRisks.validate(List.of(new AcceptedRisk("GHSA-1", "g:a", null, "2027-01-01"))).isEmpty());
        assertTrue(AcceptedRisks.validate(List.of(new AcceptedRisk(null, null, null, "2027-01-01"))).get(0).contains("<advisory>"));
        assertTrue(AcceptedRisks.validate(List.of(new AcceptedRisk("GHSA-1", null, null, null))).get(0).contains("<until>"));
        assertTrue(AcceptedRisks.validate(List.of(new AcceptedRisk("GHSA-1", null, null, "next week"))).get(0).contains("invalid <until>"));
        assertTrue(AcceptedRisks.validate(List.of(new AcceptedRisk("GHSA-1", "justonepart", null, "2027-01-01"))).get(0).contains("<coordinate>"));
    }

    @Test
    void theReportListsAcceptedAndExpiredRisksAndLeavesAcceptedOutOfTheCount() {
        ReportExporter.Result r = result(finding("GHSA-1", "CVE-1", "a", "1.0"), finding("GHSA-2", null, "b", "1.0"));
        AcceptedRisks.Result split = AcceptedRisks.apply(r.report(), List.of(
                new AcceptedRisk("GHSA-1", null, "best version available", "2027-01-01"),
                new AcceptedRisk("GHSA-2", null, null, "2026-01-01")), TODAY);
        String text = TextReport.render(AcceptedRisks.filter(r, split).report(), false, java.util.Set.of(), java.util.Set.of(), null, split);
        assertTrue(text.contains("Vulnerabilities: 1 (1 critical)"), text);
        assertTrue(text.contains("Accepted risks:  1"), text);
        assertTrue(text.contains("accepted until 2027-01-01"), text);
        assertTrue(text.contains("reason: best version available"), text);
        assertTrue(text.contains("EXPIRED   g:b:1.0"), text);
        assertFalse(TextReport.render(r.report(), false).contains("Accepted risks"));
    }
}
