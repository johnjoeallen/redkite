package com.redkite.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redkite.core.domain.*;
import com.redkite.server.ReportExporter;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CheckMojoTest {
    private static final ComponentCoordinate JACKSON = new ComponentCoordinate("com.fasterxml", "jackson-core");

    private static VulnerabilityFinding vuln(String id, String severity) {
        return new VulnerabilityFinding(id, severity, JACKSON, "2.0.0", "2.0.1", null, true, null, List.of("CVE-1"), null);
    }

    private static ScanComponent component(boolean snapshot) {
        return new ScanComponent(1, JACKSON, "2.0.0", DependencyScope.COMPILE, true, VersionSource.LITERAL,
                "pom.xml", "dependencies", Map.of(), snapshot, null, ".");
    }

    private static ScanReport report(boolean complete, List<ScanComponent> components, List<VulnerabilityFinding> vulns) {
        return new ScanReport("s1", "p1", complete, "msg", Instant.now(), components, List.of(), vulns,
                List.of(), List.of(), List.of(), List.of());
    }

    private static ReportExporter.Remediation fix(String from, String to, AdvisorySeverity residual, boolean sameMajor) {
        return new ReportExporter.Remediation("com.fasterxml", "jackson-core", from, to,
                RecommendationReason.CVE_FIX, residual, sameMajor);
    }

    @Test
    void failsOnlyWhenASameMajorVersionIsBelowTheThreshold() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("A", "HIGH")));
        CheckMojo.Outcome ok = CheckMojo.evaluate(r, List.of(fix("2.0.0", "2.0.1", AdvisorySeverity.NONE, true)), "HIGH", false, false);
        assertEquals(1, ok.problems().size());
        assertTrue(ok.problems().get(0).contains("upgrade to 2.0.1"));
        assertTrue(ok.warnings().isEmpty());
    }

    @Test
    void aDowngradeFixIsWordedAsADowngrade() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("A", "HIGH")));
        CheckMojo.Outcome o = CheckMojo.evaluate(r, List.of(fix("2.0.0", "1.9.0", AdvisorySeverity.NONE, true)), "HIGH", false, false);
        assertTrue(o.problems().get(0).contains("downgrade to 1.9.0"));
    }

    @Test
    void unfixableFindingsWarnButDoNotFail() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("A", "CRITICAL")));
        // no remediation at all, a fix on another major, and a fix that still leaves HIGH
        for (List<ReportExporter.Remediation> fixes : List.of(
                List.<ReportExporter.Remediation>of(),
                List.of(fix("2.0.0", "3.0.0", AdvisorySeverity.NONE, false)),
                List.of(fix("2.0.0", "2.0.1", AdvisorySeverity.HIGH, true)))) {
            CheckMojo.Outcome o = CheckMojo.evaluate(r, fixes, "HIGH", false, false);
            assertTrue(o.problems().isEmpty());
            assertEquals(1, o.warnings().size());
        }
    }

    @Test
    void aResidualBelowTheThresholdCountsAsFixable() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("A", "CRITICAL")));
        CheckMojo.Outcome o = CheckMojo.evaluate(r, List.of(fix("2.0.0", "2.0.1", AdvisorySeverity.MEDIUM, true)), "HIGH", false, false);
        assertEquals(1, o.problems().size());
    }

    @Test
    void findingsBelowTheThresholdAreIgnoredAndNoneDisables() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("A", "MEDIUM")));
        List<ReportExporter.Remediation> fixes = List.of(fix("2.0.0", "2.0.1", AdvisorySeverity.NONE, true));
        assertTrue(CheckMojo.evaluate(r, fixes, "HIGH", false, false).problems().isEmpty());
        ScanReport high = report(true, List.of(component(false)), List.of(vuln("B", "HIGH")));
        assertTrue(CheckMojo.evaluate(high, fixes, "NONE", false, false).problems().isEmpty());
    }

    @Test
    void severalAdvisoriesOnOneComponentGiveOneProblem() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("A", "HIGH"), vuln("B", "CRITICAL"), vuln("A", "HIGH")));
        CheckMojo.Outcome o = CheckMojo.evaluate(r, List.of(fix("2.0.0", "2.0.1", AdvisorySeverity.NONE, true)), "HIGH", false, false);
        assertEquals(1, o.problems().size());
        assertTrue(o.problems().get(0).contains("Critical") && o.problems().get(0).contains("A, B"));
    }

    @Test
    void snapshotAndIncompleteChecksAreOptIn() {
        ScanReport r = report(false, List.of(component(true)), List.of());
        assertTrue(CheckMojo.evaluate(r, List.of(), "HIGH", false, false).problems().isEmpty());
        assertEquals(2, CheckMojo.evaluate(r, List.of(), "HIGH", true, true).problems().size());
    }

    @Test
    void jsonEscapesAndListsFindings() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("A\"B", "HIGH")));
        String json = ReportWriter.toJson(r);
        assertTrue(json.contains("\"advisory\": \"A\\\"B\""));
        assertTrue(json.contains("\"artifactId\": \"jackson-core\""));
        assertEquals("null", ReportWriter.str(null));
    }

    @Test
    void textReportListsSeveritiesWorstFirstAndFixes() {
        ScanReport r = report(true, List.of(component(true)), List.of(vuln("LOW-1", "LOW"), vuln("CRIT-1", "CRITICAL")));
        String text = TextReport.render(r);
        assertTrue(text.contains("Vulnerabilities: 2 (1 critical, 1 low)"));
        assertTrue(text.indexOf("CRIT-1") < text.indexOf("LOW-1"));
        assertTrue(text.contains("fixed in 2.0.1"));
        assertTrue(text.contains("com.fasterxml:jackson-core:2.0.0"), "the SNAPSHOT dependency is listed");
    }

    @Test
    void textReportHandlesAnEmptyScan() {
        String text = TextReport.render(report(false, List.of(), List.of()));
        assertTrue(text.contains("INCOMPLETE"));
        assertTrue(text.contains("Vulnerabilities: 0"));
        assertTrue(text.contains("  none"));
    }

    @Test
    void textReportListsRepeatedFindingsOnce() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("DUP-1", "HIGH"), vuln("DUP-1", "HIGH")));
        String text = TextReport.render(r);
        assertTrue(text.contains("Vulnerabilities: 1 (1 high)"));
        assertEquals(1, text.split("DUP-1", -1).length - 1);
    }
}
