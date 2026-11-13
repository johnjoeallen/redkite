package com.redkite.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redkite.core.domain.*;
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

    @Test
    void failsOnlyAtOrAboveThreshold() {
        ScanReport r = report(true, List.of(component(false)), List.of(vuln("A", "MEDIUM"), vuln("B", "HIGH")));
        assertEquals(1, CheckMojo.evaluate(r, "HIGH", false, false).size());
        assertEquals(2, CheckMojo.evaluate(r, "MEDIUM", false, false).size());
        assertTrue(CheckMojo.evaluate(r, "CRITICAL", false, false).isEmpty());
        assertTrue(CheckMojo.evaluate(r, "NONE", false, false).isEmpty());
    }

    @Test
    void snapshotAndIncompleteChecksAreOptIn() {
        ScanReport r = report(false, List.of(component(true)), List.of());
        assertTrue(CheckMojo.evaluate(r, "HIGH", false, false).isEmpty());
        assertEquals(2, CheckMojo.evaluate(r, "HIGH", true, true).size());
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
