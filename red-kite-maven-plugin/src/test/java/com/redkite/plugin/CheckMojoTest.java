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
}
