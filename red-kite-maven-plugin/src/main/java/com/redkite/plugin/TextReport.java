package com.redkite.plugin;

import com.redkite.core.domain.AdvisorySeverity;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.core.domain.VulnerabilityFinding;
import com.redkite.core.service.AdvisoryClassifier;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Plain-text rendering of a scan, printed to the build log. */
final class TextReport {
    private TextReport() {}

    static String render(ScanReport report) {
        List<String> out = new ArrayList<>();
        out.add("RedKite report");
        out.add("==============");
        long direct = report.components().stream().filter(ScanComponent::direct).count();
        out.add("Components:      " + report.components().size() + " (" + direct + " direct, "
                + (report.components().size() - direct) + " transitive)");
        out.add("Analysis:        " + (report.complete() ? "complete" : "INCOMPLETE - " + report.completenessMessage()));

        // The same dependency appears once per module that uses it; list each finding once.
        Map<String, VulnerabilityFinding> unique = new LinkedHashMap<>();
        for (VulnerabilityFinding v : report.vulnerabilityFindings()) {
            unique.putIfAbsent(key(v.coordinate()) + ":" + v.affectedVersion() + ":" + v.advisoryId(), v);
        }
        List<VulnerabilityFinding> vulns = new ArrayList<>(unique.values());
        vulns.sort(Comparator.<VulnerabilityFinding>comparingInt(v -> -AdvisoryClassifier.severity(v).ordinal())
                .thenComparing(v -> key(v.coordinate())));
        out.add("Vulnerabilities: " + vulns.size() + severityBreakdown(vulns));
        Map<String, UpgradeRecommendation> uniqueRecs = new LinkedHashMap<>();
        for (UpgradeRecommendation r : report.recommendations()) {
            uniqueRecs.putIfAbsent(key(r.coordinate()) + ":" + r.currentVersion() + ":" + r.targetVersion(), r);
        }
        out.add("Recommendations: " + uniqueRecs.size());
        out.add("");

        out.add("Vulnerabilities");
        out.add("---------------");
        if (vulns.isEmpty()) {
            out.add("  none");
        }
        for (VulnerabilityFinding v : vulns) {
            out.add(String.format("  %-9s %s:%s  %s", AdvisoryClassifier.severity(v).label().toUpperCase(),
                    key(v.coordinate()), v.affectedVersion(), v.advisoryId()
                            + (v.cves().isEmpty() ? "" : " (" + String.join(", ", v.cves()) + ")")));
            out.add("            " + (blank(v.fixedVersion()) ? "no fixed version known" : "fixed in " + v.fixedVersion()));
        }
        out.add("");

        List<ScanComponent> snapshots = report.components().stream().filter(ScanComponent::snapshot).toList();
        out.add("SNAPSHOT dependencies");
        out.add("---------------------");
        if (snapshots.isEmpty()) {
            out.add("  none");
        }
        for (ScanComponent c : snapshots) {
            out.add("  " + key(c.coordinate()) + ":" + c.version());
        }
        out.add("");

        out.add("Recommended upgrades");
        out.add("--------------------");
        if (uniqueRecs.isEmpty()) {
            out.add("  none");
        }
        List<UpgradeRecommendation> recs = new ArrayList<>(uniqueRecs.values());
        recs.sort(Comparator.comparing((UpgradeRecommendation r) -> key(r.coordinate())));
        for (UpgradeRecommendation r : recs) {
            out.add(String.format("  %-60s %s -> %s  [%s, %s risk]", key(r.coordinate()), r.currentVersion(),
                    r.targetVersion(), r.reason(), r.riskLevel()));
        }
        if (!report.treeParseWarnings().isEmpty()) {
            out.add("");
            out.add("Warnings");
            out.add("--------");
            report.treeParseWarnings().forEach(w -> out.add("  " + w));
        }
        return String.join(System.lineSeparator(), out) + System.lineSeparator();
    }

    private static String severityBreakdown(List<VulnerabilityFinding> vulns) {
        Map<AdvisorySeverity, Integer> counts = new EnumMap<>(AdvisorySeverity.class);
        for (VulnerabilityFinding v : vulns) counts.merge(AdvisoryClassifier.severity(v), 1, Integer::sum);
        List<String> parts = new ArrayList<>();
        for (AdvisorySeverity s : List.of(AdvisorySeverity.CRITICAL, AdvisorySeverity.HIGH, AdvisorySeverity.MEDIUM,
                AdvisorySeverity.LOW, AdvisorySeverity.UNKNOWN)) {
            if (counts.containsKey(s)) parts.add(counts.get(s) + " " + s.label().toLowerCase());
        }
        return parts.isEmpty() ? "" : " (" + String.join(", ", parts) + ")";
    }

    private static String key(ComponentCoordinate c) {
        return c.groupId() + ":" + c.artifactId();
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }
}
