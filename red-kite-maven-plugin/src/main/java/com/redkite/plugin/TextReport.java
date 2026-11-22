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
        return render(report, false);
    }

    /** @param showTransitives also list plain "newer version exists" updates for transitive dependencies */
    static String render(ScanReport report, boolean showTransitives) {
        return render(report, showTransitives, java.util.Set.of());
    }

    /** @param pinned {@code groupId:artifactId} of dependencies the user pinned; plain (non-CVE) updates for
     *                them are left out, as in the server, because a pin is a deliberate decision to hold the version */
    static String render(ScanReport report, boolean showTransitives, java.util.Set<String> pinned) {
        return render(report, showTransitives, pinned, java.util.Set.of(), null);
    }

    /** @param redkitePinned {@code groupId:artifactId} of dependencies held by a RedKite-managed
     *                      {@code dependencyManagement} pin, shown beside each vulnerability
     *  @param buildPoms    project-relative paths of the POMs in the Maven build; a finding declared
     *                      elsewhere (a test fixture, say) is flagged because the upgrade goals cannot edit it.
     *                      Null means unknown, and nothing is flagged */
    static String render(ScanReport report, boolean showTransitives, java.util.Set<String> pinned,
                         java.util.Set<String> redkitePinned, java.util.Set<String> buildPoms) {
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
        // Like the server's Outdated count: a plain "newer version exists" on a transitive dependency is
        // left out, because nothing in the project makes it move and there is nothing to change for it.
        // Direct dependencies and anything driven by a vulnerability are listed; showTransitives lists all.
        java.util.Set<String> directKeys = new java.util.HashSet<>();
        for (ScanComponent c : report.components()) {
            if (c.direct()) directKeys.add(key(c.coordinate()) + ":" + c.version());
        }
        Map<String, UpgradeRecommendation> uniqueRecs = new LinkedHashMap<>();
        Map<String, UpgradeRecommendation> transitiveRecs = new LinkedHashMap<>();
        Map<String, UpgradeRecommendation> pinnedRecs = new LinkedHashMap<>();
        for (UpgradeRecommendation r : report.recommendations()) {
            String id = key(r.coordinate()) + ":" + r.currentVersion() + ":" + r.targetVersion();
            if (uniqueRecs.containsKey(id) || transitiveRecs.containsKey(id)) continue;
            if (pinned.contains(key(r.coordinate())) && !isVulnerabilityDriven(r)) {
                pinnedRecs.put(id, r);
                continue;
            }
            if (isActionable(r, directKeys.contains(key(r.coordinate()) + ":" + r.currentVersion()))) {
                uniqueRecs.put(id, r);
            } else {
                transitiveRecs.put(id, r);
            }
        }
        out.add("Recommendations: " + uniqueRecs.size()
                + (transitiveRecs.isEmpty() ? ""
                : showTransitives ? " (+ " + transitiveRecs.size() + " transitive-only updates, listed separately)"
                : " (" + transitiveRecs.size() + " transitive-only updates not listed)")
                + (pinnedRecs.isEmpty() ? "" : " (+ " + pinnedRecs.size() + " updates for pinned dependencies, listed separately)"));
        out.add("");

        out.add("Vulnerabilities");
        out.add("---------------");
        if (vulns.isEmpty()) {
            out.add("  none");
        }
        // One block per vulnerable dependency, with its advisories, where it is declared and its pin status.
        Map<String, List<VulnerabilityFinding>> byDependency = new LinkedHashMap<>();
        for (VulnerabilityFinding v : vulns) {
            byDependency.computeIfAbsent(key(v.coordinate()) + ":" + v.affectedVersion(), k -> new ArrayList<>()).add(v);
        }
        boolean firstBlock = true;
        for (Map.Entry<String, List<VulnerabilityFinding>> e : byDependency.entrySet()) {
            if (!firstBlock) out.add("");
            firstBlock = false;
            List<VulnerabilityFinding> group = e.getValue();
            VulnerabilityFinding head = group.get(0); // sorted, so the most severe advisory leads
            String k = key(head.coordinate());
            String pin = pinned.contains(k) ? "  [pinned by user]" : redkitePinned.contains(k) ? "  [pinned by RedKite]" : "";
            out.add(String.format("  %-9s %s:%s%s", AdvisoryClassifier.severity(head).label().toUpperCase(), k,
                    head.affectedVersion(), pin));
            for (VulnerabilityFinding v : group) {
                out.add("      " + v.advisoryId() + (v.cves().isEmpty() ? "" : " (" + String.join(", ", v.cves()) + ")")
                        + "  " + (blank(v.fixedVersion()) ? "no fixed version known" : "fixed in " + v.fixedVersion()));
            }
            out.addAll(locations(report, head, buildPoms));
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
        addRecommendations(out, uniqueRecs.values());
        if (showTransitives) {
            out.add("");
            out.add("Transitive-only updates");
            out.add("-----------------------");
            out.add("  Not declared by the project and not driven by a vulnerability.");
            if (transitiveRecs.isEmpty()) {
                out.add("  none");
            }
            addRecommendations(out, transitiveRecs.values());
        }
        out.add("");
        out.add("Pinned dependencies with upgrades available");
        out.add("-------------------------------------------");
        out.add("  Held back by a redkite:user-pin marker; shown for information only.");
        if (pinnedRecs.isEmpty()) {
            out.add("  none");
        }
        addRecommendations(out, pinnedRecs.values());
        if (!report.treeParseWarnings().isEmpty()) {
            out.add("");
            out.add("Warnings");
            out.add("--------");
            report.treeParseWarnings().forEach(w -> out.add("  " + w));
        }
        return String.join(System.lineSeparator(), out) + System.lineSeparator();
    }

    private static final int MAX_LOCATIONS = 5;

    /** Where a vulnerable dependency comes from: the POMs that declare it (direct) or the modules that
     *  pull it in (transitive), flagging POMs outside the build, which the upgrade goals cannot edit. */
    private static List<String> locations(ScanReport report, VulnerabilityFinding v, java.util.Set<String> buildPoms) {
        Map<String, Boolean> where = new LinkedHashMap<>(); // description -> outside the build
        for (ScanComponent c : report.components()) {
            if (!c.coordinate().equals(v.coordinate()) || !v.affectedVersion().equals(c.version())) continue;
            String pom = c.direct() ? c.sourceFilePath() : pomOf(c.modulePath());
            if (pom == null) continue;
            where.put((c.direct() ? "declared in " : "via ") + pom, buildPoms != null && !buildPoms.contains(pom));
        }
        List<String> out = new ArrayList<>();
        int shown = 0;
        boolean outside = false;
        for (Map.Entry<String, Boolean> w : where.entrySet()) {
            outside |= w.getValue();
            if (shown++ < MAX_LOCATIONS) {
                out.add("      " + w.getKey() + (w.getValue() ? "  (not in the build)" : ""));
            }
        }
        if (where.size() > MAX_LOCATIONS) out.add("      +" + (where.size() - MAX_LOCATIONS) + " more");
        if (outside) out.add("      The upgrade goals cannot edit POMs outside the build; exclude them or fix them by hand.");
        return out;
    }

    private static String pomOf(String modulePath) {
        if (modulePath == null) return null;
        return modulePath.isEmpty() || modulePath.equals(".") ? "pom.xml" : modulePath + "/pom.xml";
    }

    private static void addRecommendations(List<String> out, java.util.Collection<UpgradeRecommendation> values) {
        List<UpgradeRecommendation> recs = new ArrayList<>(values);
        recs.sort(Comparator.comparing((UpgradeRecommendation r) -> key(r.coordinate())));
        for (UpgradeRecommendation r : recs) {
            out.add(String.format("  %-60s %s -> %s  [%s, %s risk]", key(r.coordinate()), r.currentVersion(),
                    r.targetVersion(), r.reason(), r.riskLevel()));
        }
    }

    /** A recommendation worth listing: the dependency is declared directly, or it is vulnerability-driven. */
    static boolean isActionable(UpgradeRecommendation r, boolean direct) {
        if (direct) return true;
        return isVulnerabilityDriven(r);
    }

    private static boolean isVulnerabilityDriven(UpgradeRecommendation r) {
        return switch (r.reason()) {
            case CVE_FIX, CVE_FIX_DOWNGRADE, CVE_BEST_EFFORT -> true;
            default -> false;
        };
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
