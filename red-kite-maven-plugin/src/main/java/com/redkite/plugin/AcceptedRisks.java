package com.redkite.plugin;

import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.VulnerabilityFinding;
import com.redkite.server.ReportExporter;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Splits a scan's vulnerabilities into those still to be dealt with and those the project has accepted. */
final class AcceptedRisks {
    private AcceptedRisks() {}

    /** A finding together with the accepted risk that covers it and the day that acceptance ends. */
    record Entry(VulnerabilityFinding finding, AcceptedRisk risk, LocalDate until) {}

    /**
     * @param active     findings to report and act on: not accepted, or accepted but expired
     * @param accepted   findings covered by an unexpired accepted risk
     * @param expired    findings whose accepted risk has run out; also in {@code active}
     * @param unmatched  accepted risks that match no finding, which can be removed
     * @param covered    {@code groupId:artifactId:version} of components whose every finding is accepted
     */
    record Result(List<VulnerabilityFinding> active, List<Entry> accepted, List<Entry> expired,
                  List<AcceptedRisk> unmatched, Set<String> covered) {
        boolean isEmpty() {
            return accepted.isEmpty() && expired.isEmpty();
        }
    }

    /** Problems with the configuration, empty when it is usable. */
    static List<String> validate(List<AcceptedRisk> risks) {
        List<String> problems = new ArrayList<>();
        if (risks == null) return problems;
        for (AcceptedRisk r : risks) {
            String who = r == null ? "an entry" : "'" + r + "'";
            if (r == null || blank(r.advisory)) {
                problems.add("acceptedRisk " + who + " has no <advisory>");
                continue;
            }
            if (blank(r.until)) {
                problems.add("acceptedRisk " + who + " has no <until> date; set the last day (yyyy-MM-dd) the risk is accepted");
            } else if (parse(r.until) == null) {
                problems.add("acceptedRisk " + who + " has an invalid <until> date '" + r.until + "'; use yyyy-MM-dd");
            }
            if (!blank(r.coordinate) && r.coordinate.split(":", -1).length < 2) {
                problems.add("acceptedRisk " + who + " has an invalid <coordinate> '" + r.coordinate
                        + "'; use groupId:artifactId or groupId:artifactId:version");
            }
        }
        return problems;
    }

    static Result apply(ScanReport report, List<AcceptedRisk> risks, LocalDate today) {
        List<VulnerabilityFinding> active = new ArrayList<>();
        Map<String, Entry> accepted = new LinkedHashMap<>();
        Map<String, Entry> expired = new LinkedHashMap<>();
        Set<AcceptedRisk> used = new LinkedHashSet<>();
        Set<String> withAccepted = new LinkedHashSet<>();
        Set<String> withActive = new LinkedHashSet<>();
        for (VulnerabilityFinding f : report.vulnerabilityFindings()) {
            String component = component(f);
            AcceptedRisk match = risks == null ? null : risks.stream().filter(r -> r != null && covers(r, f)).findFirst().orElse(null);
            LocalDate until = match == null ? null : parse(match.until);
            if (match != null && until != null) used.add(match);
            String id = component + ":" + f.advisoryId();
            if (match != null && until != null && !today.isAfter(until)) {
                accepted.putIfAbsent(id, new Entry(f, match, until));
                withAccepted.add(component);
            } else {
                active.add(f);
                withActive.add(component);
                if (match != null && until != null) expired.putIfAbsent(id, new Entry(f, match, until));
            }
        }
        Set<String> covered = new LinkedHashSet<>(withAccepted);
        covered.removeAll(withActive);
        List<AcceptedRisk> unmatched = new ArrayList<>();
        if (risks != null) {
            for (AcceptedRisk r : risks) if (r != null && !used.contains(r)) unmatched.add(r);
        }
        return new Result(active, new ArrayList<>(accepted.values()), new ArrayList<>(expired.values()), unmatched, covered);
    }

    /**
     * The report as the rest of the goal should see it: only the active vulnerabilities, and no
     * recommendations for a dependency version whose every vulnerability is accepted, so neither
     * {@code check} nor the upgrade goals act on it.
     */
    static ReportExporter.Result filter(ReportExporter.Result result, Result split) {
        if (split.covered().isEmpty() && split.active().size() == result.report().vulnerabilityFindings().size()) return result;
        ScanReport r = result.report();
        List<UpgradeRecommendation> recs = r.recommendations().stream()
                .filter(u -> !split.covered().contains(u.coordinate().groupId() + ":" + u.coordinate().artifactId() + ":" + u.currentVersion()))
                .toList();
        ScanReport filtered = new ScanReport(r.scanId(), r.projectId(), r.complete(), r.completenessMessage(), r.createdAt(),
                r.components(), r.dependencyEdges(), split.active(), recs, r.snapshotDependencyRisks(),
                r.metadataResults(), r.treeParseWarnings());
        List<ReportExporter.Remediation> rem = result.remediations().stream()
                .filter(m -> !split.covered().contains(m.groupId() + ":" + m.artifactId() + ":" + m.currentVersion()))
                .toList();
        return new ReportExporter.Result(result.scanId(), filtered, rem);
    }

    private static boolean covers(AcceptedRisk r, VulnerabilityFinding f) {
        if (blank(r.advisory)) return false;
        boolean advisory = r.advisory.trim().equalsIgnoreCase(f.advisoryId())
                || f.cves().stream().anyMatch(c -> r.advisory.trim().equalsIgnoreCase(c));
        if (!advisory) return false;
        if (blank(r.coordinate)) return true;
        String[] p = r.coordinate.trim().split(":", -1);
        if (p.length < 2) return false;
        if (!p[0].equals(f.coordinate().groupId()) || !p[1].equals(f.coordinate().artifactId())) return false;
        return p.length < 3 || p[2].isBlank() || p[2].equals(f.affectedVersion());
    }

    private static String component(VulnerabilityFinding f) {
        return f.coordinate().groupId() + ":" + f.coordinate().artifactId() + ":" + f.affectedVersion();
    }

    private static LocalDate parse(String s) {
        if (blank(s)) return null;
        try {
            return LocalDate.parse(s.trim());
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }
}
