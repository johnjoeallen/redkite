package com.redkite.plugin;

import com.redkite.core.domain.AdvisorySeverity;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.VulnerabilityFinding;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.server.ReportExporter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;

/**
 * Prints the report, then fails the build only for vulnerabilities a developer can act on: a
 * dependency with a vulnerability at or above {@code failOnSeverity} fails the build when another
 * version on the same major line (newer or older) has nothing at or above that level. A
 * vulnerability with no such alternative is reported as a warning and never fails the build, so
 * the goal can stay bound to every build.
 */
@Mojo(name = "check", aggregator = true, defaultPhase = LifecyclePhase.VERIFY, requiresProject = true,
        requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class CheckMojo extends AbstractRedKiteMojo {

    /** Vulnerabilities at or above this severity count: LOW, MEDIUM, HIGH or CRITICAL. NONE disables the check. */
    @Parameter(property = "redkite.failOnSeverity", defaultValue = "HIGH")
    String failOnSeverity;

    /**
     * Also fail for a vulnerability at or above this severity when no version on the same major line improves
     * on the current one, so there is nothing to upgrade to. Such a finding normally only warns. It passes only
     * if it is covered by an unexpired {@code acceptedRisks} entry. NONE (the default) never fails for this.
     */
    @Parameter(property = "redkite.failOnUnfixable", defaultValue = "NONE")
    String failOnUnfixable;

    /** Fail when the project depends on a SNAPSHOT artifact. */
    @Parameter(property = "redkite.failOnSnapshot", defaultValue = "false")
    boolean failOnSnapshot;

    /** Fail when the analysis could not complete (metadata unavailable, build failure). */
    @Parameter(property = "redkite.failOnIncomplete", defaultValue = "false")
    boolean failOnIncomplete;

    /** What a check found: {@code problems} fail the build, {@code warnings} are logged only. */
    record Outcome(List<String> problems, List<String> warnings) {}

    @Override
    void execute(ReportExporter.Result result) throws MojoFailureException {
        Outcome outcome = evaluate(result.report(), result.remediations(), failOnSeverity, failOnUnfixable, failOnSnapshot, failOnIncomplete);
        outcome.warnings().forEach(w -> getLog().warn("RedKite: " + w));
        if (!outcome.problems().isEmpty()) {
            outcome.problems().forEach(p -> getLog().error("RedKite: " + p));
            throw new MojoFailureException("RedKite check failed: " + String.join("; ", outcome.problems()));
        }
        getLog().info("RedKite check passed.");
    }

    static Outcome evaluate(ScanReport report, List<ReportExporter.Remediation> remediations, String failOnSeverity,
                            boolean failOnSnapshot, boolean failOnIncomplete) {
        return evaluate(report, remediations, failOnSeverity, "NONE", failOnSnapshot, failOnIncomplete);
    }

    static Outcome evaluate(ScanReport report, List<ReportExporter.Remediation> remediations, String failOnSeverity,
                            String failOnUnfixable, boolean failOnSnapshot, boolean failOnIncomplete) {
        List<String> problems = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Map<String, String> unfixable = unfixable(report, remediations, AdvisorySeverity.fromString(failOnUnfixable));
        AdvisorySeverity threshold = AdvisorySeverity.fromString(failOnSeverity);
        if (threshold != AdvisorySeverity.NONE && threshold != AdvisorySeverity.UNKNOWN) {
            // Group the over-threshold advisories by the dependency version that carries them.
            Map<String, Set<String>> advisoriesByComponent = new LinkedHashMap<>();
            Map<String, AdvisorySeverity> worstByComponent = new LinkedHashMap<>();
            for (VulnerabilityFinding f : report.vulnerabilityFindings()) {
                AdvisorySeverity severity = AdvisoryClassifier.severity(f);
                if (severity.ordinal() < threshold.ordinal()) continue;
                String key = f.coordinate().groupId() + ":" + f.coordinate().artifactId() + ":" + f.affectedVersion();
                advisoriesByComponent.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(f.advisoryId());
                worstByComponent.merge(key, severity, AdvisorySeverity::max);
            }
            for (Map.Entry<String, Set<String>> e : advisoriesByComponent.entrySet()) {
                String key = e.getKey();
                String what = key + " has " + worstByComponent.get(key).label() + " vulnerabilities ("
                        + String.join(", ", e.getValue()) + ")";
                ReportExporter.Remediation fix = remediations.stream()
                        .filter(r -> (r.groupId() + ":" + r.artifactId() + ":" + r.currentVersion()).equals(key))
                        .filter(r -> r.sameMajor() && r.residualSeverity().ordinal() < threshold.ordinal())
                        .findFirst().orElse(null);
                if (fix != null) {
                    problems.add(what + "; " + (compare(fix.targetVersion(), fix.currentVersion()) < 0 ? "downgrade" : "upgrade")
                            + " to " + fix.targetVersion() + " leaves nothing at or above " + threshold.label());
                } else if (unfixable.containsKey(key)) {
                    problems.add(unfixable.remove(key));
                } else {
                    warnings.add(what + "; no version on the same major line is below " + threshold.label() + ", so this does not fail the build");
                }
            }
        }
        // Unfixable findings below failOnSeverity, or on components the pass above did not reach.
        problems.addAll(unfixable.values());
        if (failOnSnapshot) {
            for (ScanComponent c : report.components()) {
                if (c.snapshot()) {
                    problems.add("SNAPSHOT dependency " + c.coordinate().groupId() + ":" + c.coordinate().artifactId() + ":" + c.version());
                }
            }
        }
        if (failOnIncomplete && !report.complete()) {
            problems.add("analysis incomplete: " + report.completenessMessage());
        }
        return new Outcome(problems, warnings);
    }

    /**
     * The components with a vulnerability at or above {@code threshold} for which no same-major version
     * has a lower worst severity, keyed by {@code groupId:artifactId:version}, with the failure message.
     */
    private static Map<String, String> unfixable(ScanReport report, List<ReportExporter.Remediation> remediations,
                                                 AdvisorySeverity threshold) {
        Map<String, String> out = new LinkedHashMap<>();
        if (threshold == AdvisorySeverity.NONE || threshold == AdvisorySeverity.UNKNOWN) return out;
        Map<String, Set<String>> advisories = new LinkedHashMap<>();
        Map<String, AdvisorySeverity> worst = new LinkedHashMap<>();
        for (VulnerabilityFinding f : report.vulnerabilityFindings()) {
            AdvisorySeverity severity = AdvisoryClassifier.severity(f);
            String key = f.coordinate().groupId() + ":" + f.coordinate().artifactId() + ":" + f.affectedVersion();
            worst.merge(key, severity, AdvisorySeverity::max);
            if (severity.ordinal() >= threshold.ordinal()) advisories.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(f.advisoryId());
        }
        for (Map.Entry<String, Set<String>> e : advisories.entrySet()) {
            String key = e.getKey();
            AdvisorySeverity w = worst.get(key);
            boolean improvable = remediations.stream()
                    .filter(r -> (r.groupId() + ":" + r.artifactId() + ":" + r.currentVersion()).equals(key))
                    .anyMatch(r -> r.sameMajor() && r.residualSeverity().ordinal() < w.ordinal());
            if (!improvable) {
                out.put(key, key + " has " + w.label() + " vulnerabilities (" + String.join(", ", e.getValue())
                        + ") and no version on the same major line is better, so it cannot be fixed by upgrading; "
                        + "fix it another way, or accept it for now with <acceptedRisks> (advisory, reason, until)");
            }
        }
        return out;
    }

    /** Orders dotted versions numerically segment by segment; only used to word the message. */
    private static int compare(String a, String b) {
        String[] x = a.split("[.\\-]"), y = b.split("[.\\-]");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            long p = i < x.length ? num(x[i]) : 0, q = i < y.length ? num(y[i]) : 0;
            if (p != q) return Long.compare(p, q);
        }
        return 0;
    }

    private static long num(String s) {
        try { return Long.parseLong(s); } catch (NumberFormatException e) { return 0; }
    }
}
