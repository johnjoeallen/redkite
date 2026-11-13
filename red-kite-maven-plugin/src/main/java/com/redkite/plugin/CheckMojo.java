package com.redkite.plugin;

import com.redkite.core.domain.AdvisorySeverity;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.VulnerabilityFinding;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.server.ReportExporter;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;

/** Writes the report like {@code report}, then fails the build when a configured threshold is crossed. */
@Mojo(name = "check", aggregator = true, defaultPhase = LifecyclePhase.VERIFY, requiresProject = true,
        requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class CheckMojo extends AbstractRedKiteMojo {

    /** Fail when any vulnerability is at or above this severity: NONE disables the check;
     *  otherwise LOW, MEDIUM, HIGH or CRITICAL. */
    @Parameter(property = "redkite.failOnSeverity", defaultValue = "HIGH")
    String failOnSeverity;

    /** Fail when the project depends on a SNAPSHOT artifact. */
    @Parameter(property = "redkite.failOnSnapshot", defaultValue = "false")
    boolean failOnSnapshot;

    /** Fail when the analysis could not complete (metadata unavailable, build failure). */
    @Parameter(property = "redkite.failOnIncomplete", defaultValue = "false")
    boolean failOnIncomplete;

    @Override
    void execute(ReportExporter.Result result) throws MojoFailureException {
        List<String> problems = evaluate(result.report(), failOnSeverity, failOnSnapshot, failOnIncomplete);
        if (!problems.isEmpty()) {
            problems.forEach(p -> getLog().error("RedKite: " + p));
            throw new MojoFailureException("RedKite check failed: " + String.join("; ", problems));
        }
        getLog().info("RedKite check passed.");
    }

    static List<String> evaluate(ScanReport report, String failOnSeverity, boolean failOnSnapshot, boolean failOnIncomplete) {
        List<String> problems = new ArrayList<>();
        AdvisorySeverity threshold = AdvisorySeverity.fromString(failOnSeverity);
        if (threshold != AdvisorySeverity.NONE && threshold != AdvisorySeverity.UNKNOWN) {
            for (VulnerabilityFinding f : report.vulnerabilityFindings()) {
                if (AdvisoryClassifier.severity(f).ordinal() >= threshold.ordinal()) {
                    problems.add(f.advisoryId() + " (" + AdvisoryClassifier.severity(f).label() + ") in "
                            + f.coordinate().groupId() + ":" + f.coordinate().artifactId() + ":" + f.affectedVersion()
                            + (f.fixedVersion() != null && !f.fixedVersion().isBlank() ? ", fixed in " + f.fixedVersion() : ""));
                }
            }
        }
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
        return problems;
    }
}
