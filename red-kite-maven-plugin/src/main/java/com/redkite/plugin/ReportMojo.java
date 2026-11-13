package com.redkite.plugin;

import com.redkite.core.domain.AdvisorySeverity;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.core.domain.VulnerabilityFinding;
import com.redkite.server.ReportExporter;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;

/** Analyses the project and writes <code>redkite-report.html</code> and <code>.json</code>; never fails the build. */
@Mojo(name = "report", aggregator = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class ReportMojo extends AbstractRedKiteMojo {
    @Override
    void execute(ReportExporter.Result result) {
        long vulns = result.report().vulnerabilityFindings().size();
        AdvisorySeverity worst = AdvisorySeverity.NONE;
        for (VulnerabilityFinding f : result.report().vulnerabilityFindings()) {
            worst = worst.max(AdvisoryClassifier.severity(f));
        }
        getLog().info("RedKite: " + result.report().components().size() + " components, "
                + vulns + " vulnerabilities (worst: " + worst.label() + "), "
                + result.report().recommendations().size() + " recommendations");
    }
}
