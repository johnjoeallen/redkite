package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.maven.ManagedVersionResolver;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.redkite.server.Html.*;
import static com.redkite.server.PomXml.*;
import static com.redkite.server.ScanPageRenderer.*;

/** The analysis log dialog: completeness, metadata issues, parse warnings and enforcer details. */
final class LogModalRenderer {
    private final Store store;
    private final EnforcerAnalysis analysis;

    LogModalRenderer(Store store, EnforcerAnalysis analysis) {
        this.store = store;
        this.analysis = analysis;
    }

    String renderLogModal(ScanReport report, String scanId, Store.EnforcerResultEntry enforcerResult) {
        Map<Long, ScanComponent> byId = new LinkedHashMap<>();
        for (ScanComponent c : report.components()) byId.put(c.id(), c);

        List<String> parseWarnings = report.treeParseWarnings() != null ? report.treeParseWarnings() : List.of();
        List<MetadataResult> issues = new ArrayList<>();
        for (MetadataResult r : report.metadataResults()) {
            if (!r.complete() || (r.status() != MetadataStatus.FRESH && r.status() != MetadataStatus.NOT_APPLICABLE)) {
                issues.add(r);
            }
        }

        StringBuilder html = new StringBuilder();
        html.append("<div id=\"log-modal\" class=\"pom-modal\" style=\"display:none\">");
        html.append("<div class=\"pom-modal-backdrop\" onclick=\"closeLogModal()\"></div>");
        html.append("<div class=\"pom-modal-box log-modal-box\">");
        html.append("<div class=\"pom-modal-head\">");
        html.append("<span class=\"pom-modal-filename\">Analysis log</span>");
        html.append("<button class=\"button\" type=\"button\" onclick=\"closeLogModal()\">Close</button>");
        html.append("</div>");
        html.append("<div class=\"log-body\">");

        // Overview
        html.append("<div class=\"log-section\">");
        html.append("<div class=\"log-section-title\">Overview</div>");
        boolean buildFailed = isBuildFailed(report);
        html.append("<div style=\"display:flex;align-items:center;gap:10px;margin-bottom:10px\">");
        html.append(report.complete() ? "<span class=\"badge success\">Complete</span>"
                : buildFailed ? "<span class=\"badge\" style=\"background:rgba(220,38,38,.16);border-color:rgba(220,38,38,.4);color:#fca5a5\">Failed</span>"
                : "<span class=\"badge warn\">Incomplete</span>");
        html.append("</div>");
        html.append("<p class=\"log-text\">").append(escape(report.completenessMessage())).append("</p>");
        if (report.createdAt() != null) {
            html.append("<p class=\"log-meta-text\">Analysed: ").append(escape(report.createdAt().toString())).append("</p>");
        }
        html.append("</div>");

        // Dependency tree warnings
        if (!parseWarnings.isEmpty()) {
            html.append("<div class=\"log-section log-section-warn\">");
            if (buildFailed) {
                html.append("<div class=\"log-section-title\" style=\"color:#e05050\">&#10005; Build failure &nbsp;<span class=\"tab-count\">").append(parseWarnings.size() - 1).append(" error(s)</span></div>");
                html.append("<p class=\"log-text\">Maven could not resolve the project model. Fix the errors below and rescan.</p>");
            } else {
                html.append("<div class=\"log-section-title log-title-warn\">&#9888; Dependency tree issues &nbsp;<span class=\"tab-count\">").append(parseWarnings.size()).append("</span></div>");
                html.append("<p class=\"log-text\">Lines returned by <code>mvn dependency:tree</code> that could not be parsed as valid coordinates. Fix the underlying POM issues and rescan.</p>");
            }
            html.append("<div class=\"log-code-list\">");
            for (String line : parseWarnings) {
                String display = line.startsWith("[BUILD_FAILED] ") ? line.substring(15) : line;
                html.append("<div class=\"log-code-line\">").append(escape(display)).append("</div>");
            }
            html.append("</div>");
            html.append("</div>");
        }

        // Metadata issues
        if (!issues.isEmpty()) {
            html.append("<div class=\"log-section\">");
            html.append("<div class=\"log-section-title\">Metadata issues &nbsp;<span class=\"tab-count\">").append(issues.size()).append("</span></div>");
            html.append("<div class=\"log-issue-list\">");
            for (MetadataResult r : issues) {
                ScanComponent comp = byId.get(r.componentId());
                String name = comp != null
                        ? comp.coordinate().groupId() + ":" + comp.coordinate().artifactId()
                        : "component #" + r.componentId();
                String statusStr = r.status().name().toLowerCase().replace('_', ' ');
                String cacheStr = r.cacheState().name().toLowerCase().replace('_', ' ');
                boolean isError = r.status() == MetadataStatus.RATE_LIMITED || r.status() == MetadataStatus.PROVIDER_ERROR
                        || r.status() == MetadataStatus.OFFLINE_MISSING || r.status() == MetadataStatus.MISSING;
                html.append("<div class=\"log-issue-row\">");
                html.append("<div class=\"log-issue-name\">").append(escape(name)).append("</div>");
                html.append("<div class=\"log-issue-badges\">");
                html.append("<span class=\"badge ").append(isError ? "warn" : "neutral").append("\">").append(escape(statusStr)).append("</span>");
                html.append("<span class=\"badge neutral\">cache: ").append(escape(cacheStr)).append("</span>");
                html.append("</div>");
                if (r.message() != null && !r.message().isBlank()) {
                    html.append("<div class=\"log-issue-msg\">").append(escape(r.message())).append("</div>");
                }
                html.append("</div>");
            }
            html.append("</div>");
            html.append("</div>");
        }

        if (report.complete() && parseWarnings.isEmpty() && issues.isEmpty()) {
            html.append("<div class=\"log-section\">");
            html.append("<p class=\"log-text\">No issues. All metadata resolved successfully.</p>");
            html.append("</div>");
        }

        // Dependency management
        if (enforcerResult != null && enforcerResult.status() != EnforcerStatus.ENFORCER_NOT_CONFIGURED) {
            html.append("<div class=\"log-section\">");
            if (enforcerResult.status() == EnforcerStatus.ENFORCER_RUN_PASSED) {
                html.append("<div class=\"log-section-title\">Dependency management</div>");
                html.append("<p class=\"log-text\">All enforcer rules passed. No conflicts detected.</p>");
            } else if (enforcerResult.status() == EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS) {
                List<TransitiveConflictFinding> findings = enforcerResult.findings();
                html.append("<div class=\"log-section-title\" style=\"color:#e05050\">&#10005; Dependency management &nbsp;<span class=\"tab-count\">")
                    .append(findings.size()).append(" conflict").append(findings.size() == 1 ? "" : "s").append("</span></div>");
                html.append("<p class=\"log-text\">Conflict details are shown inline on the affected dependency pickers below.</p>");
            } else {
                html.append("<div class=\"log-section-title\">Dependency management</div>");
                html.append("<p class=\"log-text\">Dependency management check could not run &mdash; ensure Maven is on PATH.</p>");
            }

            // Pristine analysis metadata
            int exStripped = enforcerResult.exclusionsStripped();
            List<String> depMgmtRemoved = enforcerResult.depMgmtRemoved();
            if (exStripped > 0 || !depMgmtRemoved.isEmpty()) {
                html.append("<p class=\"log-text\" style=\"margin-top:12px;font-weight:600\">Pristine analysis changes</p>");
                if (exStripped > 0) {
                    html.append("<p class=\"log-text\">&#10003; ").append(exStripped)
                        .append(" exclusion").append(exStripped == 1 ? "" : "s").append(" stripped across all POMs</p>");
                }
                if (!depMgmtRemoved.isEmpty()) {
                    html.append("<p class=\"log-text\">Dep-management cleared (").append(depMgmtRemoved.size())
                        .append(" entr").append(depMgmtRemoved.size() == 1 ? "y" : "ies").append("):</p>");
                    html.append("<div class=\"log-code-list\">");
                    for (String gav : depMgmtRemoved) {
                        html.append("<div class=\"log-code-line\">- ").append(escape(gav)).append("</div>");
                    }
                    html.append("</div>");
                }
            }

            // Auto-fix verification summary with diff against original dep management
            List<TransitiveConflictFinding> phase2 = enforcerResult.phase2Findings();
            List<String> phase2Pins = enforcerResult.phase2Pins();
            if (!phase2Pins.isEmpty() || !enforcerResult.findings().isEmpty()) {
                Path projectRoot = Path.of(store.getScan(scanId).input().workingTreePath());
                Map<String, ManagedVersionResolver.ManagedVersion> declared =
                        analysis.resolveProjectManagedVersions(projectRoot, projectRoot.resolve("pom.xml"), rootPomXml(store.loadSourcePoms(scanId)));
                if (phase2Pins.isEmpty() && !enforcerResult.findings().isEmpty()) {
                    phase2Pins = analysis.computePlannedPins(enforcerResult.findings(), report.components(), projectRoot, declared);
                } else {
                    // Stored pins may predate family alignment or its fixes — never trust them verbatim
                    phase2Pins = analysis.realignStoredPins(phase2Pins, report.components(), projectRoot, declared);
                }
            }
            if (!phase2Pins.isEmpty()) {
                java.util.Set<String> stillFailing = new java.util.HashSet<>();
                if (phase2 != null) {
                    for (TransitiveConflictFinding f : phase2) stillFailing.add(f.groupId() + ":" + f.artifactId());
                }
                // Build original dep-management map for diff (G:A → V)
                Map<String, String> originalPins = new LinkedHashMap<>();
                for (String gav : depMgmtRemoved) {
                    int last = gav.lastIndexOf(':');
                    if (last > 0) originalPins.put(gav.substring(0, last), gav.substring(last + 1));
                }
                html.append("<p class=\"log-text\" style=\"margin-top:12px;font-weight:600\">Auto-fix: computed dep-management pins</p>");
                html.append("<div class=\"log-code-list\">");
                java.util.Set<String> computedGAs = new java.util.LinkedHashSet<>();
                for (String gav : phase2Pins) {
                    int last = gav.lastIndexOf(':');
                    String ga = last > 0 ? gav.substring(0, last) : gav;
                    String version = last > 0 ? gav.substring(last + 1) : "?";
                    computedGAs.add(ga);
                    boolean resolved = !stillFailing.contains(ga);
                    String origV = originalPins.get(ga);
                    String diffNote = origV == null ? " <span style=\"color:var(--muted)\">(new)</span>"
                            : origV.equals(version) ? " <span style=\"color:#6ee7b7\">(same as before)</span>"
                            : " <span style=\"color:#fde68a\">was " + escape(origV) + "</span>";
                    html.append("<div class=\"log-code-line\">")
                        .append(resolved ? "&#10003; " : "&#9888; ")
                        .append(escape(ga)).append(" &rarr; ").append(escape(version))
                        .append(diffNote)
                        .append(resolved ? "" : " <span style=\"color:#e05050\">(still failing)</span>")
                        .append("</div>");
                }
                // Show original entries that have no corresponding computed pin (no longer needed)
                for (Map.Entry<String, String> orig : originalPins.entrySet()) {
                    if (!computedGAs.contains(orig.getKey())) {
                        html.append("<div class=\"log-code-line\" style=\"color:var(--muted)\">&#8722; ")
                            .append(escape(orig.getKey())).append(":").append(escape(orig.getValue()))
                            .append(" <span>(no longer needed)</span></div>");
                    }
                }
                html.append("</div>");
            }

            if (!enforcerResult.staleExclusions().isEmpty()) {
                List<String> stale = enforcerResult.staleExclusions();
                html.append("<p class=\"log-text\" style=\"margin-top:12px;color:var(--muted)\">")
                    .append(stale.size()).append(" stale exclusion").append(stale.size() == 1 ? "" : "s")
                    .append(" (no longer resolving any conflict):</p>");
                html.append("<div class=\"log-code-list\">");
                for (String ga : stale) {
                    html.append("<div class=\"log-code-line\">").append(escape(ga)).append("</div>");
                }
                html.append("</div>");
            }
            html.append("</div>");
        }

        // Maven repositories
        html.append("<div class=\"log-section\">");
        html.append("<div class=\"log-section-title\">Maven repositories</div>");
        if (store.mavenSettingsPath != null) {
            html.append("<p class=\"log-meta-text\">Settings: <code>").append(escape(store.mavenSettingsPath)).append("</code></p>");
        }
        html.append("<div class=\"log-code-list\">");
        for (String repo : store.effectiveMavenRepos) {
            html.append("<div class=\"log-code-line\">").append(escape(repo)).append("</div>");
        }
        html.append("</div>");
        html.append("</div>");

        html.append("</div>"); // log-body
        html.append("</div>"); // pom-modal-box
        html.append("</div>"); // log-modal
        return html.toString();
    }
}
