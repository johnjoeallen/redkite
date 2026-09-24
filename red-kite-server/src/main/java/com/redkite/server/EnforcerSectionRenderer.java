package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.maven.ManagedVersionResolver;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.redkite.server.Json.*;
import static com.redkite.server.Html.*;
import static com.redkite.server.PomXml.*;

/** The dependency-management (enforcer) section of an analysis page. */
final class EnforcerSectionRenderer {
    private final Store store;
    private final EnforcerAnalysis analysis;

    EnforcerSectionRenderer(Store store, EnforcerAnalysis analysis) {
        this.store = store;
        this.analysis = analysis;
    }

    String renderEnforcerSection(String scanId, Store.EnforcerResultEntry entry) {
        StringBuilder html = new StringBuilder();
        html.append("<h2 style=\"font-size:1rem;margin:0 0 12px\">Dependency management</h2>");

        EnforcerStatus status = entry.status();
        if (status == EnforcerStatus.ENFORCER_CONFIGURED_NO_CONVERGENCE_RULES) {
            html.append("<p class=\"muted\">Enforcer plugin detected but no <code>dependencyConvergence</code> or <code>requireUpperBoundDeps</code> rules configured.</p>");
            return html.toString();
        }
        if (status == EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE) {
            if (entry.rawOutput() == null || entry.rawOutput().isBlank()) {
                html.append("<p class=\"muted\">Could not start Maven &mdash; ensure <code>mvn</code> is on PATH.</p>");
            } else {
                html.append("<p class=\"muted\">Dependency check ran (via <code>mvn verify</code> fallback) but produced no parseable conflict output. ")
                   .append("Check the analysis log for the full Maven output.</p>");
            }
            return html.toString();
        }
        if (status == EnforcerStatus.ENFORCER_RUN_PASSED) {
            html.append("<p><span class=\"badge success\">Passed</span> No dependency conflicts found");
            int exStrippedP = entry.exclusionsStripped();
            int dmRemovedP = entry.depMgmtRemoved().size();
            if (exStrippedP > 0 || dmRemovedP > 0) {
                html.append(" &mdash; pristine analysis ran with ");
                if (dmRemovedP > 0) html.append(dmRemovedP).append(" dep-management entr").append(dmRemovedP == 1 ? "y" : "ies").append(" removed");
                if (dmRemovedP > 0 && exStrippedP > 0) html.append(" and ");
                if (exStrippedP > 0) html.append(exStrippedP).append(" exclusion").append(exStrippedP == 1 ? "" : "s").append(" stripped");
                html.append(". Existing fixes may be stale.");
            } else {
                html.append(".");
            }
            html.append("</p>");
            return html.toString();
        }

        List<TransitiveConflictFinding> findings = entry.findings();
        if (findings.isEmpty()) {
            html.append("<p class=\"muted\">Enforcer reported failures but no structured findings could be extracted. Check the analysis log for details.</p>");
            return html.toString();
        }

        html.append("<p><span class=\"badge\" style=\"background:rgba(220,38,38,.16);border-color:rgba(220,38,38,.4);color:#fca5a5\">")
            .append(findings.size()).append(" conflict").append(findings.size() == 1 ? "" : "s").append("</span>");

        List<TransitiveConflictFinding> phase2 = entry.phase2Findings();
        if (phase2 != null) {
            if (phase2.isEmpty()) {
                html.append(" &nbsp;<span class=\"badge success\" style=\"font-size:.8rem\">Auto-fix verified</span>");
            } else {
                html.append(" &nbsp;<span class=\"badge\" style=\"font-size:.8rem;background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.4);color:#fde68a\">")
                    .append(phase2.size()).append(" unresolvable").append("</span>");
            }
        }
        html.append(" &nbsp;<span class=\"muted\" style=\"font-size:.85rem\">The matching dependency picker below includes the conflicting versions inline.</span></p>");

        // Pristine analysis summary
        int exStripped = entry.exclusionsStripped();
        int dmRemoved = entry.depMgmtRemoved().size();
        if (exStripped > 0 || dmRemoved > 0) {
            html.append("<p style=\"font-size:.82rem;color:var(--muted);margin:4px 0 12px\">Pristine analysis:");
            if (exStripped > 0) {
                html.append(" ").append(exStripped).append(" exclusion").append(exStripped == 1 ? "" : "s").append(" stripped");
            }
            if (exStripped > 0 && dmRemoved > 0) html.append(" &middot;");
            if (dmRemoved > 0) {
                html.append(" ").append(dmRemoved).append(" dep-management entr").append(dmRemoved == 1 ? "y" : "ies").append(" removed");
            }
            html.append("</p>");
        }

        // Auto-fix pin list — from stored Phase 2 computed pins, or derived from Phase 1 findings
        List<String> phase2Pins = entry.phase2Pins();
        if (!phase2Pins.isEmpty() || !findings.isEmpty()) {
            ScanEntry scanEntry = store.getScan(scanId);
            List<ScanComponent> scanComponents = scanEntry.report().components();
            Path projectRoot = Path.of(scanEntry.input().workingTreePath());
            Map<String, ManagedVersionResolver.ManagedVersion> declared =
                    analysis.resolveProjectManagedVersions(projectRoot, projectRoot.resolve("pom.xml"), rootPomXml(store.loadSourcePoms(scanId)));
            if (phase2Pins.isEmpty() && !findings.isEmpty()) {
                // Phase 2 hasn't run or data predates this feature — compute planned pins for display
                phase2Pins = analysis.computePlannedPins(findings, scanComponents, projectRoot, declared);
            } else {
                // Stored pins may predate family alignment or its fixes — never trust them verbatim
                phase2Pins = analysis.realignStoredPins(phase2Pins, scanComponents, projectRoot, declared);
            }
        }
        if (!phase2Pins.isEmpty()) {
            Set<String> stillFailing = new java.util.HashSet<>();
            if (phase2 != null) {
                for (TransitiveConflictFinding f : phase2) stillFailing.add(f.groupId() + ":" + f.artifactId());
            }
            // Build JSON array of {groupId,artifactId,version} for the apply button
            StringBuilder pinsJson = new StringBuilder("[");
            boolean firstPin = true;
            for (String gav : phase2Pins) {
                int last = gav.lastIndexOf(':');
                if (last <= 0) continue;
                String ga = gav.substring(0, last);
                String ver = gav.substring(last + 1);
                int colon = ga.indexOf(':');
                if (colon <= 0) continue;
                String g = ga.substring(0, colon), a = ga.substring(colon + 1);
                if (!firstPin) pinsJson.append(",");
                firstPin = false;
                pinsJson.append("{\"groupId\":").append(jsonStr(g))
                        .append(",\"artifactId\":").append(jsonStr(a))
                        .append(",\"version\":").append(jsonStr(ver)).append("}");
            }
            pinsJson.append("]");
            html.append("<div style=\"margin-top:14px;padding:12px 14px;border:1px solid rgba(75,85,99,.35);border-radius:10px;background:rgba(75,85,99,.06)\">");
            html.append("<div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:8px\">");
            html.append("<div style=\"font-size:.82rem;font-weight:600;color:var(--muted)\">Auto-fix &mdash; computed dep-management pins</div>");
            html.append("<button class=\"button primary\" type=\"button\" onclick=\"applyPhase2Pins(rk_scanId,")
                    .append(pinsJson.toString().replace("\"", "&quot;")).append(",this)\">Apply</button>");
            html.append("</div>");
            html.append("<div style=\"display:flex;flex-direction:column;gap:4px\">");
            for (String gav : phase2Pins) {
                int last = gav.lastIndexOf(':');
                String ga = last > 0 ? gav.substring(0, last) : gav;
                String version = last > 0 ? gav.substring(last + 1) : "?";
                boolean resolved = !stillFailing.contains(ga);
                html.append("<div style=\"font-size:.8rem;display:flex;align-items:baseline;gap:6px\">")
                    .append("<span style=\"color:").append(resolved ? "#6ee7b7" : "#e05050").append("\">")
                    .append(resolved ? "&#10003;" : "&#9888;").append("</span>")
                    .append("<code style=\"font-size:.78rem\">").append(escape(ga)).append("</code>")
                    .append("<span style=\"color:var(--muted)\">&rarr;</span>")
                    .append("<code style=\"font-size:.78rem\">").append(escape(version)).append("</code>")
                    .append("</div>");
            }
            html.append("</div></div>");
        }

        html.append("<div id=\"enforcer-apply-msg\" style=\"display:none;margin-bottom:12px\" class=\"badge success\">Applied - re-analyse to verify.</div>");

        List<String> staleExclusions = entry.staleExclusions();
        if (!staleExclusions.isEmpty()) {
            html.append("<div style=\"margin-top:18px;padding:14px 16px;border:1px solid rgba(75,85,99,.4);border-radius:12px;background:rgba(75,85,99,.08)\">");
            html.append("<div style=\"font-size:.85rem;font-weight:600;color:var(--muted);margin-bottom:8px\">")
                .append(staleExclusions.size()).append(" stale exclusion").append(staleExclusions.size() == 1 ? "" : "s")
                .append(" &mdash; no longer resolving any conflict</div>");
            html.append("<div style=\"display:flex;flex-wrap:wrap;gap:6px\">");
            for (String ga : staleExclusions) {
                html.append("<code style=\"font-size:.8rem;padding:2px 8px;border-radius:6px;background:rgba(0,0,0,.2)\">")
                    .append(escape(ga)).append("</code>");
            }
            html.append("</div>");
            html.append("</div>");
        }

        return html.toString();
    }
}
