package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.maven.MavenSettingsReader;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static com.redkite.server.Http.*;
import static com.redkite.server.Json.*;
import static com.redkite.server.Html.*;
import static com.redkite.server.PomXml.*;
import static com.redkite.server.ScanPageRenderer.*;

/** The dashboard, project and analysis pages. */
final class PageHandlers {
    private static final Logger LOGGER = Logger.getLogger(PageHandlers.class.getName());
    private final Store store;
    private final Pages pages;
    private final ScanPageRenderer scanPage;
    private final EnforcerSectionRenderer enforcerSection;
    private final LogModalRenderer logModal;

    PageHandlers(Store store, Pages pages, ScanPageRenderer scanPage, EnforcerSectionRenderer enforcerSection, LogModalRenderer logModal) {
        this.store = store;
        this.pages = pages;
        this.scanPage = scanPage;
        this.enforcerSection = enforcerSection;
        this.logModal = logModal;
    }

    void handleIndex(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        StringBuilder body = new StringBuilder();
        // Scan new project section
        body.append("<section class=\"card\" style=\"margin-bottom:18px\">");
        body.append("<h2>Analyse project</h2>");
        body.append("<div class=\"scan-path-row\">");
        body.append("<input id=\"scan-path\" class=\"scan-path-input\" type=\"text\" placeholder=\"/full/path/to/project\" autocomplete=\"off\" spellcheck=\"false\" onkeydown=\"if(event.key==='Enter')startScan()\"/>");
        body.append("<button class=\"button primary\" type=\"button\" onclick=\"startScan()\">Analyse</button>");
        body.append("</div>");
        body.append("<div id=\"scan-error\" class=\"scan-error\" style=\"display:none\"></div>");
        body.append("</section>");

        // Existing projects
        body.append("<section class=\"card\"><h2>Projects</h2><div class=\"list\">");
        try {
            for (ProjectEntry project : store.listProjects()) {
                body.append("<div class=\"list-row\">")
                        .append("<a href=\"/projects/").append(project.id()).append("\" class=\"list-row-link\">")
                        .append("<span class=\"list-title\">").append(escape(project.name())).append("</span>")
                        .append("<span class=\"list-meta\">").append(escape(project.rootPath())).append("</span>")
                        .append("</a>")
                        .append("<button class=\"button\" type=\"button\" onclick=\"triggerScan(").append(escape(jsString(project.rootPath()))).append(")\">Analyse</button>")
                        .append("</div>");
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "Unable to list projects for dashboard: " + e.getMessage());
            body.append("<div class=\"result-row\"><div><strong>No project data</strong><div class=\"muted\">")
                    .append(escape(e.getMessage()))
                    .append("</div></div><div class=\"badge warn\">database</div></div>");
        }
        body.append("</div></section>");

        // Blocking overlay shown during scan
        body.append(scanOverlayHtml());

        body.append("<script>");
        body.append("function startScan(){var path=document.getElementById('scan-path').value.trim();if(!path){showScanError('Enter the full path to the project.');return;}hideScanError();triggerScan(path);}");
        body.append("function showScanError(msg){var el=document.getElementById('scan-error');if(el){el.textContent=msg;el.style.display='block';}}");
        body.append("function hideScanError(){var el=document.getElementById('scan-error');if(el){el.textContent='';el.style.display='none';}}");
        body.append("</script>");

        sendHtml(exchange, 200, pages.renderPage("home", "Projects",
                "Local Maven dependency analysis, version checks, and upgrade planning.", body.toString()));
    }

    void handleHealth(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        sendText(exchange, 200, "ok");
    }

    void handleProjects(HttpExchange exchange) throws IOException {
        URI uri = exchange.getRequestURI();
        String[] parts = uri.getPath().split("/");
        if (parts.length == 3) {
            String projectId = parts[2];
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendText(exchange, 405, "Method not allowed");
                return;
            }
            ProjectEntry project = store.getProject(projectId);
            List<ScanEntry> scans = store.listScansForProject(projectId);
            ScanEntry latestScan = scans.isEmpty() ? null : scans.get(scans.size() - 1);
            java.nio.file.Path projectRoot = java.nio.file.Path.of(project.rootPath());
            java.nio.file.Path settingsPath = MavenSettingsReader.resolveSettingsFile(projectRoot);
            List<MavenSettingsReader.RepoConfig> repoConfigs = MavenSettingsReader.discoverRepositoryConfigs(projectRoot);
            java.time.format.DateTimeFormatter fmt = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(java.time.ZoneId.systemDefault());
            StringBuilder body = new StringBuilder();
            body.append("<div class=\"page-grid\">");

            // Header panel — name, path, scan button, settings, repos
            body.append("<section class=\"card span-2\">");
            body.append("<div style=\"display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap\">");
            body.append("<div><h1>").append(escape(project.name())).append("</h1>");
            body.append("<p class=\"muted\" style=\"margin:2px 0 0\">").append(escape(project.rootPath())).append("</p></div>");
            body.append("<div style=\"display:flex;gap:8px;flex-wrap:wrap\">");
            body.append("<button class=\"button primary\" type=\"button\" onclick=\"triggerScan(").append(escape(jsString(project.rootPath()))).append(")\">Analyse</button>");
            body.append("<button class=\"button danger\" type=\"button\" onclick=\"deleteProject(").append(escape(jsString(project.id()))).append(",").append(escape(jsString(project.name()))).append(")\">Delete project</button>");
            body.append("</div>");
            body.append("</div>");
            body.append("<div class=\"proj-meta\">");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Settings</span>");
            if (settingsPath != null) {
                body.append("<code class=\"proj-meta-val\">").append(escape(settingsPath.toAbsolutePath().toString())).append("</code>");
            } else {
                body.append("<span class=\"proj-meta-val muted\">none (using Maven Central)</span>");
            }
            body.append("</div>");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Repositories</span>");
            body.append("<div class=\"proj-meta-repos\">");
            for (MavenSettingsReader.RepoConfig repo : repoConfigs) {
                body.append("<code class=\"proj-meta-val\">").append(escape(repo.url())).append("</code>");
            }
            body.append("</div></div>");
            body.append("</div>");
            body.append("</section>");

            body.append(renderProjectConfigPanel(projectRoot));

            if (latestScan != null) {
                ScanReport report = latestScan.report();
                body.append("<section class=\"card\"><h2>Latest analysis</h2>");
                body.append("<p class=\"proj-meta-val muted\" style=\"margin-bottom:10px\">").append(fmt.format(latestScan.createdAt())).append("</p>");
                body.append(statGrid(
                        statCard("Components", String.valueOf(report.components().size())),
                        statCard("Recommendations", String.valueOf(report.recommendations().size())),
                        statCard("Status", report.complete() ? "Complete" : isBuildFailed(report) ? "Failed" : "Incomplete")));
                body.append("<p class=\"muted\">").append(escape(report.completenessMessage())).append("</p>");
                body.append("</section>");
            }
            body.append("<section class=\"card\"><h2>Analysis history</h2>");
            if (scans.isEmpty()) {
                body.append("<p class=\"muted\">No analyses yet.</p>");
            } else {
                List<String> scanIds = scans.stream().map(ScanEntry::id).toList();
                Map<String, Store.EnforcerResultEntry> enforcerResults = store.getEnforcerResults(scanIds);
                body.append("<div class=\"scan-history-list\">");
                for (int i = scans.size() - 1; i >= 0; i--) {
                    ScanEntry s = scans.get(i);
                    ScanReport r = s.report();
                    boolean failed = isBuildFailed(r);
                    String statusLabel = r.complete() ? "Complete" : failed ? "Failed" : "Incomplete";
                    String statusClass = r.complete() ? "success" : failed ? "scan-failed" : "warn";
                    body.append("<a class=\"scan-history-row\" href=\"/scans/").append(s.id()).append("\">");
                    body.append("<span class=\"scan-history-ts\">").append(fmt.format(s.createdAt())).append("</span>");
                    body.append("<div style=\"display:flex;gap:6px;align-items:center\">");
                    body.append("<span class=\"badge ").append(statusClass).append("\">").append(statusLabel).append("</span>");
                    body.append(enforcerBadge(enforcerResults.get(s.id())));
                    body.append("</div>");
                    if (i == scans.size() - 1) body.append("<span class=\"scan-history-latest\">latest</span>");
                    body.append("</a>");
                }
                body.append("</div>");
            }
            body.append("</section>");
            body.append("</div>");

            // Scan overlay
            body.append(scanOverlayHtml());
            body.append("<script>");
            body.append("function triggerScan(path){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='flex';renderScanLog([]);fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path})}).then(function(r){return r.ok?r.json():r.text().then(function(t){throw new Error(t);});}).then(function(d){pollScan(d.jobId);}).catch(function(err){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';alert(err.message||'Scan failed.');});}");
            body.append("function pollScan(jobId){fetch('/api/scan-status?jobId='+encodeURIComponent(jobId)).then(function(r){return r.ok?r.json():r.text().then(function(t){throw new Error(t);});}).then(function(d){if(d.status==='running'){if(d.phases)renderScanPhases(d.phases);renderScanLog(d.log);setTimeout(function(){pollScan(jobId);},500);}else if(d.status==='done'){window.location.href='/scans/'+d.scanId;}else{var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';alert(d.message||'Scan failed.');}}).catch(function(err){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';alert(err.message||'Status check failed.');});}");
            body.append("function deleteProject(id,name){if(!confirm('Delete project \"'+name+'\" and all its analyses?\\n\\nThis cannot be undone.'))return;fetch('/api/projects/'+encodeURIComponent(id),{method:'DELETE'}).then(function(r){if(r.ok){window.location.href='/';}else{r.text().then(function(t){alert('Delete failed: '+t);});}}).catch(function(err){alert('Delete failed: '+(err.message||err));});}");
            body.append("</script>");
            sendHtml(exchange, 200, pages.renderPage("project", project.name(), "Project dashboard", body.toString()));
            return;
        }
        sendText(exchange, 404, "Not found");
    }

    /** Read-only display of a project's own {@code .redkite/settings.yml} (or {@code settings.yaml})
     *  — build validation settings live in that file, checked into the project itself, rather than
     *  entered through the UI and stored in RedKite's own database. See
     *  {@link com.redkite.maven.ProjectConfigFile}. */
    private String renderProjectConfigPanel(Path projectRoot) {
        Path resolvedPath = com.redkite.maven.ProjectConfigFile.resolveExistingPath(projectRoot);
        boolean exists = resolvedPath != null;
        Path configPath = exists ? resolvedPath : projectRoot.resolve(com.redkite.maven.ProjectConfigFile.RELATIVE_PATH);
        com.redkite.maven.ProjectConfigFile.ProjectConfig config = com.redkite.maven.ProjectConfigFile.load(projectRoot);
        StringBuilder body = new StringBuilder();
        body.append("<section class=\"card span-2\"><h2>Project configuration</h2>");
        body.append("<p class=\"muted\">Extra Maven arguments, profile, and environment variables used when validating this project's build ")
                .append("— read from <code>")
                .append(escape(com.redkite.maven.ProjectConfigFile.RELATIVE_PATH)).append("</code> in the project itself.</p>");
        if (!exists) {
            body.append("<p class=\"proj-meta-val muted\">No <code>").append(escape(com.redkite.maven.ProjectConfigFile.RELATIVE_PATH))
                    .append("</code> found at <code>").append(escape(configPath.toString()))
                    .append("</code> — validation runs with no extra arguments or environment variables. See the docs for the file format.</p>");
        } else {
            body.append("<div class=\"proj-meta\">");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">File</span>")
                    .append("<code class=\"proj-meta-val\">").append(escape(configPath.toString())).append("</code></div>");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Maven arguments</span>")
                    .append(!config.args().isEmpty()
                            ? "<code class=\"proj-meta-val\">" + escape(String.join(" ", config.args())) + "</code>"
                            : "<span class=\"proj-meta-val muted\">none</span>")
                    .append("</div>");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Profile</span>")
                    .append(config.profile() != null && !config.profile().isBlank()
                            ? "<code class=\"proj-meta-val\">" + escape(config.profile()) + "</code>"
                            : "<span class=\"proj-meta-val muted\">none</span>")
                    .append("</div>");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Mode</span>")
                    .append("<code class=\"proj-meta-val\">").append(config.mode().name().toLowerCase()).append("</code>")
                    .append("</div>");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Tests enabled</span>")
                    .append("<code class=\"proj-meta-val\">").append(config.enableTests()).append("</code>")
                    .append("</div>");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Full logs</span>")
                    .append("<code class=\"proj-meta-val\">").append(config.fullLogs()).append("</code>")
                    .append("</div>");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Spring Boot profiles</span>")
                    .append(config.springProfiles() != null && !config.springProfiles().isBlank()
                            ? "<code class=\"proj-meta-val\">" + escape(config.springProfiles()) + "</code>"
                            : "<span class=\"proj-meta-val muted\">none</span>")
                    .append("</div>");
            body.append("<div class=\"proj-meta-row\"><span class=\"proj-meta-label\">Environment variables</span>");
            if (config.env().isEmpty()) {
                body.append("<span class=\"proj-meta-val muted\">none</span>");
            } else {
                body.append("<div class=\"proj-meta-repos\">");
                for (Map.Entry<String, String> e : config.env().entrySet()) {
                    body.append("<code class=\"proj-meta-val\">").append(escape(e.getKey())).append("=").append(escape(e.getValue())).append("</code>");
                }
                body.append("</div>");
            }
            body.append("</div></div>");
        }
        body.append("</section>");
        return body.toString();
    }

    void handleScans(HttpExchange exchange) throws IOException {
        URI uri = exchange.getRequestURI();
        String[] parts = uri.getPath().split("/");
        if (parts.length == 3) {
            String scanId = parts[2];
            ScanEntry scanEntry = store.getScan(scanId);
            ScanReport report = scanEntry.report();
            String projectPath = scanEntry.input().workingTreePath();
            Map<String, String> sourcePoms = store.loadSourcePoms(scanId);
            Map<String, String> moduleArtifactIds = buildModuleArtifactIds(sourcePoms);
            Map<Long, UpgradeRecommendation> recommendationsByComponent = new LinkedHashMap<>();
            for (UpgradeRecommendation recommendation : report.recommendations()) {
                if (!recommendation.affectedComponentIds().isEmpty()) {
                    recommendationsByComponent.put(recommendation.affectedComponentIds().get(0), recommendation);
                } else {
                    recommendationsByComponent.put(recommendation.id(), recommendation);
                }
            }
            Map<Long, List<MetadataResult>> metadataByComponent = new LinkedHashMap<>();
            for (MetadataResult metadataResult : report.metadataResults()) {
                metadataByComponent.computeIfAbsent(metadataResult.componentId(), key -> new ArrayList<>()).add(metadataResult);
            }
            Store.EnforcerResultEntry enforcerResult = store.getEnforcerResult(scanId);
            ProjectEntry project = store.getProject(report.projectId());
            String projectName = project != null ? project.name() : projectPath;
            StringBuilder body = new StringBuilder();
            body.append("<div class=\"page-grid\">");
            body.append("<section class=\"card span-2\"><div class=\"headline\">");
            java.time.format.DateTimeFormatter reportFmt = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(java.time.ZoneId.systemDefault());
            body.append("<div>");
            body.append("<p class=\"eyebrow\">").append(escape(reportFmt.format(report.createdAt()))).append("</p>");
            if (project != null) {
                body.append("<h1 style=\"font-size:1.5rem\"><a href=\"/projects/").append(escape(project.id())).append("\" style=\"color:inherit;text-decoration:none\">").append(escape(projectName)).append("</a></h1>");
            } else {
                body.append("<h1 style=\"font-size:1.5rem\">").append(escape(projectName)).append("</h1>");
            }
            body.append("</div>");
            body.append("<div style=\"display:flex;align-items:center;gap:10px;flex-wrap:wrap\">");
            body.append(report.complete() ? "<span class=\"badge success\" style=\"cursor:pointer\" title=\"View analysis log\" onclick=\"document.getElementById('log-modal').style.display='flex'\">Complete</span>"
                    : isBuildFailed(report) ? "<span class=\"badge\" style=\"background:rgba(220,38,38,.16);border-color:rgba(220,38,38,.4);color:#fca5a5;cursor:pointer\" title=\"View analysis log\" onclick=\"document.getElementById('log-modal').style.display='flex'\">Failed</span>"
                    : "<span class=\"badge warn\" style=\"cursor:pointer\" title=\"View analysis log\" onclick=\"document.getElementById('log-modal').style.display='flex'\">Incomplete</span>");
            body.append(enforcerBadge(enforcerResult));
            body.append("<button class=\"button\" type=\"button\" onclick=\"triggerScan(").append(escape(jsString(projectPath))).append(")\">Analyse</button>");
            body.append("<button class=\"button\" type=\"button\" onclick=\"clearCache(this)\" title=\"Clear version metadata cache\">Clear cache</button>");
            body.append("</div>");
            body.append("</div>");
            body.append("<div id=\"scan-error\" class=\"scan-error\" style=\"display:none;margin-top:12px\"></div>");
            body.append("</section>");
            if (enforcerResult != null && enforcerResult.status() != EnforcerStatus.ENFORCER_NOT_CONFIGURED) {
                body.append("<section class=\"card span-2\">");
                body.append(enforcerSection.renderEnforcerSection(scanId, enforcerResult));
                body.append("</section>");
            }
            body.append("<section class=\"card span-2\">");
            body.append("<h2 style=\"font-size:1rem;margin:0 0 12px\">License information</h2>");
            String licenseBreakdown = scanPage.licenseBreakdownHtml(report);
            body.append(licenseBreakdown.isEmpty() ? "<p class=\"muted\">No license data available.</p>" : licenseBreakdown);
            body.append("</section>");
            Map<String, List<TransitiveConflictFinding>> conflictsByKey = new LinkedHashMap<>();
            if (enforcerResult != null) {
                for (TransitiveConflictFinding f : enforcerResult.findings()) {
                    conflictsByKey.computeIfAbsent(f.groupId() + ":" + f.artifactId(), k -> new ArrayList<>()).add(f);
                }
            }
            body.append("<script>const rk_scanPath=").append(jsonStr(projectPath)).append(";</script>");
            body.append("<section class=\"card span-2\">");
            body.append(scanPage.renderRemediationView(report, scanId, !sourcePoms.isEmpty(), moduleArtifactIds, sourcePoms, conflictsByKey));
            body.append("</section>");
            body.append("</div>");
            body.append(logModal.renderLogModal(report, scanId, enforcerResult));
            body.append(scanOverlayHtml());
            body.append(applyOverlayHtml());
            sendHtml(exchange, 200, pages.renderPage("scan", "Analysis",
                    "Dependency inventory and upgrade recommendations.", body.toString()));
            return;
        }
        sendText(exchange, 404, "Not found");
    }
}
