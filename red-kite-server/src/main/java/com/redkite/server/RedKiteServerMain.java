package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.core.service.SerializationSupport;
import com.redkite.maven.ConflictOutputParser;
import com.redkite.maven.EnforcerDetector;
import com.redkite.maven.EnforcerRunner;
import com.redkite.maven.MavenProjectScanner;
import com.redkite.maven.MavenSettingsReader;
import com.redkite.maven.RemediationApplier;
import com.redkite.metadata.HttpVersionMetadataProvider;
import com.redkite.metadata.HttpVulnerabilityProvider;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.core.service.RemediationClassifier;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class RedKiteServerMain {
    private static final Logger LOGGER = Logger.getLogger(RedKiteServerMain.class.getName());
    private static final String BRAND = "RedKite";

    @FunctionalInterface
    private interface ExchangeHandler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private static final Set<String> VALID_THEMES = Set.of("dark", "light", "ocean", "dusk", "forest", "ember");

    private final Store store;
    private final HttpServer server;
    private final ConcurrentHashMap<String, ScanJob> scanJobs = new ConcurrentHashMap<>();
    private final java.nio.file.Path prefsFile;
    private volatile String theme = "dark";
    private final TemplateEngine templateEngine;
    private final String inlineCss;
    private final String inlineJs;

    private static final class ScanJob {
        enum Status { RUNNING, DONE, ERROR }
        volatile Status status = Status.RUNNING;
        volatile String phasesJson = scanPhases(0,"active",0,"pending",0,"pending",0,"pending",0,"pending");
        volatile String scanId;
        volatile String errorMessage;
    }

    private static String scanPhases(int p0, String s0, int p1, String s1, int p2, String s2,
                                     int p3, String s3, int p4, String s4) {
        return "[{\"name\":\"Dependency analysis\",\"pct\":" + p0 + ",\"status\":\"" + s0 + "\"},"
             + "{\"name\":\"Version metadata\",\"pct\":" + p1 + ",\"status\":\"" + s1 + "\"},"
             + "{\"name\":\"Vulnerability scan\",\"pct\":" + p2 + ",\"status\":\"" + s2 + "\"},"
             + "{\"name\":\"Upgrade analysis\",\"pct\":" + p3 + ",\"status\":\"" + s3 + "\"},"
             + "{\"name\":\"Dependency management\",\"pct\":" + p4 + ",\"status\":\"" + s4 + "\"}]";
    }

    public RedKiteServerMain(String jdbcUrl, String dbUser, String dbPassword, int port) throws IOException {
        this.store = Store.connect(jdbcUrl, dbUser, dbPassword);
        java.nio.file.Path defaultDataDir = java.nio.file.Path.of(System.getProperty("user.home"), ".redkite");
        this.prefsFile = java.nio.file.Path.of(System.getProperty("redkite.prefs.file",
                defaultDataDir.resolve("preferences.properties").toString()));
        this.theme = loadTheme();
        this.inlineCss = loadClasspathResource("static/styles.css");
        this.inlineJs = loadClasspathResource("static/scripts.js");
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCacheable(false);
        this.templateEngine = new TemplateEngine();
        this.templateEngine.setTemplateResolver(resolver);
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.setExecutor(Executors.newCachedThreadPool());
        registerContexts();
    }

    private static String loadClasspathResource(String path) throws IOException {
        try (InputStream is = RedKiteServerMain.class.getClassLoader().getResourceAsStream(path)) {
            if (is == null) throw new IOException("Classpath resource not found: " + path);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String renderPage(String templateName, String title, String subtitle, String bodyContent) {
        Context ctx = new Context();
        ctx.setVariable("brand", BRAND);
        ctx.setVariable("title", title);
        ctx.setVariable("subtitle", subtitle);
        ctx.setVariable("theme", theme);
        ctx.setVariable("inlineCss", inlineCss);
        ctx.setVariable("inlineJs", inlineJs);
        ctx.setVariable("bodyContent", bodyContent);
        return templateEngine.process(templateName, ctx);
    }

    private String loadTheme() {
        try {
            if (!java.nio.file.Files.exists(prefsFile)) return "dark";
            java.util.Properties p = new java.util.Properties();
            try (var r = java.nio.file.Files.newBufferedReader(prefsFile)) { p.load(r); }
            String t = p.getProperty("theme", "dark");
            return VALID_THEMES.contains(t) ? t : "dark";
        } catch (IOException e) {
            return "dark";
        }
    }

    private void saveTheme(String t) {
        try {
            java.nio.file.Files.createDirectories(prefsFile.getParent());
            java.util.Properties p = new java.util.Properties();
            if (java.nio.file.Files.exists(prefsFile)) {
                try (var r = java.nio.file.Files.newBufferedReader(prefsFile)) { p.load(r); }
            }
            p.setProperty("theme", t);
            try (var w = java.nio.file.Files.newBufferedWriter(prefsFile)) { p.store(w, "RedKite preferences"); }
            this.theme = t;
        } catch (IOException e) {
            LOGGER.warning("Failed to save theme preference: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        java.nio.file.Path dataDir = java.nio.file.Path.of(System.getProperty("user.home"), ".redkite");
        Files.createDirectories(dataDir);

        for (String arg : args) {
            if ("--drop-db".equals(arg)) {
                java.nio.file.Path dbFile = dataDir.resolve("redkite.mv.db");
                java.nio.file.Path traceFile = dataDir.resolve("redkite.trace.db");
                boolean deleted = Files.deleteIfExists(dbFile);
                Files.deleteIfExists(traceFile);
                System.out.println(deleted ? "Database dropped: " + dbFile : "No database file found at " + dbFile);
                return;
            }
        }

        String jdbcUrl = System.getProperty("redkite.db.url",
                "jdbc:h2:" + dataDir.resolve("redkite") + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE");
        String dbUser = System.getProperty("redkite.db.user", "sa");
        String dbPassword = System.getProperty("redkite.db.password", "");
        int port = Integer.parseInt(System.getProperty("redkite.port", "6502"));
        RedKiteServerMain app = new RedKiteServerMain(jdbcUrl, dbUser, dbPassword, port);
        app.start();
        System.out.println(BRAND + " server listening on http://localhost:" + port);
        new CountDownLatch(1).await();
    }

    public void start() {
        server.start();
    }

    private void registerContexts() {
        server.createContext("/health", exchange -> safeHandle(exchange, this::handleHealth));
        server.createContext("/", exchange -> safeHandle(exchange, this::handleIndex));
        server.createContext("/logo.svg", exchange -> safeHandle(exchange, this::handleLogo));
        server.createContext("/projects", exchange -> safeHandle(exchange, this::handleProjects));
        server.createContext("/scans", exchange -> safeHandle(exchange, this::handleScans));
        server.createContext("/api/scan", exchange -> safeHandle(exchange, this::handleApiScan));
        server.createContext("/api/scan-status", exchange -> safeHandle(exchange, this::handleApiScanStatus));
        server.createContext("/api/scans/pom", exchange -> safeHandle(exchange, this::handleApiScanPom));
        server.createContext("/api/scans/pom/write", exchange -> safeHandle(exchange, this::handleApiScanPomWrite));
        server.createContext("/api/metadata/clear", exchange -> safeHandle(exchange, this::handleApiMetadataClear));
        server.createContext("/api/projects", exchange -> safeHandle(exchange, this::handleApiProjects));
        server.createContext("/api/prefs", exchange -> safeHandle(exchange, this::handleApiPrefs));
        server.createContext("/api/scans/enforcer", exchange -> safeHandle(exchange, this::handleApiEnforcerResults));
        server.createContext("/api/scans/remediation/apply", exchange -> safeHandle(exchange, this::handleApiRemediationApply));
    }

    private void safeHandle(HttpExchange exchange, ExchangeHandler handler) throws IOException {
        try {
            handler.handle(exchange);
        } catch (Exception e) {
            LOGGER.log(java.util.logging.Level.SEVERE, "HTTP handler failed for " + exchange.getRequestURI(), e);
            String msg = causeChain(e);
            sendText(exchange, 500, BRAND + " error: " + escape(msg));
        }
    }

    private static String causeChain(Throwable t) {
        StringBuilder sb = new StringBuilder();
        while (t != null) {
            if (sb.length() > 0) {
                sb.append(": ");
            }
            sb.append(t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage());
            t = t.getCause();
        }
        return sb.length() == 0 ? "unexpected failure" : sb.toString();
    }

    private void handleIndex(HttpExchange exchange) throws IOException {
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

        sendHtml(exchange, 200, renderPage("home", "Projects",
                "Local Maven dependency analysis, version checks, and upgrade planning.", body.toString()));
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        sendText(exchange, 200, "ok");
    }

    private void handleProjects(HttpExchange exchange) throws IOException {
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
            body.append("function triggerScan(path){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='flex';fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path})}).then(function(r){return r.ok?r.json():r.text().then(function(t){throw new Error(t);});}).then(function(d){pollScan(d.jobId);}).catch(function(err){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';alert(err.message||'Scan failed.');});}");
            body.append("function pollScan(jobId){fetch('/api/scan-status?jobId='+encodeURIComponent(jobId)).then(function(r){return r.ok?r.json():r.text().then(function(t){throw new Error(t);});}).then(function(d){if(d.status==='running'){if(d.phases)renderScanPhases(d.phases);setTimeout(function(){pollScan(jobId);},500);}else if(d.status==='done'){window.location.href='/scans/'+d.scanId;}else{var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';alert(d.message||'Scan failed.');}}).catch(function(err){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';alert(err.message||'Status check failed.');});}");
            body.append("function deleteProject(id,name){if(!confirm('Delete project \"'+name+'\" and all its analyses?\\n\\nThis cannot be undone.'))return;fetch('/api/projects/'+encodeURIComponent(id),{method:'DELETE'}).then(function(r){if(r.ok){window.location.href='/';}else{r.text().then(function(t){alert('Delete failed: '+t);});}}).catch(function(err){alert('Delete failed: '+(err.message||err));});}");
            body.append("</script>");
            sendHtml(exchange, 200, renderPage("project", project.name(), "Project dashboard", body.toString()));
            return;
        }
        sendText(exchange, 404, "Not found");
    }

    private void handleScans(HttpExchange exchange) throws IOException {
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
                body.append(renderEnforcerSection(scanId, enforcerResult));
                body.append("</section>");
            }
            Map<String, List<TransitiveConflictFinding>> conflictsByKey = new LinkedHashMap<>();
            if (enforcerResult != null) {
                for (TransitiveConflictFinding f : enforcerResult.findings()) {
                    conflictsByKey.computeIfAbsent(f.groupId() + ":" + f.artifactId(), k -> new ArrayList<>()).add(f);
                }
            }
            body.append("<script>const rk_scanPath=").append(jsonStr(projectPath)).append(";</script>");
            body.append("<section class=\"card span-2\">");
            body.append(renderRemediationView(report, scanId, !sourcePoms.isEmpty(), moduleArtifactIds, sourcePoms, conflictsByKey));
            body.append("</section>");
            body.append("</div>");
            body.append(renderLogModal(report, scanId, enforcerResult));
            body.append(scanOverlayHtml());
            body.append(applyOverlayHtml());
            sendHtml(exchange, 200, renderPage("scan", "Analysis",
                    "Dependency inventory and upgrade recommendations.", body.toString()));
            return;
        }
        sendText(exchange, 404, "Not found");
    }

    private void handleApiScan(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        String path = parseJsonPath(readBody(exchange));
        if (path == null || path.isBlank()) {
            sendText(exchange, 400, "Missing path");
            return;
        }
        Path projectRoot = Path.of(path).toAbsolutePath().normalize();
        if (!Files.isDirectory(projectRoot)) {
            sendText(exchange, 400, "Not a directory: " + path);
            return;
        }
        if (!Files.exists(projectRoot.resolve("pom.xml"))) {
            sendText(exchange, 400, "No pom.xml found at: " + path);
            return;
        }
        String jobId = UUID.randomUUID().toString();
        ScanJob job = new ScanJob();
        scanJobs.put(jobId, job);
        sendJson(exchange, 200, "{\"jobId\":\"" + jobId + "\"}");
        new Thread(() -> {
            try {
                store.reconfigureForProject(projectRoot);

                // Phase 0: dependency scan
                int[] scanMods = {0}, scanDone = {0};
                Consumer<String> scanProg = msg -> {
                    if (msg.startsWith("Found ")) {
                        try { scanMods[0] = Integer.parseInt(msg.split(" ")[1]); } catch (Exception ignored) {}
                        job.phasesJson = scanPhases(5,"active",0,"pending",0,"pending",0,"pending",0,"pending");
                    } else if (msg.startsWith("Running dependency:tree")) {
                        scanDone[0]++;
                        int pct = scanMods[0] > 0 ? 10 + scanDone[0] * 80 / scanMods[0] : 20;
                        job.phasesJson = scanPhases(Math.min(pct, 95),"active",0,"pending",0,"pending",0,"pending",0,"pending");
                    }
                };
                ScanInput input = new MavenProjectScanner().scan(projectRoot, scanProg);

                job.phasesJson = scanPhases(100,"done",0,"active",0,"pending",0,"pending",0,"pending");
                Consumer<String> buildProg = msg -> {
                    if (msg.startsWith("Version ")) {
                        String[] parts = msg.substring("Version ".length()).split("/");
                        try {
                            int n = Integer.parseInt(parts[0].trim());
                            int t = Integer.parseInt(parts[1].trim());
                            int pct = t > 0 ? n * 100 / t : 0;
                            job.phasesJson = scanPhases(100,"done",pct,"active",0,"pending",0,"pending",0,"pending");
                        } catch (Exception ignored) {}
                    } else if (msg.startsWith("Vulnerability ")) {
                        String[] parts = msg.substring("Vulnerability ".length()).split("/");
                        try {
                            int n = Integer.parseInt(parts[0].trim());
                            int t = Integer.parseInt(parts[1].trim());
                            int pct = t > 0 ? n * 100 / t : 0;
                            job.phasesJson = scanPhases(100,"done",100,"done",pct,"active",0,"pending",0,"pending");
                        } catch (Exception ignored) {}
                    } else if ("Upgrades".equals(msg)) {
                        job.phasesJson = scanPhases(100,"done",100,"done",100,"done",0,"active",0,"pending");
                    }
                };
                ScanReport report = store.ingest(input, buildProg);

                job.phasesJson = scanPhases(100,"done",100,"done",100,"done",100,"done",0,"active");
                runEnforcerCheck(projectRoot, report.scanId(), msg -> {
                    if (msg.startsWith("Dependency management ")) {
                        try {
                            int pct = Integer.parseInt(msg.substring("Dependency management ".length()).trim());
                            job.phasesJson = scanPhases(100,"done",100,"done",100,"done",100,"done",pct,"active");
                        } catch (Exception ignored) {}
                    }
                });
                job.phasesJson = scanPhases(100,"done",100,"done",100,"done",100,"done",100,"done");

                job.scanId = report.scanId();
                job.status = ScanJob.Status.DONE;
            } catch (Throwable e) {
                job.errorMessage = causeChain(e);
                job.status = ScanJob.Status.ERROR;
            }
        }, "redkite-scan-" + jobId).start();
    }

    private void runEnforcerCheck(Path projectRoot, String scanId, Consumer<String> progress) {
        try {
            Path pomPath = projectRoot.resolve("pom.xml");
            com.redkite.maven.TempPomAnalyzer analyzer = new com.redkite.maven.TempPomAnalyzer();
            progress.accept("Dependency management 5");

            // Scan POM files for dep-management entries and RedKite exclusion metadata.
            // This is a pure file read — no Maven invocation needed.
            com.redkite.maven.TempPomAnalyzer.PomMetadata meta = analyzer.scanPomMetadata(projectRoot);
            progress.accept("Dependency management 20");

            // Run the enforcer against the original project (not a temp directory) so that
            // parent-POM resolution and source-file lookup always work correctly.
            // If a previous run established that rules are lifecycle-bound (enforcer:enforce
            // reports no rules), the project flag is set and we skip straight to verify.
            String projectId = store.getScan(scanId).projectId();
            boolean skipDirectEnforce = store.getProjectEnforcerUseVerify(projectId);
            EnforcerRunner.EnforcerRunResult enfResult = new EnforcerRunner().run(projectRoot, pomPath, skipDirectEnforce);
            if (enfResult.usedVerifyFallback() && !skipDirectEnforce) {
                store.setProjectEnforcerUseVerify(projectId);
            }
            progress.accept("Dependency management 50");

            String rawOutput = enfResult.rawOutput();
            EnforcerStatus status;
            List<TransitiveConflictFinding> findings = List.of();
            if (enfResult.errorDetail() != null) {
                status = EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE;
                LOGGER.warning(() -> "Enforcer could not start for scan " + scanId + ": " + enfResult.errorDetail());
            } else if (enfResult.passed()) {
                status = EnforcerStatus.ENFORCER_RUN_PASSED;
            } else {
                findings = new ConflictOutputParser().parse(rawOutput);
                if (findings.isEmpty()) {
                    status = EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE;
                    LOGGER.warning(() -> "Enforcer ran but produced no parseable conflict findings for scan "
                            + scanId + ". Raw output length: " + rawOutput.length());
                } else {
                    status = EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS;
                }
            }

            // Phase 2: verify auto-fix with computed dep-management pins
            progress.accept("Dependency management 60");
            List<TransitiveConflictFinding> phase2Findings = null;
            List<String> phase2Pins = List.of();
            if (status == EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS) {
                Phase2Result p2 = runPhase2Validation(projectRoot, pomPath, findings, skipDirectEnforce);
                if (p2 != null) {
                    phase2Findings = p2.remainingFindings();
                    phase2Pins = p2.appliedPins();
                }
            }
            progress.accept("Dependency management 80");

            // Stale exclusion detection
            Set<String> conflictKeys = findings.stream()
                    .map(f -> f.groupId() + ":" + f.artifactId())
                    .collect(java.util.stream.Collectors.toSet());
            List<String> staleExclusions = meta.allRedkiteExclusions().stream()
                    .filter(ga -> !conflictKeys.contains(ga))
                    .distinct().toList();

            progress.accept("Dependency management 95");
            store.saveEnforcerResult(scanId, status, rawOutput, findings, staleExclusions, phase2Findings,
                    meta.exclusionsStripped(), meta.depMgmtEntries(), phase2Pins);
        } catch (Exception e) {
            LOGGER.warning(() -> "Enforcer check failed for scan " + scanId + ": " + e.getMessage());
            store.saveEnforcerResult(scanId, EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE, "",
                    List.of(), List.of(), null, 0, List.of(), List.of());
        }
    }

    /**
     * Phase 2: applies computed dep-management pins to a temp copy of all project POMs
     * (with all existing dep management and RedKite remediations stripped) and re-runs the
     * enforcer to verify whether the auto-fix resolves all violations.
     *
     * Returns the remaining findings, an empty list if all resolved, or null if Phase 2 could not run.
     */
    private record Phase2Result(List<TransitiveConflictFinding> remainingFindings, List<String> appliedPins) {}

    private Phase2Result runPhase2Validation(
            Path projectRoot, Path pomPath, List<TransitiveConflictFinding> findings,
            boolean skipDirectEnforce) {
        try {
            // Compute winner as max version — consistent with pristine analysis (all dep mgmt stripped)
            Map<String, String> pins = new LinkedHashMap<>();
            for (TransitiveConflictFinding f : findings) {
                String winner = computeWinnerVersion(f, "");
                if (winner != null && !winner.isBlank()) {
                    pins.put(f.groupId() + ":" + f.artifactId(), winner);
                }
            }
            List<String> pinsList = pins.entrySet().stream()
                    .map(e -> e.getKey() + ":" + e.getValue())
                    .toList();
            LOGGER.info(() -> "Phase 2: running enforcer with " + pins.size() + " computed dep-management pin(s)");
            EnforcerRunner.EnforcerRunResult r =
                    new com.redkite.maven.TempPomAnalyzer().runWithPins(projectRoot, pomPath, pins, skipDirectEnforce);
            if (r.passed()) {
                LOGGER.info("Phase 2: all conflicts resolved by auto-fix");
                return new Phase2Result(List.of(), pinsList);
            }
            if (r.errorDetail() != null) return new Phase2Result(null, pinsList);
            List<TransitiveConflictFinding> remaining = new ConflictOutputParser().parse(r.rawOutput());
            LOGGER.info(() -> "Phase 2: " + remaining.size() + " conflict(s) remain after auto-fix");
            return new Phase2Result(remaining, pinsList);
        } catch (Exception e) {
            LOGGER.warning(() -> "Phase 2 validation failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Computes the version to pin for a conflict finding.
     * Prefers an existing explicit dep-management entry in the POM; falls back to the max version.
     */
    private String computeWinnerVersion(TransitiveConflictFinding f, String pomContent) {
        // Use the max of resolvedVersion, all conflicting versions, and any existing dep-management pin.
        // The pin is a candidate, not an override — if child POMs have a higher version it wins.
        String winner = f.resolvedVersion() != null ? f.resolvedVersion() : "";
        for (String v : f.conflictingVersions()) {
            if (compareVersionsSemantic(v, winner) > 0) winner = v;
        }
        String pinned = extractDepMgmtVersion(pomContent, f.groupId(), f.artifactId());
        if (pinned != null && !pinned.isBlank() && compareVersionsSemantic(pinned, winner) > 0) {
            winner = pinned;
        }
        return winner.isBlank() ? null : winner;
    }

    /** Extracts the pinned version for g:a from an existing <dependencyManagement> block. */
    private static String extractDepMgmtVersion(String pomXml, String groupId, String artifactId) {
        // Simple scan: look for <groupId>G</groupId> / <artifactId>A</artifactId> / <version>V</version>
        // within a <dependencyManagement> block.
        int dmStart = pomXml.indexOf("<dependencyManagement>");
        int dmEnd = pomXml.indexOf("</dependencyManagement>");
        if (dmStart < 0 || dmEnd <= dmStart) return null;
        String dm = pomXml.substring(dmStart, dmEnd);
        // Find each <dependency> block within dep management
        int pos = 0;
        while (true) {
            int depStart = dm.indexOf("<dependency>", pos);
            if (depStart < 0) break;
            int depEnd = dm.indexOf("</dependency>", depStart);
            if (depEnd < 0) break;
            String dep = dm.substring(depStart, depEnd);
            if (dep.contains("<groupId>" + groupId + "</groupId>")
                    && dep.contains("<artifactId>" + artifactId + "</artifactId>")) {
                int vs = dep.indexOf("<version>");
                int ve = dep.indexOf("</version>");
                if (vs >= 0 && ve > vs) return dep.substring(vs + 9, ve).trim();
            }
            pos = depEnd + 1;
        }
        return null;
    }

    private void handleApiEnforcerResults(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        String scanId = queryParam(exchange.getRequestURI().getQuery(), "scanId");
        if (scanId == null) { sendText(exchange, 400, "Missing scanId"); return; }
        Store.EnforcerResultEntry entry = store.getEnforcerResult(scanId);
        if (entry == null) { sendJson(exchange, 200, "{\"status\":\"ENFORCER_NOT_CONFIGURED\",\"findings\":[]}"); return; }
        sendJson(exchange, 200, enforcerResultToJson(entry));
    }

    private void handleApiRemediationApply(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> params = parseJsonObject(body);
        String scanId = params.get("scanId");
        String actionType = params.get("actionType");
        String groupId = params.get("groupId");
        String artifactId = params.get("artifactId");
        String version = params.get("version");
        String parentGroupId = params.get("parentGroupId");
        String parentArtifactId = params.get("parentArtifactId");
        String pomFile = params.get("pomFile");

        if (scanId == null || actionType == null || groupId == null || artifactId == null) {
            sendText(exchange, 400, "Missing required fields");
            return;
        }

        try {
            ScanEntry scanEntry = store.getScan(scanId);
            Path projectRoot = Path.of(scanEntry.input().workingTreePath());
            Path targetPom = pomFile != null && !pomFile.isBlank()
                    ? Path.of(pomFile)
                    : projectRoot.resolve("pom.xml");

            if (!targetPom.startsWith(projectRoot)) {
                sendText(exchange, 400, "POM path outside project root");
                return;
            }

            RemediationApplier applier = new RemediationApplier();
            String updatedPom;
            String reason = "Enforcer dependency convergence fix by RedKite";

            if ("ADD_EXCLUSION".equals(actionType)) {
                if (parentGroupId == null || parentArtifactId == null) {
                    sendText(exchange, 400, "Missing parentGroupId/parentArtifactId for exclusion");
                    return;
                }
                updatedPom = applier.applyExclusion(targetPom, parentGroupId, parentArtifactId,
                        groupId, artifactId, reason);
            } else if ("ADD_DEPENDENCY_MANAGEMENT".equals(actionType)) {
                if (version == null) {
                    sendText(exchange, 400, "Missing version for dependency management pin");
                    return;
                }
                updatedPom = applier.applyDependencyManagementPin(targetPom, groupId, artifactId, version, reason);
            } else {
                sendText(exchange, 400, "Unknown actionType: " + actionType);
                return;
            }

            // Write the modified POM
            Files.writeString(targetPom, updatedPom, StandardCharsets.UTF_8);

            sendJson(exchange, 200, "{\"status\":\"ok\"}");
        } catch (Exception e) {
            LOGGER.warning(() -> "Remediation apply failed: " + e.getMessage());
            sendText(exchange, 500, "Apply failed: " + e.getMessage());
        }
    }

    private String enforcerResultToJson(Store.EnforcerResultEntry entry) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"status\":").append(jsonStr(entry.status().name()));
        sb.append(",\"findings\":[");
        List<TransitiveConflictFinding> findings = entry.findings();
        for (int i = 0; i < findings.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(findingToJson(findings.get(i)));
        }
        sb.append("],\"staleExclusions\":[");
        List<String> stale = entry.staleExclusions();
        for (int i = 0; i < stale.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(jsonStr(stale.get(i)));
        }
        sb.append("]}");
        return sb.toString();
    }

    private String findingToJson(TransitiveConflictFinding f) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"groupId\":").append(jsonStr(f.groupId())).append(",");
        sb.append("\"artifactId\":").append(jsonStr(f.artifactId())).append(",");
        sb.append("\"resolvedVersion\":").append(jsonStr(f.resolvedVersion())).append(",");
        sb.append("\"ruleName\":").append(jsonStr(f.ruleName())).append(",");
        sb.append("\"conflictingVersions\":").append(stringListToJson(f.conflictingVersions())).append(",");
        sb.append("\"dependencyPaths\":").append(stringListToJson(f.dependencyPaths())).append(",");
        sb.append("\"candidateActions\":[");
        List<ConflictCandidateAction> actions = f.candidateActions();
        for (int i = 0; i < actions.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(actionToJson(actions.get(i)));
        }
        sb.append("]}");
        return sb.toString();
    }

    private String actionToJson(ConflictCandidateAction a) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"type\":").append(jsonStr(a.type().name())).append(",");
        sb.append("\"groupId\":").append(jsonStr(a.groupId())).append(",");
        sb.append("\"artifactId\":").append(jsonStr(a.artifactId())).append(",");
        sb.append("\"version\":").append(jsonStr(a.version())).append(",");
        sb.append("\"parentGroupId\":").append(jsonStr(a.parentGroupId())).append(",");
        sb.append("\"parentArtifactId\":").append(jsonStr(a.parentArtifactId()));
        sb.append("}");
        return sb.toString();
    }

    private String stringListToJson(List<String> list) {
        if (list == null || list.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(jsonStr(list.get(i)));
        }
        sb.append("]");
        return sb.toString();
    }

    private static Map<String, String> parseJsonObject(String json) {
        Map<String, String> map = new LinkedHashMap<>();
        if (json == null || json.isBlank()) return map;
        String s = json.strip();
        if (s.startsWith("{")) s = s.substring(1);
        if (s.endsWith("}")) s = s.substring(0, s.length() - 1);
        // Naive key-value parser for flat JSON objects with string values
        int i = 0;
        while (i < s.length()) {
            // Find key
            int kStart = s.indexOf('"', i);
            if (kStart == -1) break;
            int kEnd = s.indexOf('"', kStart + 1);
            if (kEnd == -1) break;
            String key = s.substring(kStart + 1, kEnd);
            // Find colon
            int colon = s.indexOf(':', kEnd + 1);
            if (colon == -1) break;
            // Find value
            int vStart = colon + 1;
            while (vStart < s.length() && s.charAt(vStart) == ' ') vStart++;
            if (vStart >= s.length()) break;
            String value;
            if (s.charAt(vStart) == '"') {
                int vEnd = vStart + 1;
                while (vEnd < s.length()) {
                    if (s.charAt(vEnd) == '\\') { vEnd += 2; continue; }
                    if (s.charAt(vEnd) == '"') break;
                    vEnd++;
                }
                value = s.substring(vStart + 1, vEnd)
                        .replace("\\\"", "\"").replace("\\n", "\n").replace("\\\\", "\\");
                map.put(key, value);
                i = vEnd + 1;
            } else {
                // non-string value (number/bool/null)
                int vEnd = vStart;
                while (vEnd < s.length() && s.charAt(vEnd) != ',' && s.charAt(vEnd) != '}') vEnd++;
                value = s.substring(vStart, vEnd).strip();
                if (!"null".equals(value)) map.put(key, value);
                i = vEnd + 1;
            }
        }
        return map;
    }

    private void handleApiScanStatus(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        String jobId = queryParam(exchange.getRequestURI().getQuery(), "jobId");
        if (jobId == null) { sendText(exchange, 400, "Missing jobId"); return; }
        ScanJob job = scanJobs.get(jobId);
        if (job == null) { sendText(exchange, 404, "Job not found"); return; }
        switch (job.status) {
            case RUNNING -> sendJson(exchange, 200, "{\"status\":\"running\",\"phases\":" + job.phasesJson + "}");
            case DONE -> {
                scanJobs.remove(jobId);
                sendJson(exchange, 200, "{\"status\":\"done\",\"scanId\":\"" + job.scanId + "\"}");
            }
            case ERROR -> {
                scanJobs.remove(jobId);
                sendJson(exchange, 200, "{\"status\":\"error\",\"message\":" + jsonStr(job.errorMessage) + "}");
            }
        }
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String parseJsonField(String json, String field) {
        if (json == null) return null;
        int idx = json.indexOf("\"" + field + "\"");
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + field.length() + 2);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = q1 + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') break;
            sb.append(c);
        }
        return sb.toString();
    }

    private static String parseJsonPath(String json) {
        if (json == null) return null;
        int idx = json.indexOf("\"path\"");
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + 6);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = q1 + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') break;
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(++i);
                if (next == '"') sb.append('"');
                else if (next == '\\') sb.append('\\');
                else if (next == '/') sb.append('/');
                else if (next == 'n') sb.append('\n');
                else if (next == 'r') sb.append('\r');
                else if (next == 't') sb.append('\t');
                else sb.append(next);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private void handleApiPrefs(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        String t = parseJsonField(readBody(exchange), "theme");
        if (t == null || !VALID_THEMES.contains(t)) {
            sendText(exchange, 400, "Invalid theme");
            return;
        }
        saveTheme(t);
        sendJson(exchange, 200, "{\"theme\":" + jsonStr(t) + "}");
    }

    private void handleApiMetadataClear(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        store.versionProvider.clearAll();
        store.clearVersionCache();
        store.vulnerabilityProvider.clearAll();
        sendJson(exchange, 200, "{\"cleared\":true}");
    }

    private void handleApiProjects(HttpExchange exchange) throws IOException {
        String[] parts = exchange.getRequestURI().getPath().split("/");
        if (parts.length == 4 && "DELETE".equalsIgnoreCase(exchange.getRequestMethod())) {
            String projectId = parts[3];
            store.deleteProject(projectId);
            sendJson(exchange, 200, "{\"deleted\":true}");
            return;
        }
        sendText(exchange, 405, "Method not allowed");
    }

    private void handleApiScanPom(HttpExchange exchange) throws IOException {
        String scanIdParam = queryParam(exchange.getRequestURI().getQuery(), "scanId");
        if (scanIdParam == null) { sendText(exchange, 400, "Missing scanId"); return; }
        String scanId = scanIdParam;

        if ("POST".equals(exchange.getRequestMethod())) {
            Map<String, String> updates = parseForm(readBody(exchange));
            if (updates.isEmpty()) { sendText(exchange, 400, "No updates"); return; }
            try {
                ScanEntry scan = store.getScan(scanId);
                Map<String, String> sourcePoms = store.loadSourcePoms(scanId);
                Store.EnforcerResultEntry enforcerResult = store.getEnforcerResult(scanId);
                Map<String, List<TransitiveConflictFinding>> conflictsByKey = new LinkedHashMap<>();
                if (enforcerResult != null && enforcerResult.findings() != null) {
                    for (TransitiveConflictFinding finding : enforcerResult.findings()) {
                        conflictsByKey.computeIfAbsent(finding.groupId() + ":" + finding.artifactId(), k -> new ArrayList<>()).add(finding);
                    }
                }
                Map<String, String> patchedFiles = generatePomPatches(
                        scan.report(), sourcePoms, scan.input().workingTreePath(), updates, conflictsByKey);
                if (patchedFiles.isEmpty()) { sendJson(exchange, 200, "{}"); return; }
                StringBuilder json = new StringBuilder("{");
                boolean first = true;
                for (Map.Entry<String, String> entry : patchedFiles.entrySet()) {
                    if (!first) json.append(",");
                    first = false;
                    json.append(jsonStr(entry.getKey())).append(":").append(jsonStr(entry.getValue()));
                }
                json.append("}");
                sendJson(exchange, 200, json.toString());
            } catch (Exception e) {
                LOGGER.warning(() -> "POM generation failed: " + e.getMessage());
                sendText(exchange, 500, "Failed: " + e.getMessage());
            }
            return;
        }

        if ("GET".equals(exchange.getRequestMethod())) {
            Map<String, String> files = store.loadPomFiles(scanId);
            if (files.isEmpty()) files = store.loadSourcePoms(scanId);
            if (files.isEmpty()) { sendText(exchange, 404, "No generated POM"); return; }
            if (files.size() == 1) {
                Map.Entry<String, String> entry = files.entrySet().iterator().next();
                byte[] bytes = entry.getValue().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/xml; charset=utf-8");
                exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"pom.xml\"");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
            } else {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                try (ZipOutputStream zip = new ZipOutputStream(buf)) {
                    for (Map.Entry<String, String> entry : files.entrySet()) {
                        zip.putNextEntry(new ZipEntry(entry.getKey()));
                        zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                        zip.closeEntry();
                    }
                }
                byte[] bytes = buf.toByteArray();
                exchange.getResponseHeaders().set("Content-Type", "application/zip");
                exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"poms.zip\"");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
            }
            return;
        }

        sendText(exchange, 405, "Method not allowed");
    }

    private void handleApiScanPomWrite(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { sendText(exchange, 405, "Method not allowed"); return; }
        String scanIdParam = queryParam(exchange.getRequestURI().getQuery(), "scanId");
        if (scanIdParam == null) { sendText(exchange, 400, "Missing scanId"); return; }
        String scanId = scanIdParam;
        String body = readBody(exchange);
        try {
            ScanEntry scan = store.getScan(scanId);
            java.nio.file.Path root = java.nio.file.Path.of(scan.input().workingTreePath()).toAbsolutePath().normalize();
            // Body is JSON object: {"relative/path/pom.xml": "content", ...}
            Map<String, String> files = parseJsonStringMap(body);
            if (files.isEmpty()) { sendJson(exchange, 200, "{\"written\":[]}"); return; }
            List<String> written = new ArrayList<>();
            for (Map.Entry<String, String> entry : files.entrySet()) {
                java.nio.file.Path target = root.resolve(entry.getKey()).normalize();
                if (!target.startsWith(root)) {
                    sendText(exchange, 400, "Path escapes project root: " + entry.getKey()); return;
                }
                java.nio.file.Files.writeString(target, entry.getValue(), StandardCharsets.UTF_8);
                written.add(entry.getKey());
                LOGGER.info(() -> "Wrote patched POM: " + target);
            }
            StringBuilder json = new StringBuilder("{\"written\":[");
            for (int i = 0; i < written.size(); i++) {
                if (i > 0) json.append(",");
                json.append(jsonStr(written.get(i)));
            }
            json.append("]}");
            sendJson(exchange, 200, json.toString());
        } catch (Exception e) {
            LOGGER.warning(() -> "POM write failed: " + e.getMessage());
            sendText(exchange, 500, "Failed: " + e.getMessage());
        }
    }

    private Map<String, String> generatePomPatches(ScanReport report, Map<String, String> sourcePoms, String workingTreePath, Map<String, String> rawUpdates, Map<String, List<TransitiveConflictFinding>> conflictsByKey) throws Exception {
        // rawUpdates keys are component IDs (from the client) — resolve each to its exact component
        Map<Long, String> updateById = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : rawUpdates.entrySet()) {
            try { updateById.put(Long.parseLong(e.getKey()), e.getValue()); } catch (NumberFormatException ignored) {}
        }
        Map<String, String> result = new LinkedHashMap<>();
        Map<Long, ScanComponent> componentsById = new LinkedHashMap<>();
        for (ScanComponent c : report.components()) {
            componentsById.put(c.id(), c);
        }

        // Direct dependency upgrades use the existing version patch flow.
        Map<String, List<ScanComponent>> directByFile = new LinkedHashMap<>();
        Map<String, String> allDirectUpdates = new LinkedHashMap<>();
        for (ScanComponent c : report.components()) {
            if (!c.direct() || c.snapshot() || c.sourceFilePath() == null) continue;
            if (!updateById.containsKey(c.id())) continue;
            directByFile.computeIfAbsent(c.sourceFilePath(), k -> new ArrayList<>()).add(c);
            String coord = c.coordinate().groupId() + ":" + c.coordinate().artifactId();
            allDirectUpdates.put(coord, updateById.get(c.id()));
        }
        for (Map.Entry<String, List<ScanComponent>> entry : directByFile.entrySet()) {
            String content = sourcePoms.get(entry.getKey());
            if (content == null) continue;
            Map<String, String> fileUpdates = new LinkedHashMap<>();
            for (ScanComponent c : entry.getValue()) {
                String coord = c.coordinate().groupId() + ":" + c.coordinate().artifactId();
                fileUpdates.put(coord, updateById.get(c.id()));
            }
            result.put(entry.getKey(), patchPomXml(content, fileUpdates));
        }

        // Sync dep-management pins in the root POM to match any direct dep upgrades,
        // so the root POM never overrides a version that was just upgraded in a child module.
        RemediationApplier applier = new RemediationApplier();
        String rootPomKey = selectRootPomKey(sourcePoms, workingTreePath);
        if (rootPomKey != null && !allDirectUpdates.isEmpty()) {
            String rootContent = result.containsKey(rootPomKey) ? result.get(rootPomKey) : sourcePoms.get(rootPomKey);
            if (rootContent != null) {
                String updated = patchPomXml(rootContent, allDirectUpdates);
                if (!updated.equals(rootContent)) {
                    result.put(rootPomKey, updated);
                }
            }
        }

        // Transitive convergence selections are translated into dependencyManagement pins
        // plus exclusions on the parents introducing the non-selected versions.
        for (Map.Entry<Long, String> entry : updateById.entrySet()) {
            ScanComponent component = componentsById.get(entry.getKey());
            if (component == null || component.direct() || component.snapshot()) {
                continue;
            }
            String selectedVersion = entry.getValue();
            if (selectedVersion == null || selectedVersion.isBlank() || selectedVersion.equals(component.version())) {
                continue;
            }
            boolean changed = false;
            TransitiveConflictFinding finding = findMatchingConflict(conflictsByKey, component);

            if (rootPomKey != null) {
                String content = result.containsKey(rootPomKey) ? result.get(rootPomKey) : sourcePoms.get(rootPomKey);
                if (content != null) {
                    String updated = applier.applyDependencyManagementPin(
                            content, component.coordinate().groupId(), component.coordinate().artifactId(), selectedVersion,
                            "Enforcer dependency convergence fix by RedKite");
                    if (!updated.equals(content)) {
                        result.put(rootPomKey, updated);
                        changed = true;
                    }
                }
            }

            if (finding != null) {
                for (ConflictCandidateAction action : finding.candidateActions()) {
                    if (action.type() != ConflictCandidateAction.ActionType.ADD_EXCLUSION) {
                        continue;
                    }
                    if (selectedVersion.equals(action.version())) {
                        continue;
                    }
                    for (String filePath : sourcePoms.keySet()) {
                        String content = result.containsKey(filePath) ? result.get(filePath) : sourcePoms.get(filePath);
                        if (content == null) continue;
                        String updated = applier.applyExclusion(
                                content,
                                action.parentGroupId(), action.parentArtifactId(),
                                finding.groupId(), finding.artifactId(),
                                "Enforcer dependency convergence fix by RedKite");
                        if (!updated.equals(content)) {
                            result.put(filePath, updated);
                            changed = true;
                        }
                    }
                }
            }

            if (!changed) {
                continue;
            }
        }
        result.entrySet().removeIf(e -> sourcePoms.containsKey(e.getKey()) && sourcePoms.get(e.getKey()).equals(e.getValue()));
        return result;
    }

    private String selectRootPomKey(Map<String, String> sourcePoms, String workingTreePath) {
        if (sourcePoms.containsKey("pom.xml")) {
            return "pom.xml";
        }
        String best = null;
        int bestDepth = Integer.MAX_VALUE;
        for (String key : sourcePoms.keySet()) {
            if (key == null || !key.endsWith("pom.xml")) {
                continue;
            }
            int depth = (int) key.chars().filter(ch -> ch == '/').count();
            if (best == null || depth < bestDepth || (depth == bestDepth && key.length() < best.length())) {
                best = key;
                bestDepth = depth;
            }
        }
        if (best != null) {
            return best;
        }
        return sourcePoms.isEmpty() ? null : sourcePoms.keySet().iterator().next();
    }

    private static String patchPomXml(String content, Map<String, String> versionUpdates) throws Exception {
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(content)));
        Element root = doc.getDocumentElement();

        // Collect <parent>, <dependency>, and <plugin> elements to patch
        NodeList allElements = doc.getElementsByTagName("*");
        List<Element> patchTargets = new ArrayList<>();
        for (int i = 0; i < allElements.getLength(); i++) {
            Node n = allElements.item(i);
            if (n instanceof Element e && ("parent".equals(e.getNodeName()) || "dependency".equals(e.getNodeName()) || "plugin".equals(e.getNodeName()))) {
                patchTargets.add(e);
            }
        }

        // Pass 1: register property names already claimed by existing property references,
        // so literal-to-property normalisation in pass 2 doesn't collide with them.
        Map<String, String> propNameForCoord = new LinkedHashMap<>();
        for (Element dep : patchTargets) {
            String g = childText(dep, "groupId"), a = childText(dep, "artifactId");
            if (g == null || a == null) continue;
            if ("plugin".equals(dep.getNodeName()) && g.trim().isEmpty()) g = "org.apache.maven.plugins";
            g = g.trim(); a = a.trim();
            Node vn = directChildVersion(dep);
            if (vn == null) continue;
            String vt = vn.getTextContent().trim();
            if (vt.startsWith("${") && vt.endsWith("}"))
                propNameForCoord.put(g + ":" + a, vt.substring(2, vt.length() - 1));
        }

        // Pass 2: apply patches.
        // Every dependency or plugin with a literal <version> is normalised to a ${prop} reference.
        // Deps with existing property references just have their property value updated (if upgrading).
        // BOM-managed deps (no <version>) only get an explicit version added when upgrading.
        // propUpgradeTo tracks what each property is being set to, so we can detect the case where
        // two deps share a property ref but the user chose different upgrade targets for them.
        Map<String, String> propUpgradeTo = new LinkedHashMap<>();
        for (Element dep : patchTargets) {
            String g = childText(dep, "groupId"), a = childText(dep, "artifactId");
            if (g == null || a == null) continue;
            if ("plugin".equals(dep.getNodeName()) && g.trim().isEmpty()) g = "org.apache.maven.plugins";
            g = g.trim(); a = a.trim();
            String coord = g + ":" + a;
            String upgrade = versionUpdates.get(coord);
            Node versionNode = directChildVersion(dep);

            if (versionNode == null) {
                // BOM-managed: add explicit <version> only when upgrading
                if (upgrade != null) {
                    Element versionEl = doc.createElement("version");
                    versionEl.setTextContent(upgrade);
                    dep.appendChild(versionEl);
                }
                continue;
            }

            String versionText = versionNode.getTextContent().trim();
            if (versionText.isEmpty()) continue;

            if (versionText.startsWith("${") && versionText.endsWith("}")) {
                // Existing property reference: update the property value when upgrading.
                // If two deps share the same property ref but target different versions,
                // give the second dep its own independent property rather than silently
                // overwriting the shared one.
                if (upgrade != null) {
                    String propName = versionText.substring(2, versionText.length() - 1);
                    String alreadySetTo = propUpgradeTo.get(propName);
                    if (alreadySetTo != null && !alreadySetTo.equals(upgrade)) {
                        // Conflict: create an independent property for this dep
                        String newPropName = assignPropName(a, g, propNameForCoord);
                        propNameForCoord.put(coord, newPropName);
                        setProperty(doc, findOrCreateProperties(doc, root), newPropName, upgrade);
                        versionNode.setTextContent("${" + newPropName + "}");
                        propUpgradeTo.put(newPropName, upgrade);
                    } else {
                        setProperty(doc, findOrCreateProperties(doc, root), propName, upgrade);
                        propUpgradeTo.put(propName, upgrade);
                    }
                }
            } else {
                // Literal version: normalise to a property reference.
                // Use the upgrade version if selected, otherwise keep the current version.
                // Exception: <parent> versions are left as literals when not being upgraded —
                // it's unusual and disruptive to normalise a parent version to a property
                // just because other deps in the same POM are being upgraded.
                if (upgrade == null && "parent".equals(dep.getNodeName())) continue;
                String effectiveVersion = upgrade != null ? upgrade : versionText;
                String propName = propNameForCoord.get(coord);
                if (propName == null) {
                    propName = assignPropName(a, g, propNameForCoord);
                    propNameForCoord.put(coord, propName);
                }
                setProperty(doc, findOrCreateProperties(doc, root), propName, effectiveVersion);
                versionNode.setTextContent("${" + propName + "}");
            }
        }

        stripWhitespaceNodes(doc);
        var tf = TransformerFactory.newInstance();
        var transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    private static Node directChildVersion(Element dep) {
        for (int j = 0; j < dep.getChildNodes().getLength(); j++) {
            Node child = dep.getChildNodes().item(j);
            if ("version".equals(child.getNodeName())) return child;
        }
        return null;
    }

    private static String assignPropName(String a, String g, Map<String, String> propNameForCoord) {
        String shortName = a + ".version";
        if (!propNameForCoord.containsValue(shortName)) return shortName;
        return g + "." + a + ".version";
    }

    private static Element findOrCreateProperties(Document doc, Element root) {
        for (int i = 0; i < root.getChildNodes().getLength(); i++) {
            Node n = root.getChildNodes().item(i);
            if (n instanceof Element e && "properties".equals(e.getNodeName())) return e;
        }
        Element propertiesEl = doc.createElement("properties");
        Node insertBefore = null;
        for (String anchor : List.of("dependencyManagement", "dependencies", "build")) {
            NodeList nl = root.getElementsByTagName(anchor);
            if (nl.getLength() > 0) { insertBefore = nl.item(0); break; }
        }
        if (insertBefore != null) {
            root.insertBefore(doc.createTextNode("\n  "), insertBefore);
            root.insertBefore(propertiesEl, insertBefore);
        } else {
            root.appendChild(doc.createTextNode("\n  "));
            root.appendChild(propertiesEl);
        }
        return propertiesEl;
    }

    private static void stripWhitespaceNodes(Node node) {
        for (int i = node.getChildNodes().getLength() - 1; i >= 0; i--) {
            Node child = node.getChildNodes().item(i);
            if (child.getNodeType() == Node.TEXT_NODE && child.getTextContent().isBlank()) {
                node.removeChild(child);
            } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                stripWhitespaceNodes(child);
            }
        }
    }

    private static Map<String, String> buildModuleArtifactIds(Map<String, String> sourcePoms) {
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : sourcePoms.entrySet()) {
            String artifactId = extractArtifactId(e.getValue());
            result.put(e.getKey(), artifactId != null ? artifactId : modulePathLabel(e.getKey()));
        }
        return result;
    }

    private static String modulePathLabel(String mod) {
        if ("pom.xml".equals(mod) || "(root)".equals(mod)) return "(root)";
        if (mod.endsWith("/pom.xml")) return mod.substring(0, mod.length() - 8);
        return mod;
    }

    private static String extractArtifactId(String pomXml) {
        int searchFrom = 0;
        int parentEnd = pomXml.indexOf("</parent>");
        if (parentEnd >= 0) searchFrom = parentEnd + 9;
        int start = pomXml.indexOf("<artifactId>", searchFrom);
        if (start < 0) return null;
        int end = pomXml.indexOf("</artifactId>", start);
        if (end < 0) return null;
        return pomXml.substring(start + 12, end).trim();
    }

    private static void setProperty(Document doc, Element propertiesEl, String name, String value) {
        NodeList existing = propertiesEl.getElementsByTagName(name);
        if (existing.getLength() > 0) {
            existing.item(0).setTextContent(value);
        } else {
            propertiesEl.appendChild(doc.createTextNode("\n    "));
            Element prop = doc.createElement(name);
            prop.setTextContent(value);
            propertiesEl.appendChild(prop);
        }
    }

    private static String childText(Element parent, String tagName) {
        NodeList nl = parent.getElementsByTagName(tagName);
        return nl.getLength() > 0 ? nl.item(0).getTextContent() : null;
    }

    private static String queryParam(String query, String name) {
        if (query == null) return null;
        for (String part : query.split("&")) {
            int eq = part.indexOf('=');
            if (eq > 0 && part.substring(0, eq).equals(name)) {
                return URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static void sendHtml(HttpExchange exchange, int status, String body) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/html; charset=utf-8");
        sendText(exchange, status, body);
    }

    private static void sendText(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static <T extends java.io.Serializable> void sendBase64(HttpExchange exchange, int status, T body) throws IOException {
        String encoded = SerializationSupport.toBase64(body);
        byte[] bytes = encoded.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream in = exchange.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String jsString(String value) {
        if (value == null) return "''";
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }

    /** Parse a flat JSON object whose keys and values are all strings, e.g. {"a/pom.xml":"content"}. */
    private static Map<String, String> parseJsonStringMap(String json) {
        Map<String, String> result = new LinkedHashMap<>();
        if (json == null || json.isBlank()) return result;
        int i = 0;
        while (i < json.length()) {
            int kq1 = json.indexOf('"', i);
            if (kq1 < 0) break;
            String key = readJsonString(json, kq1 + 1);
            int kq2 = kq1 + 1 + key.length() + 1;
            int colon = json.indexOf(':', kq2);
            if (colon < 0) break;
            int vq1 = json.indexOf('"', colon + 1);
            if (vq1 < 0) break;
            String value = readJsonString(json, vq1 + 1);
            result.put(key, value);
            i = vq1 + 1 + value.length() + 1;
        }
        return result;
    }

    private static String readJsonString(String json, int from) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') break;
            if (c == '\\' && i + 1 < json.length()) {
                char n = json.charAt(++i);
                switch (n) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    default -> sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> result = new LinkedHashMap<>();
        if (body == null || body.isBlank()) {
            return result;
        }
        for (String pair : body.split("&")) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String key = urlDecode(pair.substring(0, idx));
                String value = urlDecode(pair.substring(idx + 1));
                result.put(key, value);
            }
        }
        return result;
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private String renderDependencyTree(ScanReport report) {
        Map<Long, ScanComponent> componentsById = new LinkedHashMap<>();
        for (ScanComponent component : report.components()) {
            componentsById.put(component.id(), component);
        }
        Map<String, List<DependencyEdge>> childrenByParent = new LinkedHashMap<>();
        for (DependencyEdge edge : report.dependencyEdges()) {
            childrenByParent.computeIfAbsent(edge.fromComponentId(), key -> new ArrayList<>()).add(edge);
        }
        StringBuilder html = new StringBuilder();
        Map<String, DependencyEdge> roots = new LinkedHashMap<>();
        for (DependencyEdge edge : report.dependencyEdges()) {
            if (edge.fromComponentId().startsWith("module:")) {
                roots.putIfAbsent(edge.toComponentId(), edge);
            }
        }
        if (roots.isEmpty()) {
            html.append("<p class=\"muted\">No dependency tree data available.</p>");
            return html.toString();
        }
        html.append("<ul class=\"tree\">");
        for (DependencyEdge rootEdge : roots.values()) {
            html.append(renderTreeNode(rootEdge, componentsById, childrenByParent, new java.util.HashSet<>()));
        }
        html.append("</ul>");
        return html.toString();
    }

    // ---- Stage 6: Remediation-first single-column view ----

    private record ComponentView(
            ScanComponent component,
            RemediationStatus status,
            MetadataResult versionMetadata,
            UpgradeRecommendation recommendation,
            List<VulnerabilityFinding> findings,
            boolean canUpgradeViaDirect,
            TransitiveConflictFinding convergenceFinding) {}

    private static String enforcerBadge(Store.EnforcerResultEntry e) {
        if (e == null) return "";
        return switch (e.status()) {
            case ENFORCER_RUN_PASSED ->
                "<span class=\"badge success\" title=\"Dependency management check passed\">Dep. mgmt ✓</span>";
            case ENFORCER_RUN_FAILED_WITH_FINDINGS -> {
                int n = e.findings().size();
                List<TransitiveConflictFinding> phase2 = e.phase2Findings();
                if (phase2 != null && phase2.isEmpty()) {
                    // All conflicts resolved by auto-fix
                    yield "<span class=\"badge success\" title=\"" + n + " conflict" + (n == 1 ? "" : "s")
                        + " resolved by dep-management pins\">"
                        + n + " conflict" + (n == 1 ? "" : "s") + " resolved ✓</span>";
                }
                if (phase2 != null && !phase2.isEmpty()) {
                    yield "<span class=\"badge\" style=\"background:rgba(220,38,38,.16);border-color:rgba(220,38,38,.4);color:#fca5a5\""
                        + " title=\"" + phase2.size() + " conflict" + (phase2.size() == 1 ? "" : "s") + " remain unresolvable\">"
                        + phase2.size() + " unresolvable</span>";
                }
                yield "<span class=\"badge\" style=\"background:rgba(220,38,38,.16);border-color:rgba(220,38,38,.4);color:#fca5a5\""
                    + " title=\"Dependency management check failed\">"
                    + n + " convergence " + (n == 1 ? "conflict" : "conflicts") + "</span>";
            }
            default -> "";
        };
    }

    private static String scanOverlayHtml() {
        return "<div id=\"scan-overlay\" class=\"scan-overlay\" style=\"display:none\">"
             + "<div class=\"scan-overlay-box\">"
             + "<div style=\"display:flex;align-items:center;gap:10px\">"
             + "<div class=\"scan-spinner\"></div>"
             + "<span>Analysing…</span>"
             + "</div>"
             + "<div id=\"scan-phases\" style=\"width:300px;display:flex;flex-direction:column;gap:10px\"></div>"
             + "</div></div>";
    }

    private static String applyOverlayHtml() {
        return "<div id=\"apply-overlay\" class=\"scan-overlay\" style=\"display:none\">"
             + "<div class=\"scan-overlay-box\">"
             + "<div style=\"display:flex;align-items:center;gap:10px\">"
             + "<div class=\"scan-spinner\"></div>"
             + "<span>Applying fixes…</span>"
             + "</div>"
             + "<div id=\"apply-progress-count\" style=\"font-size:.85rem;color:var(--muted);font-weight:400\">0 / 0</div>"
             + "<div class=\"scan-phase-track\" style=\"width:300px\">"
             + "<div id=\"apply-progress-bar\" class=\"scan-phase-fill active\" style=\"width:0%\"></div>"
             + "</div>"
             + "<div id=\"apply-progress-text\" style=\"font-size:.78rem;color:var(--muted);font-weight:400;"
             + "font-family:ui-monospace,monospace;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\"></div>"
             + "</div></div>";
    }

    private String renderEnforcerSection(String scanId, Store.EnforcerResultEntry entry) {
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
        if (phase2Pins.isEmpty() && !findings.isEmpty()) {
            // Phase 2 hasn't run or data predates this feature — compute planned pins for display
            phase2Pins = findings.stream()
                    .map(f -> {
                        String w = computeWinnerVersion(f, "");
                        return w != null ? f.groupId() + ":" + f.artifactId() + ":" + w : null;
                    })
                    .filter(s -> s != null)
                    .toList();
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

    private String renderRemediationView(ScanReport report, String scanId, boolean pomExists, Map<String, String> moduleArtifactIds, Map<String, String> sourcePoms, Map<String, List<TransitiveConflictFinding>> conflictsByKey) {
        ReportSummary summary = RemediationClassifier.summarize(report);
        List<ScanComponent> components = report.components();
        if (components.isEmpty()) {
            return "<p class=\"muted\">No dependency inventory is available for this scan.</p>";
        }

        // Build lookup maps
        Map<Long, UpgradeRecommendation> recByComponent = new LinkedHashMap<>();
        for (UpgradeRecommendation rec : report.recommendations()) {
            if (!rec.affectedComponentIds().isEmpty()) {
                for (Long id : rec.affectedComponentIds()) {
                    recByComponent.put(id, rec);
                }
            } else {
                recByComponent.put(rec.id(), rec);
            }
        }
        Map<Long, MetadataResult> versionMetaByComponent = new LinkedHashMap<>();
        for (MetadataResult m : report.metadataResults()) {
            if (m.metadataType() == MetadataType.VERSION) {
                versionMetaByComponent.put(m.componentId(), m);
            }
        }
        Map<String, List<VulnerabilityFinding>> vulnsByKey = new LinkedHashMap<>();
        for (VulnerabilityFinding f : report.vulnerabilityFindings()) {
            vulnsByKey.computeIfAbsent(
                    f.coordinate().groupId() + ":" + f.coordinate().artifactId() + "@" + f.affectedVersion(),
                    k -> new ArrayList<>()).add(f);
        }

        // Deduplicate and classify
        Map<String, ScanComponent> unique = new LinkedHashMap<>();
        for (ScanComponent c : components) {
            String key = c.sourceFilePath() + "|" + c.coordinate().groupId() + ":"
                    + c.coordinate().artifactId() + "|" + c.version() + "|" + c.direct();
            unique.putIfAbsent(key, c);
        }

        // Build id→component index and reverse edge map (child → parent component ids)
        Map<Long, ScanComponent> componentsById = new LinkedHashMap<>();
        for (ScanComponent c : unique.values()) componentsById.put(c.id(), c);
        Map<Long, List<Long>> parentIdsByChild = new LinkedHashMap<>();
        Map<Long, List<Long>> childrenByParent = new LinkedHashMap<>();
        for (DependencyEdge edge : report.dependencyEdges()) {
            if (edge.fromComponentId() == null || edge.fromComponentId().startsWith("module:")) continue;
            try {
                long fromId = Long.parseLong(edge.fromComponentId());
                long toId = Long.parseLong(edge.toComponentId());
                parentIdsByChild.computeIfAbsent(toId, k -> new ArrayList<>()).add(fromId);
                childrenByParent.computeIfAbsent(fromId, k -> new ArrayList<>()).add(toId);
            } catch (NumberFormatException ignored) {}
        }

        List<ComponentView> views = new ArrayList<>();
        for (ScanComponent c : unique.values()) {
            RemediationStatus status = RemediationClassifier.classify(
                    c, report.vulnerabilityFindings(), report.recommendations(), report.metadataResults());
            MetadataResult versionMeta = versionMetaByComponent.get(c.id());
            UpgradeRecommendation rec = recByComponent.get(c.id());
            TransitiveConflictFinding conflict = findMatchingConflict(conflictsByKey, c);
            List<VulnerabilityFinding> vulns = vulnsByKey.getOrDefault(
                    c.coordinate().groupId() + ":" + c.coordinate().artifactId() + "@" + c.version(), List.of());
            boolean canUpgradeViaDirect = false;
            if (!c.direct() && rec != null) {
                for (long parentId : parentIdsByChild.getOrDefault(c.id(), List.of())) {
                    ScanComponent parent = componentsById.get(parentId);
                    if (parent != null && parent.direct()) {
                        UpgradeRecommendation parentRec = recByComponent.get(parentId);
                        if (parentRec != null && sameMajor(parent.version(), parentRec.targetVersion())) {
                            canUpgradeViaDirect = true;
                            break;
                        }
                    }
                }
            }
            views.add(new ComponentView(c, status, versionMeta, rec, vulns, canUpgradeViaDirect, conflict));
        }

        // Sort: CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN advisory → SNAPSHOT → STALE → VERSION_MGMT → UPGRADE → CLEAN
        // Within same bucket: direct before transitive, then alphabetical
        views.sort((a, b) -> {
            int ka = remediationSortKey(a);
            int kb = remediationSortKey(b);
            if (ka != kb) return Integer.compare(ka, kb);
            if (a.component().direct() != b.component().direct()) return a.component().direct() ? -1 : 1;
            return a.component().coordinate().artifactId()
                    .compareTo(b.component().coordinate().artifactId());
        });

        StringBuilder html = new StringBuilder();

        // Summary banner
        html.append("<div class=\"rem-banner\">");
        html.append("<div class=\"rem-banner-row\">");
        html.append("<span class=\"rem-stat\"><strong>").append(summary.totalComponents()).append("</strong> components</span>");
        if (summary.needsRemediation() > 0) {
            html.append("<span class=\"rem-stat\"><strong>").append(summary.needsRemediation()).append("</strong> need remediation</span>");
        }
        html.append("<span class=\"rem-stat muted\">").append(summary.clean()).append(" clean</span>");
        html.append("</div>");
        html.append("<div class=\"rem-banner-row\">");
        if (summary.criticalCount() > 0) html.append("<span class=\"sev-chip sev-critical\">&#9762; ").append(summary.criticalCount()).append(" Critical</span>");
        if (summary.highCount() > 0) html.append("<span class=\"sev-chip sev-high\">&#9760; ").append(summary.highCount()).append(" High</span>");
        if (summary.mediumCount() > 0) html.append("<span class=\"sev-chip sev-medium\">&#9888; ").append(summary.mediumCount()).append(" Medium</span>");
        if (summary.lowCount() > 0) html.append("<span class=\"sev-chip sev-low\">&#x2139; ").append(summary.lowCount()).append(" Low</span>");
        if (summary.unknownCount() > 0) html.append("<span class=\"sev-chip sev-unknown\">? ").append(summary.unknownCount()).append(" Unknown</span>");
        if (summary.snapshotCount() > 0) html.append("<span class=\"sev-chip sev-snap\">&#9889; ").append(summary.snapshotCount()).append(" Snapshot</span>");
        if (summary.staleMetadataCount() > 0) html.append("<span class=\"sev-chip sev-stale\">&#8635; ").append(summary.staleMetadataCount()).append(" Stale metadata</span>");
        html.append("</div>");
        html.append("</div>");

        // Build module index — seed from all known source POMs so empty modules still appear
        Map<String, List<ComponentView>> byModule = new LinkedHashMap<>();
        for (String modPath : moduleArtifactIds.keySet()) {
            byModule.put(modPath, new ArrayList<>());
        }
        for (ComponentView v : views) {
            String mod = v.component().modulePath() == null || v.component().modulePath().isBlank()
                    ? "(root)" : v.component().modulePath();
            byModule.computeIfAbsent(mod, k -> new ArrayList<>()).add(v);
        }

        // Module dropdown — root POM (shallowest path, typically "pom.xml") listed first
        if (byModule.size() > 1) {
            List<String> moduleOrder = new ArrayList<>(byModule.keySet());
            moduleOrder.sort((a, b) -> {
                int depthA = a.equals("(root)") ? 0 : (int) a.chars().filter(c -> c == '/').count();
                int depthB = b.equals("(root)") ? 0 : (int) b.chars().filter(c -> c == '/').count();
                if (depthA != depthB) return Integer.compare(depthA, depthB);
                return a.compareTo(b);
            });
            String firstModule = moduleOrder.stream()
                    .filter(m -> byModule.getOrDefault(m, List.of()).stream().anyMatch(this::isDefaultVisibleRemediationCard))
                    .findFirst()
                    .orElseGet(() -> moduleOrder.stream()
                            .filter(m -> !byModule.getOrDefault(m, List.of()).isEmpty())
                            .findFirst()
                            .orElse(moduleOrder.get(0)));
            html.append("<script>remModule=").append(jsString(firstModule)).append(";</script>");
            html.append("<select class=\"rem-module-select\" onchange=\"filterRemediationModule(this.value)\">");
            for (String mod : moduleOrder) {
                String label = moduleArtifactIds.getOrDefault(mod, modulePathLabel(mod));
                html.append("<option value=\"").append(escape(mod)).append("\"")
                        .append(mod.equals(firstModule) ? " selected" : "").append(">")
                        .append(escape(label)).append("</option>");
            }
            html.append("</select>");
        }

        // Filter toggle: CVE | Conflict | Snapshot | Upgrade | Transitive | Clean | All
        long cveCount = views.stream().filter(v -> v.status().hasVulnerability()).count();
        long conflictCount = views.stream().filter(v -> v.convergenceFinding() != null).count();
        long snapshotCount = views.stream().filter(v -> v.status().isSnapshot()).count();
        long transitiveCount = views.stream().filter(v -> !v.component().direct() && !v.component().snapshot()).count();
        long cleanCount = views.stream().filter(v -> !v.status().needsRemediation() && v.convergenceFinding() == null).count();
        html.append("<div class=\"rem-toggle\">");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"cve\" onclick=\"setRemediationMode('cve')\">CVE <span class=\"tab-count\">").append(cveCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"conflict\" onclick=\"setRemediationMode('conflict')\">&#9651; Conflict <span class=\"tab-count\">").append(conflictCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"snapshot\" onclick=\"setRemediationMode('snapshot')\">Snapshot <span class=\"tab-count\">").append(snapshotCount).append("</span></button>");
        html.append("<button class=\"button primary rem-toggle-btn\" type=\"button\" data-mode=\"upgrade\" onclick=\"setRemediationMode('upgrade')\">Upgradeable <span class=\"tab-count\" id=\"upg-all-count\">0</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"transitive\" onclick=\"setRemediationMode('transitive')\">Transitive <span class=\"tab-count\">").append(transitiveCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"clean\" onclick=\"setRemediationMode('clean')\">Clean <span class=\"tab-count\">").append(cleanCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"all\" onclick=\"setRemediationMode('all')\">All <span class=\"tab-count\">").append(views.size()).append("</span></button>");
        html.append("</div>");

        // Apply bar
        html.append("<div class=\"pom-actions\">");
        html.append("<button class=\"button primary\" type=\"button\" id=\"apply-btn\"");
        if (!pomExists) {
            html.append(" disabled data-nopom=\"true\" title=\"No source POMs available for this scan\"");
        } else {
            html.append(" disabled");
        }
        html.append(" onclick=\"applyPomChanges()\">Apply selected</button>");
        html.append("</div>");

        // Emit component index + edge map for client-side tree expansion
        html.append("<script>const rk_scanId=").append(jsonStr(scanId)).append(";const rk_comps={");
        boolean firstComp = true;
        for (ComponentView v : views) {
            if (!firstComp) html.append(",");
            firstComp = false;
            ScanComponent c = v.component();
            RemediationStatus s = v.status();
            html.append("\"").append(c.id()).append("\":{")
                .append("\"g\":").append(jsonStr(c.coordinate().groupId())).append(",")
                .append("\"a\":").append(jsonStr(c.coordinate().artifactId())).append(",")
                .append("\"v\":").append(jsonStr(c.version())).append(",")
                .append("\"icon\":").append(jsonStr(s.highestSeverity().icon())).append(",")
                .append("\"label\":").append(jsonStr(s.highestSeverity().label())).append(",")
                .append("\"sev\":").append(jsonStr(s.highestSeverity().name().toLowerCase())).append(",")
                .append("\"kind\":").append(jsonStr(c.snapshot() ? "snapshot" : c.direct() ? "declared" : "transitive")).append(",")
                .append("\"clean\":").append(!s.needsRemediation()).append(",")
                .append("\"hasvuln\":").append(s.hasVulnerability());
            if (v.recommendation() != null && v.recommendation().targetVersion() != null) {
                html.append(",\"rec\":").append(jsonStr(v.recommendation().targetVersion()));
            }
            if (v.versionMetadata() != null) {
                String latest = v.versionMetadata().latestVersion();
                if (latest != null && !latest.isBlank() && !"unknown".equalsIgnoreCase(latest)
                        && !latest.equals(c.version())) {
                    html.append(",\"latest\":").append(jsonStr(latest));
                }
            }
            html.append("}");
        }
        html.append("};const rk_edges={");
        boolean firstEdge = true;
        for (Map.Entry<Long, List<Long>> entry : parentIdsByChild.entrySet()) {
            if (!firstEdge) html.append(",");
            firstEdge = false;
            html.append("\"").append(entry.getKey()).append("\":[");
            boolean firstChild = true;
            for (Long cid : entry.getValue()) {
                if (!firstChild) html.append(",");
                firstChild = false;
                html.append(cid);
            }
            html.append("]");
        }
        html.append("};");

        // Build rk_propGroups: "filePath:propName" → [compId, ...] for shared property references.
        // rk_compPropKey: compId → "filePath:propName" (only for comps in a shared-prop group).
        // Used client-side to sync sibling dropdowns when the user changes a version.
        {
            Map<String, Long> coordFileKey = new LinkedHashMap<>();
            for (ScanComponent c : report.components()) {
                if (!c.direct() || c.sourceFilePath() == null) continue;
                coordFileKey.put(c.sourceFilePath() + "|" + c.coordinate().groupId() + ":" + c.coordinate().artifactId(), c.id());
            }
            Map<String, List<Long>> propGroups = new LinkedHashMap<>();
            Map<Long, String> compPropKey = new LinkedHashMap<>();
            for (Map.Entry<String, String> pomEntry : sourcePoms.entrySet()) {
                String filePath = pomEntry.getKey();
                try {
                    var dbf2 = DocumentBuilderFactory.newInstance();
                    dbf2.setNamespaceAware(false);
                    Document pdoc = dbf2.newDocumentBuilder().parse(new InputSource(new StringReader(pomEntry.getValue())));
                    NodeList nl = pdoc.getElementsByTagName("*");
                    for (int i = 0; i < nl.getLength(); i++) {
                        if (!(nl.item(i) instanceof Element de)) continue;
                        if (!"dependency".equals(de.getNodeName()) && !"plugin".equals(de.getNodeName())) continue;
                        String pg = childText(de, "groupId"), pa = childText(de, "artifactId");
                        if (pg == null || pa == null) continue;
                        if ("plugin".equals(de.getNodeName()) && pg.trim().isEmpty()) pg = "org.apache.maven.plugins";
                        pg = pg.trim(); pa = pa.trim();
                        Node pvn = directChildVersion(de);
                        if (pvn == null) continue;
                        String pvt = pvn.getTextContent().trim();
                        if (!pvt.startsWith("${") || !pvt.endsWith("}")) continue;
                        String propName = pvt.substring(2, pvt.length() - 1);
                        Long cid = coordFileKey.get(filePath + "|" + pg + ":" + pa);
                        if (cid == null) continue;
                        String groupKey = filePath + ":" + propName;
                        propGroups.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(cid);
                        compPropKey.put(cid, groupKey);
                    }
                } catch (Exception ignored) {}
            }
            // Only emit groups with 2+ members; single-member groups need no syncing
            html.append("const rk_propGroups={");
            boolean fg = true;
            for (Map.Entry<String, List<Long>> e : propGroups.entrySet()) {
                if (e.getValue().size() < 2) continue;
                if (!fg) html.append(",");
                fg = false;
                html.append(jsonStr(e.getKey())).append(":[");
                for (int i = 0; i < e.getValue().size(); i++) {
                    if (i > 0) html.append(",");
                    html.append(e.getValue().get(i));
                }
                html.append("]");
            }
            html.append("};const rk_compPropKey={");
            boolean fk = true;
            for (Map.Entry<Long, String> e : compPropKey.entrySet()) {
                if (!propGroups.containsKey(e.getValue()) || propGroups.get(e.getValue()).size() < 2) continue;
                if (!fk) html.append(",");
                fk = false;
                html.append("\"").append(e.getKey()).append("\":").append(jsonStr(e.getValue()));
            }
            html.append("};");
        }
        // Coordinate groups: g:a → [compId, ...] for cross-POM sibling syncing
        {
            Map<String, List<Long>> coordGroups = new LinkedHashMap<>();
            for (ComponentView v : views) {
                ScanComponent c = v.component();
                if (c.coordinate() == null) continue;
                String coord = c.coordinate().groupId() + ":" + c.coordinate().artifactId();
                coordGroups.computeIfAbsent(coord, k -> new ArrayList<>()).add(c.id());
            }
            html.append("const rk_coordGroups={");
            boolean first = true;
            for (Map.Entry<String, List<Long>> e : coordGroups.entrySet()) {
                if (e.getValue().size() < 2) continue;
                if (!first) html.append(",");
                first = false;
                html.append(jsonStr(e.getKey())).append(":[");
                for (int i = 0; i < e.getValue().size(); i++) {
                    if (i > 0) html.append(",");
                    html.append(e.getValue().get(i));
                }
                html.append("]");
            }
            html.append("};");
        }
        html.append("</script>");

        // Component cards
        html.append("<div class=\"rem-list\">");
        for (ComponentView view : views) {
            String mod = view.component().modulePath() == null || view.component().modulePath().isBlank()
                    ? "(root)" : view.component().modulePath();
            boolean hasParents = !parentIdsByChild.getOrDefault(view.component().id(), List.of()).isEmpty();
            html.append(renderComponentCard(view, mod, hasParents, vulnsByKey));
        }
        html.append("</div>");

        // POM preview modal
        html.append("<div id=\"pom-modal\" class=\"pom-modal\" style=\"display:none\">");
        html.append("<div class=\"pom-modal-backdrop\" onclick=\"closePomModal()\"></div>");
        html.append("<div class=\"pom-modal-box\">");
        html.append("<div class=\"pom-modal-head\">");
        html.append("<div style=\"display:flex;align-items:center;gap:10px;min-width:0;overflow:hidden\">");
        html.append("<span id=\"pom-modal-filename\" class=\"pom-modal-filename\"></span>");
        html.append("<select id=\"pom-file-sel\" style=\"display:none;padding:4px 10px;border-radius:8px;"
                + "border:1px solid var(--line);background:var(--surf-nav);color:var(--text);"
                + "font-size:.82rem;font-family:ui-monospace,monospace;cursor:pointer\" onchange=\"switchPomFile(this.value)\"></select>");
        html.append("</div>");
        html.append("<div style=\"display:flex;gap:8px;flex-shrink:0\">");
        html.append("<button class=\"button\" type=\"button\" onclick=\"copyPomContent()\">Copy</button>");
        html.append("<button class=\"button\" type=\"button\" onclick=\"closePomModal()\">Close</button>");
        html.append("</div></div>");
        html.append("<div class=\"pom-modal-body\"><pre id=\"pom-modal-content\"></pre></div>");
        html.append("</div></div>");

        return html.toString();
    }

    private static boolean isBuildFailed(ScanReport report) {
        List<String> w = report.treeParseWarnings();
        return w != null && w.stream().anyMatch(s -> s.startsWith("[BUILD_FAILED]"));
    }

    private static String scopeLabel(DependencyScope scope) {
        if (scope == null) return "unknown";
        return switch (scope) {
            case PLUGIN_BUILD -> "plugin build";
            default -> scope.name().toLowerCase();
        };
    }

    private static String idsString(List<Long> ids) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (Long id : ids) {
            if (n > 0) sb.append(',');
            sb.append(id);
            if (++n >= 10) break;
        }
        return sb.toString();
    }

    private String renderComponentCard(ComponentView view, String module, boolean hasChildren, Map<String, List<VulnerabilityFinding>> vulnsByKey) {
        ScanComponent comp = view.component();
        RemediationStatus status = view.status();
        boolean hasHighSeverityCve = hasHighOrCriticalCve(view.findings());
        boolean clean = !status.needsRemediation();
        // Non-conflict transitive deps are only actionable for HIGH/CRITICAL CVEs — suppress
        // upgrade-only and low-severity recommendations to avoid noise.
        if (!comp.direct() && view.convergenceFinding() == null && !hasHighSeverityCve && !status.isSnapshot()) {
            clean = true;
        }
        String coordStr = comp.coordinate().groupId() + ":" + comp.coordinate().artifactId();

        StringBuilder html = new StringBuilder();
        String kind = comp.snapshot() ? "snapshot" : comp.direct() ? "declared" : "transitive";
        boolean upgradeOnly = status.hasUpgradeRecommendation()
                && !status.hasVulnerability() && !status.isSnapshot()
                && !status.hasDeclaredVersionDeclaration() && !status.hasStaleMetadata();
        boolean actionableConvergence = view.convergenceFinding() != null;
        String conflictJson = actionableConvergence ? buildConflictJson(view.convergenceFinding()) : "";
        html.append("<div class=\"rem-card").append(clean && !actionableConvergence ? " clean" : "").append("\" data-clean=\"").append(clean && !actionableConvergence)
                .append("\" data-module=\"").append(escape(module))
                .append("\" data-kind=\"").append(kind)
                .append("\" data-hasvuln=\"").append(status.hasVulnerability())
                .append("\" data-upgradeonly=\"").append(upgradeOnly)
                .append("\" data-hasconflict=\"").append(actionableConvergence)
                .append("\" data-coord=\"").append(escape(coordStr))
                .append("\" data-comp-id=\"").append(comp.id());
        if (actionableConvergence) {
            html.append("\" data-conflict='").append(conflictJson).append("'>");
        } else {
            html.append("\">");
        }

        // Header: coordinate + badges
        html.append("<div class=\"rem-header\">");
        html.append("<span class=\"rem-title\">").append(escape(coordStr)).append("</span>");
        html.append("<div class=\"rem-badges\">");
        html.append(severityBadgeHtml(status.highestSeverity(), clean));
        String kindClass = comp.snapshot() ? "warn" : comp.direct() ? "success" : "neutral";
        String kindLabel = comp.snapshot() ? "snapshot" : comp.direct() ? "declared" : "transitive";
        html.append("<span class=\"badge ").append(kindClass).append("\">").append(kindLabel).append("</span>");
        html.append("<span class=\"badge neutral\">").append(scopeLabel(comp.scope())).append("</span>");
        if (actionableConvergence) {
            html.append("<span class=\"badge conflict-badge\">&#9651; Conflict</span>");
        }
        html.append("</div>");
        html.append("</div>");

        // Version info
        html.append("<div class=\"rem-meta\">");
        html.append("<span>Current: <strong>").append(escape(comp.version() != null ? comp.version() : "unknown")).append("</strong></span>");
        if (view.recommendation() != null && !status.isSnapshot()) {
            html.append("<span>&rarr; Recommended: <strong>").append(escape(view.recommendation().targetVersion())).append("</strong></span>");
        }
        if (view.versionMetadata() != null && view.versionMetadata().latestVersion() != null
                && !view.versionMetadata().latestVersion().isBlank()
                && !"unknown".equalsIgnoreCase(view.versionMetadata().latestVersion())) {
            html.append("<span class=\"muted\">(Latest: ").append(escape(view.versionMetadata().latestVersion())).append(")</span>");
        }
        html.append("</div>");

        // CVE identifiers
        if (status.hasVulnerability() && !view.findings().isEmpty()) {
            List<String> allCves = new ArrayList<>();
            for (VulnerabilityFinding f : view.findings()) {
                if (f.cves() != null) allCves.addAll(f.cves());
            }
            if (!allCves.isEmpty()) {
                html.append("<div class=\"rem-cves\">").append(escape(String.join(", ", allCves))).append("</div>");
            }
        }

        // Remediation reason chips
        List<String> otherReasons = status.reasons().stream()
                .filter(r -> !"Upgrade recommended".equals(r)).toList();
        boolean showUpgradeBtn = view.recommendation() != null && !status.isSnapshot();
        boolean showNoUpgradeChip = !comp.direct() && !status.isSnapshot()
                && view.recommendation() == null && view.versionMetadata() != null;
        if (!otherReasons.isEmpty() || showUpgradeBtn || showNoUpgradeChip) {
            html.append("<div class=\"rem-reasons\">");
            for (String reason : otherReasons) {
                html.append("<span class=\"reason-chip\">").append(escape(reason)).append("</span>");
            }
            if (showUpgradeBtn) {
                if (comp.direct()) {
                    html.append("<button class=\"reason-chip reason-chip-btn\" type=\"button\" onclick=\"applyUpgrade(")
                        .append(comp.id()).append(",'").append(escape(view.recommendation().targetVersion())).append("',this)\">")
                        .append("Upgrade to ").append(escape(view.recommendation().targetVersion())).append("</button>");
                } else {
                    String transitiveChip = view.canUpgradeViaDirect() ? "Upgrade available" : "Major upgrade available";
                    html.append("<span class=\"reason-chip\">").append(transitiveChip).append("</span>");
                }
            } else if (showNoUpgradeChip) {
                html.append("<span class=\"reason-chip\">No upgrade available</span>");
            }
            html.append("</div>");
        }

        // Show version selector for: direct deps with metadata or conflict, transitive conflict deps,
        // and transitive deps with HIGH/CRITICAL CVE (where an upgrade is actionable).
        boolean showVersionSelector = view.convergenceFinding() != null
                || (comp.direct() && view.versionMetadata() != null)
                || (!comp.direct() && hasHighSeverityCve && view.versionMetadata() != null);
        if (showVersionSelector) {
            html.append("<div class=\"rem-actions\">");
            if (comp.direct()) {
                String selectorId = "view_" + comp.id();
                List<String> directConflictVersions = view.convergenceFinding() != null
                        ? view.convergenceFinding().conflictingVersions() : List.of();
                String selectedVersion = view.convergenceFinding() != null
                        ? conflictDefaultVersion(view.convergenceFinding(), comp, view.findings(), vulnsByKey, view.versionMetadata())
                        : (view.recommendation() != null ? view.recommendation().targetVersion() : comp.version());
                if (view.convergenceFinding() != null && view.recommendation() != null
                        && view.recommendation().targetVersion() != null
                        && compareVersionsSemantic(view.recommendation().targetVersion(), selectedVersion != null ? selectedVersion : "") > 0) {
                    selectedVersion = view.recommendation().targetVersion();
                }
                html.append(renderVersionSelect(selectorId, comp.coordinate(), comp.version(), selectedVersion,
                        view.versionMetadata(), view.recommendation(), view.findings(), false, directConflictVersions,
                        view.convergenceFinding() != null));
            } else if (view.versionMetadata() != null || view.convergenceFinding() != null) {
                String selectorId = "view_" + comp.id();
                List<String> conflictVersions = view.convergenceFinding() != null
                        ? view.convergenceFinding().conflictingVersions()
                        : List.of();
                String selectedVersion = view.convergenceFinding() != null
                        ? conflictDefaultVersion(view.convergenceFinding(), comp, view.findings(), vulnsByKey, view.versionMetadata())
                        : (view.recommendation() != null ? view.recommendation().targetVersion() : comp.version());
                if (view.convergenceFinding() != null && view.recommendation() != null
                        && view.recommendation().targetVersion() != null
                        && compareVersionsSemantic(view.recommendation().targetVersion(), selectedVersion != null ? selectedVersion : "") > 0) {
                    selectedVersion = view.recommendation().targetVersion();
                }
                html.append(renderVersionSelect(selectorId, comp.coordinate(), comp.version(), selectedVersion,
                        view.versionMetadata(), view.recommendation(), view.findings(), false,
                        conflictVersions, true));
            }
            html.append("</div>");
        }

        if (hasChildren) {
            html.append("<div class=\"card-expand-row\">");
            html.append("<button class=\"card-expand-btn\" type=\"button\" data-comp-id=\"").append(comp.id())
                .append("\" onclick=\"toggleTree(this)\">+</button>");
            html.append("</div>");
            html.append("<div class=\"dep-tree-panel\" style=\"display:none\"></div>");
        }

        html.append("</div>");
        return html.toString();
    }

    private static String jsonStr(String value) {
        if (value == null) return "null";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }

    private String severityBadgeHtml(AdvisorySeverity severity, boolean clean) {
        if (clean || severity == AdvisorySeverity.NONE) {
            return "<span class=\"sev-badge sev-none\">&#10003; Clean</span>";
        }
        String cls = "sev-" + severity.name().toLowerCase();
        return "<span class=\"sev-badge " + cls + "\">" + escape(severity.icon()) + " " + escape(severity.label()) + "</span>";
    }

    private int remediationSortKey(ComponentView view) {
        ScanComponent component = view.component();
        RemediationStatus status = view.status();
        if (view.convergenceFinding() != null) {
            return 80;
        }
        if (status.hasVulnerability()) {
            return switch (status.highestSeverity()) {
                case CRITICAL -> 0;
                case HIGH -> 10;
                case MEDIUM -> 20;
                case LOW -> 30;
                default -> 40; // UNKNOWN
            };
        }
        if (status.isSnapshot()) return 50;
        if (status.hasStaleMetadata()) return 60;
        if (status.hasDeclaredVersionDeclaration()) return 70;
        if (status.hasUpgradeRecommendation()) return 80;
        return 90;
    }

    // ---- Stage 8: Compact version selector dropdown ----

    private String renderVersionSelect(String selectorId, ComponentCoordinate coordinate, String currentVersion,
            String selectedVersion, MetadataResult versionMetadata, UpgradeRecommendation recommendation,
            List<VulnerabilityFinding> vulnFindings, boolean includeNameAttr, List<String> conflictVersions,
            boolean includeCurrentOption) {
        List<String> choices = versionChoices(versionMetadata, recommendation);
        // Build deduplicated ordered set: recommended first, then choices, then latest
        LinkedHashSet<String> ordered = new LinkedHashSet<>();
        if (includeCurrentOption && currentVersion != null && !currentVersion.isBlank()) {
            ordered.add(currentVersion);
        }
        if (recommendation != null && recommendation.targetVersion() != null && !recommendation.targetVersion().isBlank()) {
            ordered.add(recommendation.targetVersion());
        }
        ordered.addAll(choices);
        if (conflictVersions != null) {
            ordered.addAll(conflictVersions);
            // Guarantee the conflict-default version is always selectable
            if (!conflictVersions.isEmpty() && selectedVersion != null && !selectedVersion.isBlank()) {
                ordered.add(selectedVersion);
            }
        }
        if (versionMetadata != null && versionMetadata.latestVersion() != null
                && !versionMetadata.latestVersion().isBlank()
                && !"unknown".equalsIgnoreCase(versionMetadata.latestVersion())
                && !isPreRelease(versionMetadata.latestVersion())) {
            ordered.add(versionMetadata.latestVersion());
        }

        if (ordered.isEmpty()) {
            return "<span class=\"version-note muted\">No upgrade candidates</span>";
        }

        // Sort versions in semantic ascending order before rendering
        List<String> sortedVersions = new ArrayList<>(ordered);
        sortedVersions.sort(this::compareVersionsSemantic);

        StringBuilder html = new StringBuilder();
        html.append("<div class=\"version-sel-wrap\">");

        // Show current version chip
        if (currentVersion != null && !currentVersion.isBlank()) {
            boolean currentHasCve = hasCveForVersion(coordinate, currentVersion, vulnFindings);
            html.append("<span class=\"version-current").append(currentHasCve ? " cve" : "").append("\">");
            html.append(escape(currentVersion));
            if (currentHasCve) html.append("<span class=\"pill\">CVE</span>");
            html.append("</span>");
            html.append("<span style=\"color:var(--muted)\">&#8594;</span>");
        }

        String recommendedVersion = recommendation != null ? recommendation.targetVersion() : null;
        String latestVersion = versionMetadata != null ? versionMetadata.latestVersion() : null;
        String latestSameMajor = versionMetadata != null ? versionMetadata.latestSameMajorVersion() : null;
        java.util.Set<String> conflictSet = conflictVersions == null ? java.util.Set.of() : new java.util.LinkedHashSet<>(conflictVersions);

        // Explicit selectedVersion (e.g. conflict default) takes priority over the recommendation.
        // For conflict cards, allow the current version to be selected (current may already be the resolution target).
        boolean hasConflict = conflictVersions != null && !conflictVersions.isEmpty();
        boolean hasExplicitSelection = selectedVersion != null && !selectedVersion.isBlank()
                && (hasConflict || !selectedVersion.equals(currentVersion)) && ordered.contains(selectedVersion);
        boolean hasPreSelection = hasExplicitSelection
                || (recommendedVersion != null && !recommendedVersion.isBlank()
                    && !recommendedVersion.equals(currentVersion) && ordered.contains(recommendedVersion));
        String preSelectedVersion = hasExplicitSelection ? selectedVersion : recommendedVersion;

        String nameAttr = includeNameAttr ? " name=\"" + escape(selectorId) + "\"" : "";
        html.append("<select class=\"version-sel\" id=\"").append(escape(selectorId)).append("\"").append(nameAttr)
                .append(" onchange=\"onVersionSelect(this)\"");
        if (recommendedVersion != null && !recommendedVersion.isBlank()) {
            html.append(" data-recommended=\"").append(escape(recommendedVersion)).append("\"");
        }
        html.append(">");
        // Blank placeholder shown only when nothing is pre-selected
        html.append("<option value=\"\"").append(hasPreSelection ? "" : " selected").append(">No change</option>");
        for (String version : sortedVersions) {
            boolean hasCve = hasCveForVersion(coordinate, version, vulnFindings);
            String label = buildVersionOptionLabel(version, recommendedVersion, latestVersion, latestSameMajor,
                    recommendation != null ? recommendation.reason() : null, hasCve, currentVersion,
                    conflictSet.contains(version), includeCurrentOption && version.equals(currentVersion));
            html.append("<option value=\"").append(escape(version)).append("\"")
                    .append(hasPreSelection && version.equals(preSelectedVersion) ? " selected" : "")
                    .append(">").append(escape(label)).append("</option>");
        }
        html.append("</select>");
        html.append("</div>");
        return html.toString();
    }

    private String buildVersionOptionLabel(String version, String recommendedVersion, String latestVersion,
            String latestSameMajor, RecommendationReason reason, boolean hasCve, String currentVersion,
            boolean isConflictVersion, boolean isCurrentVersion) {
        List<String> tags = new ArrayList<>();
        if (isCurrentVersion) tags.add("current");
        if (version.equals(recommendedVersion)) {
            tags.add("recommended");
            if (reason == RecommendationReason.CVE_FIX) tags.add("fixes CVE");
        }
        if (version.equals(latestVersion)) tags.add("latest");
        if (version.equals(latestSameMajor) && !version.equals(latestVersion)) {
            tags.add(sameMajorMinor(version, currentVersion) ? "latest same minor" : "latest same major");
        }
        if (hasCve) tags.add("vulnerable");
        if (isConflictVersion) tags.add("conflict");
        if (version.contains("-SNAPSHOT") || version.contains("-alpha") || version.contains("-beta") || version.contains("-rc")) {
            tags.add("pre-release");
        }
        return tags.isEmpty() ? version : version + " — " + String.join(", ", tags);
    }

    private int compareVersionsSemantic(String a, String b) {
        if (a == null) return b == null ? 0 : -1;
        if (b == null) return 1;
        String[] pa = a.replace('-', '.').split("\\.");
        String[] pb = b.replace('-', '.').split("\\.");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            String sa = i < pa.length ? pa[i] : "0";
            String sb = i < pb.length ? pb[i] : "0";
            try {
                int diff = Integer.compare(Integer.parseInt(sa), Integer.parseInt(sb));
                if (diff != 0) return diff;
            } catch (NumberFormatException e) {
                int diff = sa.compareTo(sb);
                if (diff != 0) return diff;
            }
        }
        return 0;
    }

    private String conflictDefaultVersion(TransitiveConflictFinding f, ScanComponent comp,
            List<VulnerabilityFinding> vulnFindings, Map<String, List<VulnerabilityFinding>> vulnsByKey) {
        return conflictDefaultVersion(f, comp, vulnFindings, vulnsByKey, null);
    }

    private String conflictDefaultVersion(TransitiveConflictFinding f, ScanComponent comp,
            List<VulnerabilityFinding> vulnFindings, Map<String, List<VulnerabilityFinding>> vulnsByKey,
            MetadataResult versionMeta) {
        String newest = f.resolvedVersion() != null ? f.resolvedVersion() : "";
        for (String v : f.conflictingVersions()) {
            if (compareVersionsSemantic(v, newest) > 0) newest = v;
        }
        if (comp.version() != null && compareVersionsSemantic(comp.version(), newest) > 0) {
            newest = comp.version();
        }
        if (comp.coordinate() == null) return newest.isBlank() ? null : newest;

        // Collect all known vulnerability findings for this artifact across all affected versions.
        // This lets us do range-based checking: if affectedVersion <= candidate < fixedVersion,
        // the candidate is still vulnerable even if we have no finding keyed exactly to it.
        String ga = comp.coordinate().groupId() + ":" + comp.coordinate().artifactId();
        List<VulnerabilityFinding> allArtifactVulns = new ArrayList<>();
        if (vulnFindings != null) allArtifactVulns.addAll(vulnFindings);
        if (vulnsByKey != null) {
            String prefix = ga + "@";
            for (Map.Entry<String, List<VulnerabilityFinding>> e : vulnsByKey.entrySet()) {
                if (e.getKey().startsWith(prefix)) {
                    for (VulnerabilityFinding vf : e.getValue()) {
                        if (vf.coordinate() != null
                                && comp.coordinate().groupId().equals(vf.coordinate().groupId())
                                && comp.coordinate().artifactId().equals(vf.coordinate().artifactId())) {
                            allArtifactVulns.add(vf);
                        }
                    }
                }
            }
        }

        // Walk up through available versions (same major) until finding a clean one.
        List<String> upgradePath = (versionMeta != null && versionMeta.upgradePathVersions() != null)
                ? versionMeta.upgradePathVersions() : List.of();
        String candidate = newest;
        int maxPasses = upgradePath.size() + allArtifactVulns.size() + 2;
        for (int pass = 0; pass < maxPasses; pass++) {
            // Find the lowest fixedVersion that covers the candidate (affectedVersion <= candidate < fixedVersion, same major)
            String fixVersion = null;
            for (VulnerabilityFinding finding : allArtifactVulns) {
                if (finding.fixedVersion() == null) continue;
                if (!sameMajor(candidate, finding.fixedVersion())) continue;
                if (compareVersionsSemantic(candidate, finding.fixedVersion()) >= 0) continue;
                // candidate < fixedVersion — check range: affectedVersion <= candidate
                if (finding.affectedVersion() != null
                        && compareVersionsSemantic(finding.affectedVersion(), candidate) > 0) continue;
                if (fixVersion == null || compareVersionsSemantic(finding.fixedVersion(), fixVersion) < 0) {
                    fixVersion = finding.fixedVersion();
                }
            }
            if (fixVersion == null) break; // candidate is clean
            // Find the lowest available version >= fixVersion within same major
            String next = null;
            for (String v : upgradePath) {
                if (!sameMajor(candidate, v)) continue;
                if (compareVersionsSemantic(v, fixVersion) >= 0
                        && (next == null || compareVersionsSemantic(v, next) < 0)) {
                    next = v;
                }
            }
            if (next == null) next = fixVersion; // no upgrade path entry, use fix directly
            if (next.equals(candidate)) break;
            candidate = next;
        }
        // Fallback: if candidate is still listed as an affectedVersion in CVE data but no fixedVersion
        // was resolvable (fixedVersion=null), bump to the lowest same-major version in the upgrade path.
        if (!allArtifactVulns.isEmpty()) {
            String finalCandidate = candidate;
            boolean candidateIsAffected = allArtifactVulns.stream().anyMatch(vf ->
                    finalCandidate.equals(vf.affectedVersion())
                    || (vf.affectedVersion() != null
                        && compareVersionsSemantic(vf.affectedVersion(), finalCandidate) <= 0
                        && vf.fixedVersion() == null));
            if (candidateIsAffected) {
                for (String v : upgradePath) {
                    if (sameMajor(candidate, v) && compareVersionsSemantic(v, candidate) > 0
                            && !isPreRelease(v)) {
                        candidate = v;
                        break;
                    }
                }
            }
        }
        return candidate.isBlank() ? null : candidate;
    }

    private boolean sameMajorMinor(String v1, String v2) {
        if (v1 == null || v2 == null) return false;
        String[] p1 = v1.split("\\.", 3);
        String[] p2 = v2.split("\\.", 3);
        return p1.length >= 2 && p2.length >= 2 && p1[0].equals(p2[0]) && p1[1].equals(p2[1]);
    }

    private boolean sameMajor(String v1, String v2) {
        if (v1 == null || v2 == null) return false;
        String[] p1 = v1.split("[.\\-]", 2);
        String[] p2 = v2.split("[.\\-]", 2);
        return p1.length >= 1 && p2.length >= 1 && !p1[0].isBlank() && p1[0].equals(p2[0]);
    }

    private boolean isDefaultVisibleRemediationCard(ComponentView view) {
        if (view == null) {
            return false;
        }
        if (view.convergenceFinding() != null) {
            return true;
        }
        RemediationStatus status = view.status();
        return status != null
                && status.needsRemediation()
                && !status.hasVulnerability()
                && !status.isSnapshot();
    }

    private TransitiveConflictFinding findMatchingConflict(Map<String, List<TransitiveConflictFinding>> conflictsByKey, ScanComponent component) {
        if (conflictsByKey == null || component == null || component.coordinate() == null) {
            return null;
        }
        String key = component.coordinate().groupId() + ":" + component.coordinate().artifactId();
        List<TransitiveConflictFinding> conflicts = conflictsByKey.get(key);
        if (conflicts == null || conflicts.isEmpty()) {
            return null;
        }
        String currentVersion = component.version();
        if (currentVersion != null && !currentVersion.isBlank()) {
            for (TransitiveConflictFinding conflict : conflicts) {
                if (currentVersion.equals(conflict.resolvedVersion())) {
                    return conflict;
                }
            }
        }
        return conflicts.get(0);
    }

    private String buildConflictJson(TransitiveConflictFinding f) {
        StringBuilder json = new StringBuilder("{");
        json.append("\"groupId\":").append(jsonStr(f.groupId())).append(",");
        json.append("\"artifactId\":").append(jsonStr(f.artifactId())).append(",");
        json.append("\"resolvedVersion\":").append(jsonStr(f.resolvedVersion())).append(",");
        json.append("\"exclusions\":[");
        boolean first = true;
        for (ConflictCandidateAction a : f.candidateActions()) {
            if (a.type() != ConflictCandidateAction.ActionType.ADD_EXCLUSION || a.version() == null) continue;
            if (!first) json.append(",");
            first = false;
            json.append("{\"parentGroupId\":").append(jsonStr(a.parentGroupId()))
                .append(",\"parentArtifactId\":").append(jsonStr(a.parentArtifactId()))
                .append(",\"introducedVersion\":").append(jsonStr(a.version())).append("}");
        }
        json.append("]}");
        return json.toString().replace("'", "&#39;");
    }

    private String renderDependencyInventory(ScanReport report) {
        StringBuilder html = new StringBuilder();
        List<ScanComponent> components = report.components();
        if (components.isEmpty()) {
            html.append("<p class=\"muted\">No dependency inventory is available for this scan.</p>");
            return html.toString();
        }
        Map<Long, UpgradeRecommendation> recommendationByComponent = new LinkedHashMap<>();
        Map<Long, MetadataResult> versionMetadataByComponent = new LinkedHashMap<>();
        Map<String, List<VulnerabilityFinding>> vulnerabilitiesByComponent = new LinkedHashMap<>();
        for (UpgradeRecommendation recommendation : report.recommendations()) {
            if (!recommendation.affectedComponentIds().isEmpty()) {
                recommendationByComponent.put(recommendation.affectedComponentIds().get(0), recommendation);
            } else {
                recommendationByComponent.put(recommendation.id(), recommendation);
            }
        }
        for (MetadataResult metadataResult : report.metadataResults()) {
            if (metadataResult.metadataType() == MetadataType.VERSION) {
                versionMetadataByComponent.put(metadataResult.componentId(), metadataResult);
            }
        }
        for (VulnerabilityFinding finding : report.vulnerabilityFindings()) {
            String key = finding.coordinate().groupId() + ":" + finding.coordinate().artifactId() + "@" + finding.affectedVersion();
            vulnerabilitiesByComponent.computeIfAbsent(key, k -> new ArrayList<>()).add(finding);
        }
        Map<String, ScanComponent> unique = new LinkedHashMap<>();
        for (ScanComponent component : components) {
            String key = component.sourceFilePath() + "|" + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + "|" + component.version() + "|" + component.direct();
            unique.putIfAbsent(key, component);
        }
        Map<String, List<ScanComponent>> byModule = new LinkedHashMap<>();
        for (ScanComponent component : unique.values()) {
            String module = component.modulePath() == null || component.modulePath().isBlank() ? "(root)" : component.modulePath();
            byModule.computeIfAbsent(module, key -> new ArrayList<>()).add(component);
        }
        long directCount = unique.values().stream().filter(c -> c.direct() && !c.snapshot()).count();
        long transitiveCount = unique.values().stream().filter(c -> !c.direct() && !c.snapshot()).count();
        long snapshotCount = unique.values().stream().filter(ScanComponent::snapshot).count();
        html.append("<div class=\"inventory-grid\">");
        html.append("<div class=\"inventory-tabs span-2 module-tabs\">");
        html.append("<button class=\"button primary inventory-tab active\" type=\"button\" data-module=\"all\" onclick=\"filterInventoryModule('all')\">All modules <span class=\"tab-count\">").append(byModule.size()).append("</span></button>");
        for (Map.Entry<String, List<ScanComponent>> entry : byModule.entrySet()) {
            html.append("<button class=\"button inventory-tab\" type=\"button\" data-module=\"").append(escape(entry.getKey())).append("\" onclick=\"filterInventoryModule('").append(escape(entry.getKey())).append("')\">");
            html.append(escape(entry.getKey())).append(" <span class=\"tab-count\">").append(entry.getValue().size()).append("</span></button>");
        }
        html.append("</div>");
        html.append("<div class=\"inventory-tabs span-2 kind-tabs\">");
        html.append("<button class=\"button primary inventory-tab active\" type=\"button\" data-kind=\"all\" onclick=\"filterInventoryKind('all')\">All <span class=\"tab-count\">").append(unique.size()).append("</span></button>");
        html.append("<button class=\"button inventory-tab\" type=\"button\" data-kind=\"declared\" onclick=\"filterInventoryKind('declared')\">Declared <span class=\"tab-count\">").append(directCount).append("</span></button>");
        html.append("<button class=\"button inventory-tab\" type=\"button\" data-kind=\"transitive\" onclick=\"filterInventoryKind('transitive')\">Transitive <span class=\"tab-count\">").append(transitiveCount).append("</span></button>");
        html.append("<button class=\"button inventory-tab\" type=\"button\" data-kind=\"snapshot\" onclick=\"filterInventoryKind('snapshot')\">Snapshots <span class=\"tab-count\">").append(snapshotCount).append("</span></button>");
        html.append("</div>");
        for (Map.Entry<String, List<ScanComponent>> entry : byModule.entrySet()) {
            String source = entry.getKey();
            List<ScanComponent> sourceComponents = entry.getValue();
        html.append("<section class=\"inventory-group\" data-module=\"").append(escape(source)).append("\">");
            html.append("<div class=\"inventory-header\">");
            html.append("<div>");
            html.append("<div class=\"eyebrow\">").append(escape(source)).append("</div>");
            html.append("<h3>").append(sourceComponents.size()).append(" dependencies</h3>");
            html.append("</div>");
            html.append("<span class=\"badge neutral\">").append(escape(sourceComponents.size() == 1 ? "1 item" : sourceComponents.size() + " items")).append("</span>");
            html.append("</div>");
            html.append("<div class=\"inventory-items\">");
            for (ScanComponent component : sourceComponents) {
                UpgradeRecommendation recommendation = recommendationByComponent.get(component.id());
                MetadataResult versionMetadata = versionMetadataByComponent.get(component.id());
                String kind = component.snapshot() ? "snapshot" : (component.direct() ? "declared" : "transitive");
                html.append("<div class=\"inventory-row\" data-kind=\"").append(kind).append("\">");
                html.append("<div class=\"inventory-main\">");
                html.append("<div class=\"inventory-title\">").append(escape(component.coordinate().groupId() + ":" + component.coordinate().artifactId())).append("</div>");
                html.append("<div class=\"inventory-subtitle\">current ").append(escape(component.version())).append("</div>");
                html.append(renderVersionButtonGroup(component.coordinate(), component.version(), component.id(), versionMetadata, recommendation, versionChoices(versionMetadata, recommendation), recommendation == null ? component.version() : recommendation.targetVersion(), vulnerabilitiesByComponent.get(component.coordinate().groupId() + ":" + component.coordinate().artifactId() + "@" + component.version()), false));
                html.append("</div>");
                html.append("<div class=\"inventory-badges\">");
                html.append("<span class=\"badge ").append(component.snapshot() ? "warn" : component.direct() ? "success" : "neutral").append("\">");
                html.append(component.snapshot() ? "snapshot" : component.direct() ? "declared" : "transitive");
                html.append("</span>");
                if (recommendation != null) {
                    html.append("<span class=\"badge\">").append(escape(reasonLabel(recommendation.reason()))).append("</span>");
                }
                html.append("</div>");
                html.append("</div>");
            }
            html.append("</div>");
            html.append("</section>");
        }
        html.append("</div>");
        return html.toString();
    }

    private String renderMetadataResults(ScanReport report) {
        StringBuilder html = new StringBuilder();
        if (report.metadataResults().isEmpty()) {
            html.append("<p class=\"muted\">No metadata lookups have been recorded yet.</p>");
            return html.toString();
        }
        html.append("<table class=\"table\"><thead><tr><th>Component</th><th>Current</th><th>Version path</th><th>Type</th><th>Provider</th><th>Status</th><th>Cache</th><th>Message</th></tr></thead><tbody>");
        Map<Long, ScanComponent> componentsById = new LinkedHashMap<>();
        for (ScanComponent component : report.components()) {
            componentsById.put(component.id(), component);
        }
        for (MetadataResult result : report.metadataResults()) {
            ScanComponent component = componentsById.get(result.componentId());
            String label = component == null ? String.valueOf(result.componentId()) : component.coordinate().groupId() + ":" + component.coordinate().artifactId();
            html.append("<tr>");
            html.append("<td>").append(escape(label)).append("</td>");
            html.append("<td>").append(escape(result.currentVersion())).append("</td>");
            html.append("<td>").append(escape(versionPath(result.currentVersion(), result.latestSameMajorVersion(), result.upgradePathVersions()))).append("</td>");
            html.append("<td>").append(escape(result.metadataType().name())).append("</td>");
            html.append("<td>").append(escape(result.provider())).append("</td>");
            html.append("<td>").append(escape(result.status().name())).append("</td>");
            html.append("<td>").append(escape(result.cacheState().name())).append("</td>");
            html.append("<td>").append(escape(result.message())).append("</td>");
            html.append("</tr>");
        }
        html.append("</tbody></table>");
        return html.toString();
    }

    private String renderTreeNode(DependencyEdge edge, Map<Long, ScanComponent> componentsById, Map<String, List<DependencyEdge>> childrenByParent, java.util.Set<String> path) {
        StringBuilder html = new StringBuilder();
        ScanComponent component = parseComponent(edge.toComponentId(), componentsById);
        if (component == null) {
            return "";
        }
        String nodeId = edge.toComponentId();
        if (!path.add(nodeId)) {
            return "";
        }
        html.append("<li class=\"tree-node\">");
        html.append("<div class=\"tree-card\">");
        html.append("<div class=\"headline\">");
        html.append("<div>");
        html.append("<strong>").append(escape(component.coordinate().groupId() + ":" + component.coordinate().artifactId())).append("</strong>");
        html.append("<div class=\"muted mono\">").append(escape(component.version())).append("</div>");
        html.append("</div>");
        html.append("<div class=\"badge ").append(component.direct() ? "success" : "neutral").append("\">");
        html.append(component.direct() ? "declared" : "transitive");
        html.append("</div>");
        html.append("</div>");
        html.append("<div class=\"tree-meta\">");
        html.append(escape("scope: " + edge.scope().name().toLowerCase() + " · source: " + component.sourceFilePath()));
        html.append("</div>");
        html.append("</div>");
            List<DependencyEdge> children = childrenByParent.get(nodeId);
        if (children != null && !children.isEmpty()) {
            html.append("<ul class=\"tree\">");
            Map<String, List<DependencyEdge>> collapsedChildren = new LinkedHashMap<>();
            for (DependencyEdge child : children) {
                collapsedChildren.computeIfAbsent(child.toComponentId(), key -> new ArrayList<>()).add(child);
            }
            for (List<DependencyEdge> sameNodeEdges : collapsedChildren.values()) {
                DependencyEdge child = sameNodeEdges.get(0);
                String childHtml = renderTreeNode(child, componentsById, childrenByParent, new java.util.HashSet<>(path));
                if (!childHtml.isEmpty()) {
                    if (sameNodeEdges.size() > 1) {
                        int insertAt = childHtml.lastIndexOf("</div></li>");
                        if (insertAt > 0) {
                            childHtml = childHtml.substring(0, insertAt) + "<span class=\"badge neutral\">x" + sameNodeEdges.size() + "</span>" + childHtml.substring(insertAt);
                        }
                    }
                    html.append(childHtml);
                }
            }
            html.append("</ul>");
        }
        html.append("</li>");
        return html.toString();
    }

    private ScanComponent parseComponent(String componentId, Map<Long, ScanComponent> componentsById) {
        try {
            long id = Long.parseLong(componentId);
            return componentsById.get(id);
        } catch (NumberFormatException e) {
            return null;
        }
    }


    private String renderLogModal(ScanReport report, String scanId, Store.EnforcerResultEntry enforcerResult) {
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
            if (phase2Pins.isEmpty() && !enforcerResult.findings().isEmpty()) {
                phase2Pins = enforcerResult.findings().stream()
                        .map(f -> {
                            String w = computeWinnerVersion(f, "");
                            return w != null ? f.groupId() + ":" + f.artifactId() + ":" + w : null;
                        })
                        .filter(s -> s != null)
                        .toList();
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

    private void handleLogo(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        byte[] bytes = logoSvgInline().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "image/svg+xml; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private String logoSvgInline() {
        try (var stream = getClass().getResourceAsStream("/redkite-icon.svg")) {
            if (stream != null) return new String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
        // fallback geometric icon
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 128 128\" role=\"img\" aria-label=\"RedKite logo\">"
                + "<defs><linearGradient id=\"rk\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\"><stop offset=\"0%\" stop-color=\"#ff6b6b\"/><stop offset=\"100%\" stop-color=\"#e11d48\"/></linearGradient></defs>"
                + "<rect width=\"128\" height=\"128\" rx=\"28\" fill=\"#0f172a\"/>"
                + "<path d=\"M64 16 L104 58 L78 66 L64 112 L50 66 L24 58 Z\" fill=\"url(#rk)\"/>"
                + "<path d=\"M64 16 L64 112\" stroke=\"#ffe4e6\" stroke-width=\"4\" stroke-linecap=\"round\" opacity=\"0.9\"/>"
                + "<path d=\"M24 58 L64 66 L104 58\" fill=\"none\" stroke=\"#ffe4e6\" stroke-width=\"4\" stroke-linecap=\"round\" stroke-linejoin=\"round\" opacity=\"0.9\"/>"
                + "<circle cx=\"64\" cy=\"66\" r=\"6\" fill=\"#fff1f2\"/>"
                + "</svg>";
    }

    private String statGrid(String... cards) {
        StringBuilder html = new StringBuilder("<div class=\"stat-grid\">");
        for (String card : cards) {
            html.append(card);
        }
        html.append("</div>");
        return html.toString();
    }

    private String statCard(String label, String value) {
        return "<div class=\"stat\"><div class=\"muted\">" + escape(label) + "</div><strong>" + escape(value) + "</strong></div>";
    }

    private String versionPath(String currentVersion, String latestSameMajorVersion, List<String> upgradePathVersions) {
        String current = currentVersion == null || currentVersion.isBlank() ? "unknown" : currentVersion;
        String sameFamily = latestSameMajorVersion == null || latestSameMajorVersion.isBlank() ? null : latestSameMajorVersion;
        List<String> tail = new ArrayList<>();
        if (upgradePathVersions != null) {
            for (String version : upgradePathVersions) {
                if (version == null || version.isBlank()) {
                    continue;
                }
                if (version.equals(current) || (sameFamily != null && version.equals(sameFamily))) {
                    continue;
                }
                tail.add(version);
            }
        }
        StringBuilder html = new StringBuilder(current);
        if (sameFamily != null && !sameFamily.equals(current)) {
            html.append(" -> ").append(sameFamily);
        }
        if (!tail.isEmpty()) {
            html.append(" -> ").append(String.join(", ", tail));
        }
        return html.toString();
    }

    private String renderVersionButtonGroup(ComponentCoordinate coordinate, String currentVersion, long selectorKey, MetadataResult versionMetadata, UpgradeRecommendation recommendation, List<String> choices, String selectedVersion, List<VulnerabilityFinding> vulnerabilityFindings, boolean includeHiddenInput) {
        StringBuilder html = new StringBuilder();
        String selectorId = "targetVersion_" + selectorKey;
        boolean snapshot = (currentVersion != null && currentVersion.contains("SNAPSHOT")) || (recommendation != null && recommendation.reason() == RecommendationReason.SNAPSHOT_REPLACEMENT);
        html.append("<div class=\"version-selector\" data-selector-id=\"").append(escape(selectorId)).append("\">");
        html.append("<span class=\"version-label\">Versions</span>");
        if (snapshot) {
            if (currentVersion != null && !currentVersion.isBlank()) {
                html.append("<span class=\"version-choice current\">").append(escape(currentVersion)).append("</span>");
            }
            html.append("<span class=\"version-choice active\">Release required</span>");
            html.append("</div>");
            return html.toString();
        }
        if (currentVersion != null && !currentVersion.isBlank()) {
            boolean currentCve = hasCveForVersion(coordinate, currentVersion, vulnerabilityFindings);
            html.append(versionChoiceButton(selectorId, currentVersion, currentVersion, currentVersion.equals(selectedVersion), currentCve, true));
        }
        java.util.LinkedHashSet<String> ordered = new java.util.LinkedHashSet<>();
        if (recommendation != null && recommendation.targetVersion() != null && !recommendation.targetVersion().isBlank()) {
            ordered.add(recommendation.targetVersion());
        }
        if (choices != null) {
            ordered.addAll(choices);
        }
        if (versionMetadata != null && versionMetadata.latestVersion() != null && !versionMetadata.latestVersion().isBlank()) {
            ordered.add(versionMetadata.latestVersion());
        }
        for (String version : ordered) {
            if (version == null || version.isBlank() || version.equals(currentVersion)) {
                continue;
            }
            boolean active = selectedVersion != null && selectedVersion.equals(version);
            boolean cve = hasCveForVersion(coordinate, version, vulnerabilityFindings);
            html.append(versionChoiceButton(selectorId, version, version, active, cve, false));
        }
        if (includeHiddenInput) {
            html.append("<input type=\"hidden\" id=\"").append(escape(selectorId)).append("\" name=\"").append(escape(selectorId)).append("\" value=\"").append(escape(selectedVersion == null ? "" : selectedVersion)).append("\"/>");
        }
        html.append("</div>");
        return html.toString();
    }

    private String versionChoiceButton(String selectorId, String version, String label, boolean active, boolean cve, boolean current) {
        StringBuilder html = new StringBuilder();
        html.append("<button type=\"button\" class=\"version-choice");
        if (current) {
            html.append(" current");
        }
        if (active) {
            html.append(" active");
        }
        if (cve) {
            html.append(" cve");
        }
        html.append("\" data-version=\"").append(escape(version)).append("\" onclick=\"selectVersionChoice(this, '").append(escape(selectorId)).append("')\">");
        html.append(escape(label));
        if (cve) {
            html.append("<span class=\"pill\">CVE</span>");
        }
        html.append("</button>");
        return html.toString();
    }

    private boolean hasHighOrCriticalCve(List<VulnerabilityFinding> findings) {
        if (findings == null) return false;
        for (VulnerabilityFinding f : findings) {
            String sev = f.severity();
            if ("HIGH".equalsIgnoreCase(sev) || "CRITICAL".equalsIgnoreCase(sev)) return true;
        }
        return false;
    }

    private boolean hasCveForVersion(ComponentCoordinate coordinate, String candidateVersion, List<VulnerabilityFinding> findings) {
        if (coordinate == null || candidateVersion == null || candidateVersion.isBlank() || findings == null || findings.isEmpty()) {
            return false;
        }
        for (VulnerabilityFinding finding : findings) {
            if (finding == null || finding.coordinate() == null) {
                continue;
            }
            if (!coordinate.groupId().equals(finding.coordinate().groupId()) || !coordinate.artifactId().equals(finding.coordinate().artifactId())) {
                continue;
            }
            if (candidateVersion.equals(finding.affectedVersion())) {
                return true;
            }
        }
        return false;
    }

    private List<String> versionChoices(MetadataResult versionMetadata, UpgradeRecommendation recommendation) {
        java.util.LinkedHashSet<String> choices = new java.util.LinkedHashSet<>();
        if (recommendation != null && recommendation.targetVersion() != null && !recommendation.targetVersion().isBlank()
                && !isPreRelease(recommendation.targetVersion())) {
            choices.add(recommendation.targetVersion());
        }
        if (versionMetadata != null) {
            if (versionMetadata.latestSameMajorVersion() != null && !versionMetadata.latestSameMajorVersion().isBlank()
                    && !isPreRelease(versionMetadata.latestSameMajorVersion())) {
                choices.add(versionMetadata.latestSameMajorVersion());
            }
            if (versionMetadata.upgradePathVersions() != null) {
                for (String version : versionMetadata.upgradePathVersions()) {
                    if (version != null && !version.isBlank() && !isPreRelease(version)) {
                        choices.add(version);
                    }
                }
            }
            if (versionMetadata.latestVersion() != null && !versionMetadata.latestVersion().isBlank()
                    && !isPreRelease(versionMetadata.latestVersion())) {
                choices.add(versionMetadata.latestVersion());
            }
        }
        if (recommendation != null && recommendation.currentVersion() != null) {
            choices.remove(recommendation.currentVersion());
        }
        return List.copyOf(choices);
    }

    private static boolean isPreRelease(String version) {
        if (version == null || version.isBlank()) return false;
        String v = version.toLowerCase();
        return v.contains("snapshot") || v.contains("alpha") || v.contains("beta")
                || v.matches(".*[.\\-]rc\\d*([.\\-].*)?")
                || v.matches(".*[.\\-]m\\d+([.\\-].*)?")
                || v.contains("milestone") || v.contains("preview") || v.contains("incubat")
                || v.matches(".*[.\\-]cr\\d*([.\\-].*)?");
    }

    private String reasonLabel(RecommendationReason reason) {
        return switch (reason) {
            case CVE_FIX -> "CVE FIX";
            case PATCH_AVAILABLE -> "UPGRADE";
            case MINOR_AVAILABLE -> "MINOR";
            case MAJOR_AVAILABLE -> "MAJOR";
            case SNAPSHOT_REPLACEMENT -> "USE RELEASE";
        };
    }

    private static boolean canPlanUpgrade(ScanComponent component) {
        return component != null;
    }

    static final class Store {
        private final String jdbcUrl;
        private final String dbUser;
        private final String dbPassword;
        volatile HttpVersionMetadataProvider versionProvider;
        final HttpVulnerabilityProvider vulnerabilityProvider;
        volatile List<String> effectiveMavenRepos;
        volatile String mavenSettingsPath;

        private Store(String jdbcUrl, String dbUser, String dbPassword) {
            this.jdbcUrl = jdbcUrl;
            this.dbUser = dbUser;
            this.dbPassword = dbPassword;
            String mavenRepos = System.getProperty("redkite.maven.repositories");
            if (mavenRepos != null) {
                this.versionProvider = new HttpVersionMetadataProvider(mavenRepos, null, null, this::dbConnection);
                this.mavenSettingsPath = null;
            } else {
                // At startup the project root is not yet known; use home settings only.
                // reconfigureForProject() is called before each scan with the real root.
                java.nio.file.Path settingsPath = MavenSettingsReader.resolveSettingsFile(null);
                this.mavenSettingsPath = settingsPath != null ? settingsPath.toAbsolutePath().toString() : null;
                this.versionProvider = buildVersionProvider(null);
            }
            this.effectiveMavenRepos = this.versionProvider.getRepositoryBaseUrls();
            LOGGER.info(() -> "Maven settings: " + (mavenSettingsPath != null ? mavenSettingsPath : "(none)"));
            LOGGER.info(() -> "Effective Maven repositories: " + effectiveMavenRepos);
            this.vulnerabilityProvider = new HttpVulnerabilityProvider(System.getProperty("redkite.osv.url", "https://api.osv.dev"), this::dbConnection);
            initializeSchema();
        }

        /** Re-resolve settings from the project root before a scan. No-op when overridden by system property. */
        synchronized void reconfigureForProject(java.nio.file.Path projectRoot) {
            if (System.getProperty("redkite.maven.repositories") != null) return;
            java.nio.file.Path resolved = MavenSettingsReader.resolveSettingsFile(projectRoot);
            String newPath = resolved != null ? resolved.toAbsolutePath().toString() : null;
            if (java.util.Objects.equals(newPath, mavenSettingsPath)) {
                // Same settings file but credentials might have changed (env vars set after startup).
                // Clear error/missing cache so they get re-fetched with fresh env resolution.
                versionProvider.clearErrorCache();
                return;
            }
            LOGGER.info(() -> "Reconfiguring Maven settings for project " + projectRoot + ": " + newPath);
            this.mavenSettingsPath = newPath;
            this.versionProvider = buildVersionProvider(projectRoot); // instance method — has access to this::connection
            this.effectiveMavenRepos = this.versionProvider.getRepositoryBaseUrls();
            LOGGER.info(() -> "Effective Maven repositories: " + effectiveMavenRepos);
        }

        private HttpVersionMetadataProvider buildVersionProvider(java.nio.file.Path projectRoot) {
            List<MavenSettingsReader.RepoConfig> repoConfigs = MavenSettingsReader.discoverRepositoryConfigs(projectRoot);
            String urls = repoConfigs.stream()
                    .map(MavenSettingsReader.RepoConfig::url)
                    .collect(java.util.stream.Collectors.joining(","));
            String repoUser = null, repoPass = null;
            for (MavenSettingsReader.RepoConfig cfg : repoConfigs) {
                if (cfg.username() != null && !cfg.username().isBlank()) {
                    repoUser = cfg.username();
                    repoPass = cfg.password();
                    break;
                }
            }
            return new HttpVersionMetadataProvider(urls, repoUser, repoPass, this::dbConnection);
        }

        private java.sql.Connection dbConnection() {
            try { return connection(); } catch (java.sql.SQLException e) { throw new RuntimeException(e); }
        }

        synchronized void clearVersionCache() {
            try (Connection c = connection();
                 PreparedStatement ps = c.prepareStatement("delete from rk_version_cache")) {
                int rows = ps.executeUpdate();
                LOGGER.info(() -> "Cleared rk_version_cache: " + rows + " rows deleted");
            } catch (SQLException e) {
                LOGGER.warning(() -> "Failed to clear rk_version_cache: " + e.getMessage());
            }
        }

        static Store connect(String jdbcUrl, String dbUser, String dbPassword) {
            return new Store(jdbcUrl, dbUser, dbPassword);
        }

        synchronized List<ProjectEntry> listProjects() {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, name, root_path, created_at, updated_at
                         from projects
                         order by updated_at desc
                         """);
                 ResultSet rs = statement.executeQuery()) {
                List<ProjectEntry> projects = new ArrayList<>();
                while (rs.next()) {
                    projects.add(new ProjectEntry(
                            rs.getString("id"),
                            rs.getString("name"),
                            rs.getString("root_path"),
                            rs.getTimestamp("created_at").toInstant(),
                            rs.getTimestamp("updated_at").toInstant()));
                }
                return projects;
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to list projects", e);
            }
        }

        synchronized ProjectEntry getProject(String id) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, name, root_path, created_at, updated_at
                         from projects
                         where id = ?
                         """)) {
                statement.setString(1, id);
                try (ResultSet rs = statement.executeQuery()) {
                    if (!rs.next()) {
                        throw new IllegalArgumentException("project not found");
                    }
                    return new ProjectEntry(
                            rs.getString("id"),
                            rs.getString("name"),
                            rs.getString("root_path"),
                            rs.getTimestamp("created_at").toInstant(),
                            rs.getTimestamp("updated_at").toInstant());
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to fetch project", e);
            }
        }

        synchronized void deleteProject(String id) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("delete from projects where id = ?")) {
                statement.setString(1, id);
                statement.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to delete project", e);
            }
        }

        synchronized boolean getProjectEnforcerUseVerify(String projectId) {
            try (Connection c = connection();
                 PreparedStatement ps = c.prepareStatement(
                         "select enforcer_use_verify from projects where id = ?")) {
                ps.setString(1, projectId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() && rs.getBoolean("enforcer_use_verify");
                }
            } catch (SQLException e) {
                LOGGER.warning(() -> "Failed to read enforcer_use_verify for project " + projectId + ": " + e.getMessage());
                return false;
            }
        }

        synchronized void setProjectEnforcerUseVerify(String projectId) {
            try (Connection c = connection();
                 PreparedStatement ps = c.prepareStatement(
                         "update projects set enforcer_use_verify = true where id = ?")) {
                ps.setString(1, projectId);
                ps.executeUpdate();
                LOGGER.info(() -> "Recorded enforcer_use_verify=true for project " + projectId);
            } catch (SQLException e) {
                LOGGER.warning(() -> "Failed to set enforcer_use_verify for project " + projectId + ": " + e.getMessage());
            }
        }

        synchronized ScanEntry latestScanForProject(String projectId) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, project_id, raw_input_json, report_json, created_at
                         from scans
                         where project_id = ?
                         order by created_at desc
                         fetch first 1 row only
                         """)) {
                statement.setString(1, projectId);
                try (ResultSet rs = statement.executeQuery()) {
                    if (!rs.next()) {
                        return null;
                    }
                    return scanFromRow(rs);
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to fetch latest scan", e);
            }
        }

        synchronized List<ScanEntry> listScansForProject(String projectId) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, project_id, raw_input_json, report_json, created_at
                         from scans
                         where project_id = ?
                         order by created_at asc
                         """)) {
                statement.setString(1, projectId);
                List<ScanEntry> scans = new ArrayList<>();
                try (ResultSet rs = statement.executeQuery()) {
                    while (rs.next()) scans.add(scanFromRow(rs));
                }
                return scans;
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to list scans for project", e);
            }
        }

        synchronized ScanEntry getScan(String scanId) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, project_id, raw_input_json, report_json, created_at
                         from scans
                         where id = ?
                         """)) {
                statement.setString(1, scanId);
                try (ResultSet rs = statement.executeQuery()) {
                    if (!rs.next()) {
                        throw new IllegalArgumentException("scan not found");
                    }
                    return scanFromRow(rs);
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to fetch scan", e);
            }
        }

        synchronized ScanReport ingest(ScanInput input) {
            return ingest(input, msg -> {});
        }

        synchronized ScanReport ingest(ScanInput input, Consumer<String> progress) {
            try (Connection connection = connection()) {
                connection.setAutoCommit(false);
                try {
                    String projectId = upsertProject(connection, input.projectName(), input.projectRootPath());
                    ScanReport draft = buildReport(input, projectId, null, progress);
                    String scanId = insertScan(connection, projectId, input, draft);
                    List<MetadataResult> metadataResults = draft.metadataResults().stream().map(result -> withScanId(result, scanId)).toList();
                    ScanReport finalReport = new ScanReport(scanId, projectId, draft.complete(), draft.completenessMessage(), draft.createdAt(), draft.components(), draft.dependencyEdges(), draft.vulnerabilityFindings(), draft.recommendations(), draft.snapshotDependencyRisks(), metadataResults, draft.treeParseWarnings());
                    updateScanReport(connection, scanId, finalReport);
                    persistMetadataCache(connection, finalReport);
                    persistSourcePoms(connection, scanId, input);
                    connection.commit();
                    return finalReport;
                } catch (RuntimeException | SQLException e) {
                    connection.rollback();
                    throw e;
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to ingest scan", e);
            }
        }

        private MetadataResult withScanId(MetadataResult result, String scanId) {
            return new MetadataResult(scanId, result.componentId(), result.metadataType(), result.provider(), result.currentVersion(), result.latestVersion(), result.latestSameMajorVersion(), result.upgradePathVersions(), result.complete(), result.status(), result.cacheState(), result.lastSuccessfulCheckAt(), result.cacheExpiryAt(), result.attemptedRefreshAt(), result.suggestedRetryAt(), result.message());
        }

        private void persistMetadataCache(Connection connection, ScanReport report) throws SQLException {
            java.util.Set<String> seen = new java.util.HashSet<>();
            try (PreparedStatement insert = connection.prepareStatement("""
                    insert into metadata_cache_entries(
                      scan_id, component_id, metadata_type, provider, component_group_id, component_artifact_id, component_version, latest_version, latest_same_major_version,
                      complete, status, cache_state, last_successful_check_at, cache_expiry_at, attempted_refresh_at,
                      suggested_retry_at, message
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                for (MetadataResult result : report.metadataResults()) {
                    String key = result.scanId() + ":" + result.componentId() + ":" + result.metadataType().name();
                    if (!seen.add(key)) {
                        continue;
                    }
                    ScanComponent component = componentById(report.components(), result.componentId());
                    insert.setString(1, result.scanId());
                    insert.setLong(2, result.componentId());
                    insert.setString(3, result.metadataType().name());
                    insert.setString(4, result.provider());
                    insert.setString(5, component == null ? "unknown" : component.coordinate().groupId());
                    insert.setString(6, component == null ? "unknown" : component.coordinate().artifactId());
                    insert.setString(7, component == null ? "unknown" : component.version());
                    insert.setString(8, result.latestVersion() == null ? "unknown" : result.latestVersion());
                    insert.setString(9, result.latestSameMajorVersion() == null ? "unknown" : result.latestSameMajorVersion());
                    insert.setBoolean(10, result.complete());
                    insert.setString(11, result.status().name());
                    insert.setString(12, result.cacheState().name());
                    insert.setTimestamp(13, result.lastSuccessfulCheckAt() == null ? null : java.sql.Timestamp.from(result.lastSuccessfulCheckAt()));
                    insert.setTimestamp(14, result.cacheExpiryAt() == null ? null : java.sql.Timestamp.from(result.cacheExpiryAt()));
                    insert.setTimestamp(15, result.attemptedRefreshAt() == null ? null : java.sql.Timestamp.from(result.attemptedRefreshAt()));
                    insert.setTimestamp(16, result.suggestedRetryAt() == null ? null : java.sql.Timestamp.from(result.suggestedRetryAt()));
                    insert.setString(17, result.message());
                    insert.addBatch();
                }
                insert.executeBatch();
            }
        }

        private ScanComponent componentById(List<ScanComponent> components, long componentId) {
            for (ScanComponent component : components) {
                if (component.id() == componentId) {
                    return component;
                }
            }
            return null;
        }

        private ScanReport buildReport(ScanInput input, String projectId, String scanId, Consumer<String> progress) {
            List<ScanComponent> components = input.components();
            int total = components.size();

            // Pass 1: version metadata
            Map<Long, VersionMetadata> versionMap = new LinkedHashMap<>();
            for (int i = 0; i < components.size(); i++) {
                ScanComponent c = components.get(i);
                progress.accept("Version " + (i + 1) + "/" + total);
                if (!c.snapshot()) {
                    versionMap.put(c.id(), versionProvider.latestVersion(c.coordinate(), c.version()));
                }
            }

            // Pass 2: vulnerability scan
            Map<Long, List<VulnerabilityFinding>> vulnMap = new LinkedHashMap<>();
            for (int i = 0; i < components.size(); i++) {
                ScanComponent c = components.get(i);
                progress.accept("Vulnerability " + (i + 1) + "/" + total);
                if (!c.snapshot()) {
                    vulnMap.put(c.id(), vulnerabilityProvider.vulnerabilities(c.coordinate(), c.version()));
                }
            }

            // Pass 3: upgrade analysis
            progress.accept("Upgrades");
            List<SnapshotDependencyRisk> snapshotRisks = new ArrayList<>();
            List<UpgradeRecommendation> recs = new ArrayList<>();
            List<MetadataResult> metadata = new ArrayList<>();
            List<VulnerabilityFinding> vulnerabilityFindings = new ArrayList<>();
            boolean complete = true;
            for (ScanComponent component : components) {
                LOGGER.info(() -> "Enriching component " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " version=" + component.version());
                if (component.snapshot()) {
                    LOGGER.info(() -> "Component is SNAPSHOT; recording unverified dependency risk for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                    snapshotRisks.add(new SnapshotDependencyRisk(component.id(), "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata.", "Use release.", severity(component.scope())));
                    String target = component.version() == null ? "1.0.0" : component.version().replace("-SNAPSHOT", "");
                    recs.add(new UpgradeRecommendation(component.id(), component.coordinate(), component.version(), target, RecommendationReason.SNAPSHOT_REPLACEMENT, RiskLevel.MAJOR, RecommendationConfidence.MEDIUM, List.of(), List.of(component.id())));
                    LOGGER.info(() -> "No Maven/CVE verification attempted for SNAPSHOT component " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, "none", component.version(), "unknown", "unknown", List.of(), false, MetadataStatus.NOT_APPLICABLE, CacheState.MISSING, null, null, Instant.now(), null, "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata."));
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VULNERABILITY, "none", component.version(), "unknown", "unknown", List.of(), false, MetadataStatus.NOT_APPLICABLE, CacheState.MISSING, null, null, Instant.now(), null, "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata."));
                } else {
                    VersionMetadata versionMetadata = versionMap.get(component.id());
                    LOGGER.info(() -> "Maven version metadata for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " => latest=" + versionMetadata.latestVersion() + ", sameMajor=" + versionMetadata.latestSameMajorVersion() + ", complete=" + versionMetadata.complete() + ", status=" + versionMetadata.status());
                    String versionMessage = versionMetadata.complete()
                            ? "Latest Maven release is " + versionMetadata.latestVersion() + "."
                            : "No cached Maven metadata was available; version is unknown.";
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, versionMetadata.source(), component.version(), versionMetadata.latestVersion(), versionMetadata.latestSameMajorVersion(), versionMetadata.upgradePathVersions(), versionMetadata.complete(), versionMetadata.status(), versionMetadata.cacheState(), versionMetadata.checkedAt(), null, Instant.now(), null, versionMessage));
                    if (!versionMetadata.complete()) {
                        complete = false;
                    }

                    List<VulnerabilityFinding> compVulns = vulnMap.getOrDefault(component.id(), List.of());
                    boolean hasVulns = !compVulns.isEmpty();
                    String vulnMessage = hasVulns
                            ? "Found " + compVulns.size() + " vulnerabilit" + (compVulns.size() == 1 ? "y" : "ies") + "."
                            : "No known vulnerabilities.";
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VULNERABILITY, "osv.dev", component.version(), "unknown", "unknown", List.of(), true, MetadataStatus.FRESH, CacheState.FRESH, Instant.now(), null, Instant.now(), null, vulnMessage));
                    for (VulnerabilityFinding f : compVulns) {
                        vulnerabilityFindings.add(new VulnerabilityFinding(f.advisoryId(), f.severity(), f.coordinate(), f.affectedVersion(), f.fixedVersion(), component.direct(), component.owningVersionControlPoint(), f.cves(), null));
                    }

                    if (versionMetadata.complete() && canPlanUpgrade(component)) {
                        String target = selectUpgradeTarget(component.version(), versionMetadata);
                        if (target != null && isUpgradeable(component.version(), target)) {
                            if (!input.allowMajorUpgrades() && isMajorUpgrade(component.version(), target)) {
                                LOGGER.info(() -> "Skipping major upgrade recommendation for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " because the scan did not allow major upgrades");
                            } else {
                                RecommendationReason reason = hasVulns ? RecommendationReason.CVE_FIX : upgradeReason(component.version(), target);
                                RiskLevel risk = component.direct() ? upgradeRisk(component.version(), target) : RiskLevel.ELEVATED;
                                RecommendationConfidence confidence = RecommendationConfidence.HIGH;
                                recs.add(new UpgradeRecommendation(component.id(), component.coordinate(), component.version(), target, reason, risk, confidence, List.of(), List.of(component.id())));
                                LOGGER.info(() -> "Created Maven upgrade recommendation for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " => " + component.version() + " -> " + target);
                            }
                        } else if (versionMetadata.complete()) {
                            LOGGER.info(() -> "No upgrade recommendation selected for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " because no later version was suitable");
                        }
                    } else if (!component.direct()) {
                        LOGGER.info(() -> "Transitive dependency " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " is reported without an edit recommendation");
                    } else if (versionMetadata.complete()) {
                        LOGGER.info(() -> "Maven dependency is up to date for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " at version " + component.version());
                    }
                }
            }
            List<String> treeWarnings = input.treeParseWarnings() != null ? input.treeParseWarnings() : List.of();
            if (!treeWarnings.isEmpty()) complete = false;
            boolean buildFailed = treeWarnings.stream().anyMatch(w -> w.startsWith("[BUILD_FAILED]"));
            String message;
            if (complete) {
                message = "Analysis complete. Dependency and vulnerability metadata was checked using fresh provider data or fresh cache.";
            } else if (buildFailed) {
                message = "Build failed. Maven could not resolve the project model — check the analysis log for details and re-analyse after fixing the POM.";
            } else if (!treeWarnings.isEmpty()) {
                message = "Analysis incomplete. " + treeWarnings.size() + " dependency tree line(s) could not be parsed. Re-analyse after resolving the issues listed below.";
            } else {
                message = "Analysis incomplete. Some Maven metadata could not be refreshed or was unavailable. The analysis is still shown with unknown metadata and re-analysis is suggested.";
            }
            return new ScanReport(scanId, projectId, complete, message, Instant.now(), input.components(), input.dependencyEdges(), List.copyOf(vulnerabilityFindings), recs, snapshotRisks, metadata, treeWarnings);
        }

        private String reasonMessage(RecommendationReason reason, String target) {
            return switch (reason) {
                case PATCH_AVAILABLE -> "A newer patch release is available: " + target + ".";
                case MINOR_AVAILABLE -> "A newer minor release is available: " + target + ".";
                case MAJOR_AVAILABLE -> "A newer major release is available: " + target + ".";
                case CVE_FIX -> "A fixed release is available: " + target + ".";
                case SNAPSHOT_REPLACEMENT -> "Use release.";
            };
        }

        private String selectUpgradeTarget(String currentVersion, VersionMetadata versionMetadata) {
            if (versionMetadata == null) {
                return null;
            }
            String sameMajor = versionMetadata.latestSameMajorVersion();
            if (!isPreRelease(sameMajor) && isUpgradeable(currentVersion, sameMajor)) {
                return sameMajor;
            }
            if (versionMetadata.upgradePathVersions() == null || versionMetadata.upgradePathVersions().isEmpty()) {
                return versionMetadata == null ? null : versionMetadata.latestVersion();
            }
            for (String candidate : versionMetadata.upgradePathVersions()) {
                if (candidate == null || candidate.isBlank() || isPreRelease(candidate)) {
                    continue;
                }
                if (!isUpgradeable(currentVersion, candidate)) {
                    continue;
                }
                if (major(currentVersion) == major(candidate) && minor(currentVersion) == minor(candidate)) {
                    return candidate;
                }
                if (major(currentVersion) == major(candidate) && minor(candidate) > minor(currentVersion)) {
                    return candidate;
                }
            }
            for (String candidate : versionMetadata.upgradePathVersions()) {
                if (candidate == null || candidate.isBlank() || isPreRelease(candidate)) {
                    continue;
                }
                if (!isUpgradeable(currentVersion, candidate)) {
                    continue;
                }
                return candidate;
            }
            String latest = versionMetadata.latestVersion();
            if (!isPreRelease(latest) && isUpgradeable(currentVersion, latest)) {
                return latest;
            }
            return null;
        }

        private boolean isUpgradeable(String currentVersion, String latestVersion) {
            if (currentVersion == null || currentVersion.isBlank() || latestVersion == null || latestVersion.isBlank()) {
                return false;
            }
            return compareVersions(currentVersion, latestVersion) < 0;
        }

        private boolean isMajorUpgrade(String currentVersion, String targetVersion) {
            return major(currentVersion) < major(targetVersion);
        }

        private RecommendationReason upgradeReason(String currentVersion, String targetVersion) {
            if (isMajorUpgrade(currentVersion, targetVersion)) {
                return RecommendationReason.MAJOR_AVAILABLE;
            }
            int currentMinor = minor(currentVersion);
            int targetMinor = minor(targetVersion);
            if (targetMinor > currentMinor) {
                return RecommendationReason.MINOR_AVAILABLE;
            }
            return RecommendationReason.PATCH_AVAILABLE;
        }

        private RiskLevel upgradeRisk(String currentVersion, String targetVersion) {
            if (isMajorUpgrade(currentVersion, targetVersion)) {
                return RiskLevel.MAJOR;
            }
            int currentMinor = minor(currentVersion);
            int targetMinor = minor(targetVersion);
            if (targetMinor > currentMinor) {
                return RiskLevel.MINOR;
            }
            return RiskLevel.PATCH;
        }

        private int major(String version) {
            return parseVersionPart(version, 0);
        }

        private int minor(String version) {
            return parseVersionPart(version, 1);
        }

        private int parseVersionPart(String version, int index) {
            if (version == null) {
                return 0;
            }
            String[] parts = version.replace('_', '.').split("[.-]");
            if (index >= parts.length) {
                return 0;
            }
            try {
                String token = parts[index].replaceAll("[^0-9].*$", "");
                if (token.isBlank()) {
                    return 0;
                }
                return Integer.parseInt(token);
            } catch (NumberFormatException e) {
                return 0;
            }
        }

        private int compareVersions(String left, String right) {
            String[] leftParts = normalizeVersion(left).split("\\.");
            String[] rightParts = normalizeVersion(right).split("\\.");
            int max = Math.max(leftParts.length, rightParts.length);
            for (int i = 0; i < max; i++) {
                int leftPart = i < leftParts.length ? parsePart(leftParts[i]) : 0;
                int rightPart = i < rightParts.length ? parsePart(rightParts[i]) : 0;
                if (leftPart != rightPart) {
                    return Integer.compare(leftPart, rightPart);
                }
            }
            return 0;
        }

        private String normalizeVersion(String version) {
            if (version == null || version.isBlank()) {
                return "0";
            }
            return version.trim().replace('-', '.').replace('_', '.');
        }

        private int parsePart(String part) {
            try {
                String digits = part.replaceAll("[^0-9].*$", "");
                if (digits.isBlank()) {
                    return 0;
                }
                return Integer.parseInt(digits);
            } catch (NumberFormatException e) {
                return 0;
            }
        }

        private String severity(DependencyScope scope) {
            return switch (scope) {
                case COMPILE, RUNTIME -> "HIGH";
                case PROVIDED, PLUGIN_BUILD -> "MEDIUM";
                case TEST -> "LOW";
                default -> "UNKNOWN";
            };
        }

        private void initializeSchema() {
            try (Connection connection = connection();
                 Statement st = connection.createStatement()) {

                // v2 is the only versioned gate: it was a destructive rekey from integer to UUID
                // primary keys. Guard it so it never re-runs on a DB that has already been migrated.
                st.executeUpdate("create table if not exists rk_schema_version (version int primary key)");
                int storedVersion;
                try (ResultSet vrs = st.executeQuery("select version from rk_schema_version")) {
                    storedVersion = vrs.next() ? vrs.getInt("version") : 0;
                }
                if (storedVersion < 2) {
                    LOGGER.info("One-time migration: dropping pre-UUID tables");
                    st.executeUpdate("drop table if exists generated_poms");
                    st.executeUpdate("drop table if exists source_poms");
                    st.executeUpdate("drop table if exists metadata_cache_entries");
                    st.executeUpdate("drop table if exists scans");
                    st.executeUpdate("drop table if exists projects");
                    st.executeUpdate("merge into rk_schema_version (version) values (2)");
                }

                // --- create all tables with their current full schema ---
                // Idempotent: CREATE TABLE IF NOT EXISTS is a no-op when the table already exists.

                st.executeUpdate("""
                        create table if not exists projects (
                          id uuid primary key,
                          name varchar(255) not null,
                          root_path varchar(1024) not null unique,
                          created_at timestamp not null default current_timestamp,
                          updated_at timestamp not null default current_timestamp,
                          enforcer_use_verify boolean not null default false
                        )
                        """);

                st.executeUpdate("""
                        create table if not exists scans (
                          id uuid primary key,
                          project_id uuid not null,
                          project_name varchar(255) not null,
                          repo_path varchar(1024) not null,
                          branch_name varchar(255) not null,
                          head_commit varchar(128) not null,
                          working_tree_clean boolean not null,
                          raw_input_json text not null,
                          report_json text not null,
                          complete boolean not null,
                          completeness_message text not null,
                          created_at timestamp not null default current_timestamp,
                          foreign key (project_id) references projects(id) on delete cascade
                        )
                        """);

                st.executeUpdate("""
                        create table if not exists metadata_cache_entries (
                          id uuid default random_uuid() primary key,
                          scan_id uuid not null,
                          component_id bigint not null,
                          metadata_type varchar(32) not null,
                          provider varchar(255) not null,
                          component_group_id varchar(255) not null,
                          component_artifact_id varchar(255) not null,
                          component_version varchar(255) not null,
                          latest_version varchar(255) not null,
                          latest_same_major_version varchar(255) not null,
                          complete boolean not null,
                          status varchar(32) not null,
                          cache_state varchar(32) not null,
                          last_successful_check_at timestamp with time zone,
                          cache_expiry_at timestamp with time zone,
                          attempted_refresh_at timestamp with time zone,
                          suggested_retry_at timestamp with time zone,
                          message text not null,
                          created_at timestamp with time zone not null default current_timestamp,
                          updated_at timestamp with time zone not null default current_timestamp,
                          unique (scan_id, component_id, metadata_type),
                          foreign key (scan_id) references scans(id) on delete cascade
                        )
                        """);

                st.executeUpdate("""
                        create table if not exists source_poms (
                          id uuid default random_uuid() primary key,
                          scan_id uuid not null,
                          file_path varchar(1024) not null,
                          pom_xml text not null,
                          unique (scan_id, file_path),
                          foreign key (scan_id) references scans(id) on delete cascade
                        )
                        """);

                st.executeUpdate("""
                        create table if not exists generated_poms (
                          id uuid default random_uuid() primary key,
                          scan_id uuid not null,
                          file_path varchar(1024) not null,
                          pom_xml text not null,
                          generated_at timestamp not null default current_timestamp,
                          unique (scan_id, file_path),
                          foreign key (scan_id) references scans(id) on delete cascade
                        )
                        """);

                st.executeUpdate("""
                        create table if not exists provider_rate_limit_state (
                          provider varchar(255) primary key,
                          rate_limited_at timestamp with time zone,
                          retry_after_at timestamp with time zone,
                          consecutive_rate_limits integer not null,
                          cooldown_until timestamp with time zone,
                          last_success_at timestamp with time zone,
                          updated_at timestamp with time zone not null default current_timestamp
                        )
                        """);

                st.executeUpdate("""
                        create table if not exists enforcer_results (
                          scan_id uuid primary key,
                          status varchar(64) not null,
                          raw_output text not null default '',
                          findings_blob text not null default '',
                          stale_exclusions_json text not null default '[]',
                          phase2_findings_blob text not null default '',
                          exclusions_stripped int not null default 0,
                          dep_mgmt_removed_json text not null default '[]',
                          phase2_pins_json text not null default '[]',
                          created_at timestamp not null default current_timestamp,
                          foreign key (scan_id) references scans(id) on delete cascade
                        )
                        """);

                st.executeUpdate("""
                        create table if not exists rk_version_cache (
                          cache_key varchar(512) primary key,
                          all_versions text not null,
                          latest_version varchar(255),
                          source varchar(512),
                          expires_at_epoch_ms bigint not null,
                          status varchar(32) not null,
                          complete boolean not null,
                          updated_at timestamp with time zone not null default current_timestamp
                        )
                        """);

                st.executeUpdate("""
                        create table if not exists rk_vuln_cache (
                          cache_key varchar(512) primary key,
                          response_json text not null,
                          expires_at_epoch_ms bigint not null,
                          updated_at timestamp with time zone not null default current_timestamp
                        )
                        """);

                // --- reconcile columns that were added to existing tables after initial release ---
                // ADD COLUMN IF NOT EXISTS is a no-op when the column already exists, so these
                // run on every startup without harm. New installs never reach these (the CREATE
                // TABLE above already includes all columns).
                st.executeUpdate("alter table enforcer_results add column if not exists stale_exclusions_json text not null default '[]'");
                st.executeUpdate("alter table enforcer_results add column if not exists phase2_findings_blob text not null default ''");
                st.executeUpdate("alter table enforcer_results add column if not exists exclusions_stripped int not null default 0");
                st.executeUpdate("alter table enforcer_results add column if not exists dep_mgmt_removed_json text not null default '[]'");
                st.executeUpdate("alter table enforcer_results add column if not exists phase2_pins_json text not null default '[]'");
                st.executeUpdate("alter table projects add column if not exists enforcer_use_verify boolean not null default false");

            } catch (SQLException e) {
                throw new IllegalStateException("Failed to initialize schema", e);
            }
        }

        private Connection connection() throws SQLException {
            return DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
        }

        private String upsertProject(Connection connection, String name, String rootPath) throws SQLException {
            try (PreparedStatement select = connection.prepareStatement("select id from projects where root_path = ?")) {
                select.setString(1, rootPath);
                try (ResultSet rs = select.executeQuery()) {
                    if (rs.next()) {
                        String id = rs.getString(1);
                        try (PreparedStatement update = connection.prepareStatement("update projects set name = ?, updated_at = current_timestamp where id = ?")) {
                            update.setString(1, name);
                            update.setString(2, id);
                            update.executeUpdate();
                        }
                        return id;
                    }
                }
            }
            String id = java.util.UUID.randomUUID().toString();
            try (PreparedStatement insert = connection.prepareStatement("insert into projects(id, name, root_path) values (?, ?, ?)")) {
                insert.setString(1, id);
                insert.setString(2, name);
                insert.setString(3, rootPath);
                insert.executeUpdate();
            }
            return id;
        }

        private String insertScan(Connection connection, String projectId, ScanInput input, ScanReport report) throws SQLException {
            String scanId = java.util.UUID.randomUUID().toString();
            try (PreparedStatement insert = connection.prepareStatement("""
                    insert into scans(id, project_id, project_name, repo_path, branch_name, head_commit, working_tree_clean, raw_input_json, report_json, complete, completeness_message)
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                insert.setString(1, scanId);
                insert.setString(2, projectId);
                insert.setString(3, input.projectName());
                insert.setString(4, input.projectRootPath());
                insert.setString(5, input.currentBranch());
                insert.setString(6, input.currentHeadCommit());
                insert.setBoolean(7, input.workingTreeClean());
                insert.setString(8, SerializationSupport.toBase64(input));
                insert.setString(9, SerializationSupport.toBase64(report));
                insert.setBoolean(10, report.complete());
                insert.setString(11, report.completenessMessage());
                insert.executeUpdate();
            }
            pruneScanHistory(connection, projectId);
            return scanId;
        }

        private void pruneScanHistory(Connection connection, String projectId) throws SQLException {
            try (PreparedStatement stmt = connection.prepareStatement("""
                    delete from scans where project_id = ? and id not in (
                      select id from (select id from scans where project_id = ? order by created_at desc limit 7) as t
                    )
                    """)) {
                stmt.setString(1, projectId);
                stmt.setString(2, projectId);
                stmt.executeUpdate();
            }
        }

        private void updateScanReport(Connection connection, String scanId, ScanReport report) throws SQLException {
            try (PreparedStatement update = connection.prepareStatement("update scans set report_json = ?, complete = ?, completeness_message = ? where id = ?")) {
                update.setString(1, SerializationSupport.toBase64(report));
                update.setBoolean(2, report.complete());
                update.setString(3, report.completenessMessage());
                update.setString(4, scanId);
                update.executeUpdate();
            }
        }

        private ScanEntry scanFromRow(ResultSet rs) throws SQLException {
            ScanInput input = SerializationSupport.fromBase64(rs.getString("raw_input_json"), ScanInput.class);
            ScanReport report = SerializationSupport.fromBase64(rs.getString("report_json"), ScanReport.class);
            return new ScanEntry(rs.getString("id"), rs.getString("project_id"), input, report, rs.getTimestamp("created_at").toInstant());
        }

        private void persistSourcePoms(Connection connection, String scanId, ScanInput input) throws SQLException {
            java.util.Set<String> paths = new LinkedHashSet<>();
            // Include all discovered POM files, not just those with components
            paths.addAll(input.fileHashes().keySet());
            for (ScanComponent c : input.components()) {
                if (c.sourceFilePath() != null && !c.sourceFilePath().isBlank()) {
                    paths.add(c.sourceFilePath());
                }
            }
            try (PreparedStatement del = connection.prepareStatement("delete from source_poms where scan_id = ?")) {
                del.setString(1, scanId);
                del.executeUpdate();
            }
            try (PreparedStatement ins = connection.prepareStatement(
                    "insert into source_poms(scan_id, file_path, pom_xml) values (?, ?, ?)")) {
                for (String filePath : paths) {
                    try {
                        Path pomPath = Path.of(filePath);
                        if (!pomPath.isAbsolute()) pomPath = Path.of(input.workingTreePath()).resolve(pomPath);
                        String raw = Files.readString(pomPath);
                        ins.setString(1, scanId);
                        ins.setString(2, filePath);
                        ins.setString(3, raw);
                        ins.executeUpdate();
                    } catch (IOException e) {
                        LOGGER.warning(() -> "Could not snapshot POM: " + filePath + " — " + e.getMessage());
                    }
                }
            }
        }

        synchronized Map<String, String> loadSourcePoms(String scanId) {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement(
                         "select file_path, pom_xml from source_poms where scan_id = ? order by file_path")) {
                ps.setString(1, scanId);
                Map<String, String> result = new LinkedHashMap<>();
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) result.put(rs.getString("file_path"), rs.getString("pom_xml"));
                }
                return result;
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to load source POMs", e);
            }
        }

        synchronized boolean hasSourcePoms(String scanId) {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement("select count(*) from source_poms where scan_id = ?")) {
                ps.setString(1, scanId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() && rs.getLong(1) > 0;
                }
            } catch (SQLException e) {
                return false;
            }
        }

        synchronized boolean hasSavedPom(String scanId) {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement("select count(*) from generated_poms where scan_id = ?")) {
                ps.setString(1, scanId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() && rs.getLong(1) > 0;
                }
            } catch (SQLException e) {
                return false;
            }
        }

        synchronized void savePomFiles(String scanId, Map<String, String> files) {
            try (Connection connection = connection()) {
                try (PreparedStatement del = connection.prepareStatement("delete from generated_poms where scan_id = ?")) {
                    del.setString(1, scanId);
                    del.executeUpdate();
                }
                try (PreparedStatement ins = connection.prepareStatement(
                        "insert into generated_poms(scan_id, file_path, pom_xml) values (?, ?, ?)")) {
                    for (Map.Entry<String, String> e : files.entrySet()) {
                        ins.setString(1, scanId);
                        ins.setString(2, e.getKey());
                        ins.setString(3, e.getValue());
                        ins.executeUpdate();
                    }
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to save generated POMs", e);
            }
        }

        synchronized Map<String, String> loadPomFiles(String scanId) {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement(
                         "select file_path, pom_xml from generated_poms where scan_id = ? order by file_path")) {
                ps.setString(1, scanId);
                Map<String, String> result = new LinkedHashMap<>();
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) result.put(rs.getString("file_path"), rs.getString("pom_xml"));
                }
                return result;
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to load generated POMs", e);
            }
        }

        synchronized void saveEnforcerResult(String scanId, EnforcerStatus status,
                                             String rawOutput, List<TransitiveConflictFinding> findings,
                                             List<String> staleExclusions,
                                             List<TransitiveConflictFinding> phase2Findings,
                                             int exclusionsStripped, List<String> depMgmtRemoved,
                                             List<String> phase2Pins) {
            try (Connection c = connection();
                 PreparedStatement ps = c.prepareStatement(
                         "merge into enforcer_results (scan_id, status, raw_output, findings_blob, stale_exclusions_json, phase2_findings_blob, exclusions_stripped, dep_mgmt_removed_json, phase2_pins_json) key (scan_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, scanId);
                ps.setString(2, status.name());
                ps.setString(3, rawOutput == null ? "" : rawOutput);
                ps.setString(4, SerializationSupport.toBase64(new java.util.ArrayList<>(findings)));
                ps.setString(5, toJsonStringArray(staleExclusions));
                ps.setString(6, phase2Findings == null ? "" : SerializationSupport.toBase64(new java.util.ArrayList<>(phase2Findings)));
                ps.setInt(7, exclusionsStripped);
                ps.setString(8, toJsonStringArray(depMgmtRemoved));
                ps.setString(9, toJsonStringArray(phase2Pins));
                ps.executeUpdate();
            } catch (SQLException e) {
                LOGGER.warning(() -> "Failed to save enforcer result for scan " + scanId + ": " + e.getMessage());
            }
        }

        private static String toJsonStringArray(List<String> list) {
            if (list == null || list.isEmpty()) return "[]";
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(list.get(i).replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
            }
            return sb.append("]").toString();
        }

        private static List<String> fromJsonStringArray(String json) {
            if (json == null || json.isBlank() || "[]".equals(json.trim())) return List.of();
            String inner = json.trim();
            if (inner.startsWith("[")) inner = inner.substring(1);
            if (inner.endsWith("]")) inner = inner.substring(0, inner.length() - 1);
            List<String> result = new ArrayList<>();
            for (String part : inner.split(",")) {
                String s = part.trim();
                if (s.startsWith("\"")) s = s.substring(1);
                if (s.endsWith("\"")) s = s.substring(0, s.length() - 1);
                if (!s.isEmpty()) result.add(s);
            }
            return result;
        }

        synchronized Map<String, EnforcerResultEntry> getEnforcerResults(List<String> scanIds) {
            if (scanIds.isEmpty()) return Map.of();
            Map<String, EnforcerResultEntry> result = new LinkedHashMap<>();
            for (String id : scanIds) {
                EnforcerResultEntry entry = getEnforcerResult(id);
                if (entry != null) result.put(id, entry);
            }
            return result;
        }

        synchronized EnforcerResultEntry getEnforcerResult(String scanId) {
            try (Connection c = connection();
                 PreparedStatement ps = c.prepareStatement(
                         "select status, raw_output, findings_blob, stale_exclusions_json, phase2_findings_blob, exclusions_stripped, dep_mgmt_removed_json, phase2_pins_json from enforcer_results where scan_id = ?")) {
                ps.setString(1, scanId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    EnforcerStatus status = EnforcerStatus.valueOf(rs.getString("status"));
                    String rawOutput = rs.getString("raw_output");
                    @SuppressWarnings("unchecked")
                    List<TransitiveConflictFinding> findings = SerializationSupport.fromBase64(rs.getString("findings_blob"), java.util.ArrayList.class);
                    List<String> staleExclusions = fromJsonStringArray(rs.getString("stale_exclusions_json"));
                    String p2blob = rs.getString("phase2_findings_blob");
                    @SuppressWarnings("unchecked")
                    List<TransitiveConflictFinding> phase2Findings = (p2blob == null || p2blob.isBlank())
                            ? null : SerializationSupport.fromBase64(p2blob, java.util.ArrayList.class);
                    int exclusionsStripped = rs.getInt("exclusions_stripped");
                    List<String> depMgmtRemoved = fromJsonStringArray(rs.getString("dep_mgmt_removed_json"));
                    List<String> phase2Pins = fromJsonStringArray(rs.getString("phase2_pins_json"));
                    return new EnforcerResultEntry(status, rawOutput,
                            findings == null ? List.of() : findings, staleExclusions, phase2Findings,
                            exclusionsStripped, depMgmtRemoved, phase2Pins);
                }
            } catch (SQLException | IllegalArgumentException e) {
                LOGGER.warning(() -> "Failed to load enforcer result for scan " + scanId + ": " + e.getMessage());
                return null;
            }
        }

        record EnforcerResultEntry(EnforcerStatus status, String rawOutput,
                                   List<TransitiveConflictFinding> findings, List<String> staleExclusions,
                                   List<TransitiveConflictFinding> phase2Findings,
                                   int exclusionsStripped, List<String> depMgmtRemoved,
                                   List<String> phase2Pins) {}

    }

    record ProjectEntry(String id, String name, String rootPath, Instant createdAt, Instant updatedAt) implements java.io.Serializable {
    }

    record ScanEntry(String id, String projectId, ScanInput input, ScanReport report, Instant createdAt) implements java.io.Serializable {
    }
}
