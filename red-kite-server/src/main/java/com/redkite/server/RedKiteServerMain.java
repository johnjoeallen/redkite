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
import com.redkite.core.service.CandidateUpdateResolver;
import com.redkite.core.service.RemediationClassifier;
import com.redkite.core.service.UpdatePlanBuilder;

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
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.stream.Collectors;
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
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class RedKiteServerMain {
    private static final Logger LOGGER = Logger.getLogger(RedKiteServerMain.class.getName());
    private static final String BRAND = "RedKite";
    private static final String VERSION = Optional.ofNullable(RedKiteServerMain.class.getPackage().getImplementationVersion())
            .orElse("dev");

    @FunctionalInterface
    private interface ExchangeHandler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private static final Set<String> VALID_THEMES = Set.of("dark", "light", "ocean", "dusk", "forest", "ember");

    private record ConfigTtlEntry(String key, String label, Duration defaultValue) {}

    /** The cache TTLs editable from the /config page — single source of truth shared by the
     *  first-run seeding logic and the config page's rendering, so the two never drift apart. */
    private static final List<ConfigTtlEntry> CONFIG_TTL_ENTRIES = List.of(
            new ConfigTtlEntry(HttpVulnerabilityProvider.CONFIG_KEY_FRESH_TTL,
                    "Vulnerability lookup cache (OSV.dev)", HttpVulnerabilityProvider.DEFAULT_FRESH_TTL),
            new ConfigTtlEntry(HttpVersionMetadataProvider.CONFIG_KEY_FRESH_TTL,
                    "Version metadata cache (Maven Central)", HttpVersionMetadataProvider.DEFAULT_FRESH_TTL),
            new ConfigTtlEntry(HttpVersionMetadataProvider.CONFIG_KEY_LOCAL_TTL,
                    "Version metadata cache (internal/local repositories)", HttpVersionMetadataProvider.DEFAULT_LOCAL_TTL),
            new ConfigTtlEntry(HttpVersionMetadataProvider.CONFIG_KEY_NEGATIVE_TTL,
                    "Version metadata cache (artifact not found)", HttpVersionMetadataProvider.DEFAULT_NEGATIVE_TTL),
            new ConfigTtlEntry(HttpVersionMetadataProvider.CONFIG_KEY_ERROR_TTL,
                    "Version metadata cache (provider error)", HttpVersionMetadataProvider.DEFAULT_ERROR_TTL));

    /** Preset choices offered by each TTL dropdown on the /config page, in minutes. */
    private static final List<Map.Entry<Long, String>> CONFIG_TTL_OPTIONS = List.of(
            Map.entry(15L, "15 minutes"),
            Map.entry(30L, "30 minutes"),
            Map.entry(60L, "1 hour"),
            Map.entry(120L, "2 hours"),
            Map.entry(240L, "4 hours"),
            Map.entry(360L, "6 hours"),
            Map.entry(720L, "12 hours"),
            Map.entry(1440L, "1 day"));

    private final Store store;
    private final HttpServer server;
    private final ConcurrentHashMap<String, ScanJob> scanJobs = new ConcurrentHashMap<>();

    private static final class ApplyJob {
        enum Status { RUNNING, DONE, FAILED, ERROR }
        enum Phase { PRE_VALIDATE, APPLYING, POST_VALIDATE }
        volatile Status status = Status.RUNNING;
        volatile Phase phase = Phase.PRE_VALIDATE;
        volatile boolean baselinePassed = true;
        volatile String failureMessage;
        volatile String attribution;
        volatile String revertedVersion;
        volatile String failedVersion;
        volatile String failureSignature;
        /** True when the fully-computed patched POM set turned out identical to what's already on
         *  disk — nothing was validated or written, since there was nothing to apply. */
        volatile boolean noChanges = false;
    }

    private final ConcurrentHashMap<String, ApplyJob> applyJobs = new ConcurrentHashMap<>();
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
             + "{\"name\":\"Update analysis\",\"pct\":" + p3 + ",\"status\":\"" + s3 + "\"},"
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
        server.createContext("/api/scans/remediation/apply-batch", exchange -> safeHandle(exchange, this::handleApiRemediationApplyBatch));
        server.createContext("/api/scans/remediation/apply-status", exchange -> safeHandle(exchange, this::handleApiRemediationApplyStatus));
        server.createContext("/api/scans/remediation/resolve", exchange -> safeHandle(exchange, this::handleApiRemediationResolve));
        server.createContext("/api/scans/remediation/plan", exchange -> safeHandle(exchange, this::handleApiRemediationPlan));
        server.createContext("/config", exchange -> safeHandle(exchange, this::handleConfig));
        server.createContext("/api/config", exchange -> safeHandle(exchange, this::handleApiConfig));
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

            body.append("<section class=\"card span-2\"><h2>Build validation</h2>");
            body.append("<p class=\"muted\">Extra options used when validating this project's build before/after Applying changes ")
                    .append("(e.g. a Spring profile a spring-boot:run startup check needs). Applies to the next apply.</p>");
            body.append("<form method=\"POST\" action=\"/api/projects/").append(escape(project.id())).append("/validation\">");
            body.append("<div class=\"config-row\"><label for=\"mavenArgs\">Extra mvn arguments</label>");
            body.append("<div class=\"config-row-input\"><input type=\"text\" id=\"mavenArgs\" name=\"mavenArgs\" ")
                    .append("placeholder=\"-Pdev -Dspring.profiles.active=dev\" value=\"")
                    .append(escape(project.validationMavenArgs())).append("\"></div></div>");
            body.append("<div class=\"config-row\"><label for=\"env\">Extra environment variables</label>");
            body.append("<div class=\"config-row-input\"><input type=\"text\" id=\"env\" name=\"env\" ")
                    .append("placeholder=\"SPRING_PROFILES_ACTIVE=dev,DB_HOST=localhost\" value=\"")
                    .append(escape(project.validationEnv())).append("\"></div></div>");
            body.append("<button class=\"button primary\" type=\"submit\">Save</button>");
            body.append("</form>");
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
                    } else if ("Updates".equals(msg)) {
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
            ScanEntry scanEntry = store.getScan(scanId);
            String projectId = scanEntry.projectId();
            List<ScanComponent> components = scanEntry.report().components();
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
                    String tail = rawOutput.length() > 2000 ? rawOutput.substring(rawOutput.length() - 2000) : rawOutput;
                    LOGGER.warning(() -> "Enforcer ran but produced no parseable conflict findings for scan "
                            + scanId + ". Raw output (last 2000 chars):\n" + tail);
                } else {
                    status = EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS;
                }
            }

            // Phase 2: verify auto-fix with computed dep-management pins
            progress.accept("Dependency management 60");
            List<TransitiveConflictFinding> phase2Findings = null;
            List<String> phase2Pins = List.of();
            if (status == EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS) {
                Phase2Result p2 = runPhase2Validation(projectRoot, pomPath, findings, skipDirectEnforce, components);
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
            LOGGER.log(java.util.logging.Level.WARNING,
                    "Enforcer check failed for scan " + scanId, e);
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
            boolean skipDirectEnforce, List<ScanComponent> components) {
        try {
            // The project's own (non-RedKite) dep-management entries are deliberate choices —
            // pristine analysis strips them, which resurfaces conflicts the project has already
            // resolved. Respect the project's version for those artifacts instead of re-deriving
            // a winner from the stripped tree (which max-picks and can cross a release line the
            // project deliberately avoided, e.g. Netty 4.1 -> 4.2).
            Map<String, String> declared = projectDeclaredDepMgmt(readFileQuietly(pomPath));
            Map<String, String> pins = new LinkedHashMap<>();
            for (TransitiveConflictFinding f : findings) {
                String key = f.groupId() + ":" + f.artifactId();
                String winner = reconcileWithDeclared(computeWinnerVersion(f, ""), declared.get(key));
                if (winner != null && !winner.isBlank()) {
                    pins.put(key, winner);
                }
            }
            alignFamilyVersions(pins, components, declared);
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
     * A group of artifacts released together on one version (a "release train"), where pinning
     * members independently — as {@link #computeWinnerVersion} does per groupId:artifactId — can
     * split the family across incompatible versions (e.g. forcing {@code cucumber-core} lower than
     * the {@code cucumber.version} the rest of the Cucumber stack is declared at, which breaks
     * {@code cucumber-junit-platform-engine}'s test discovery).
     *
     * @param artifactAllowlist restricts matching to these artifactIds within the group, for
     *                          families that publish independently-versioned siblings under the
     *                          same groupId (e.g. Cucumber's formatter/reporting plugins and the
     *                          standalone {@code io.cucumber:gherkin} parser, which do NOT share
     *                          {@code cucumber.version}). {@code null} matches every artifact under
     *                          {@code groupIdPrefix}.
     */
    private record FamilyGroup(String id, String groupIdPrefix, Set<String> artifactAllowlist) {
        boolean matches(String groupId, String artifactId) {
            boolean groupMatches = groupId.equals(groupIdPrefix) || groupId.startsWith(groupIdPrefix + ".");
            if (!groupMatches) return false;
            return artifactAllowlist == null || artifactAllowlist.contains(artifactId);
        }
    }

    private static final List<FamilyGroup> COORDINATED_FAMILIES = List.of(
            new FamilyGroup("cucumber", "io.cucumber", Set.of(
                    "cucumber-core", "cucumber-gherkin", "cucumber-gherkin-messages", "cucumber-plugin",
                    "datatable", "docstring", "cucumber-java", "cucumber-spring", "cucumber-junit-platform-engine")),
            new FamilyGroup("netty", "io.netty", null),
            new FamilyGroup("aws-sdk", "software.amazon.awssdk", null),
            new FamilyGroup("brave", "io.zipkin.brave", null),
            new FamilyGroup("jetty", "org.eclipse.jetty", null),
            new FamilyGroup("bytebuddy", "net.bytebuddy", null),
            new FamilyGroup("opentelemetry", "io.opentelemetry", null),
            new FamilyGroup("logback", "ch.qos.logback", null),
            // JUnit Jupiter (5.x) and Platform (1.x) are released together but on different
            // version schemes — they must be aligned within themselves, never with each other.
            new FamilyGroup("junit-jupiter", "org.junit.jupiter", null),
            new FamilyGroup("junit-platform", "org.junit.platform", null),
            // Micrometer core (1.1x.y) and tracing (1.x.y) version independently despite the
            // shared groupId, and context-propagation is independent of both.
            new FamilyGroup("micrometer-core", "io.micrometer", Set.of(
                    "micrometer-commons", "micrometer-core", "micrometer-jakarta9", "micrometer-observation",
                    "micrometer-registry-prometheus")),
            new FamilyGroup("micrometer-tracing", "io.micrometer", Set.of(
                    "micrometer-tracing", "micrometer-tracing-bridge-brave", "micrometer-tracing-bridge-otel")),
            new FamilyGroup("jackson", "com.fasterxml.jackson", null));

    /**
     * Computes planned dep-management pins for a set of findings, family-aligned. Used both by
     * {@link #runPhase2Validation} and by display-only fallback paths that recompute pins live
     * when a scan's stored {@code phase2Pins} is empty (e.g. cached data from before Phase 2 ran).
     */
    private List<String> computePlannedPins(List<TransitiveConflictFinding> findings, List<ScanComponent> components,
                                            Map<String, String> projectDeclared) {
        Map<String, String> pins = new LinkedHashMap<>();
        for (TransitiveConflictFinding f : findings) {
            String key = f.groupId() + ":" + f.artifactId();
            String winner = reconcileWithDeclared(computeWinnerVersion(f, ""), projectDeclared.get(key));
            if (winner != null && !winner.isBlank()) {
                pins.put(key, winner);
            }
        }
        alignFamilyVersions(pins, components, projectDeclared);
        return pins.entrySet().stream().map(e -> e.getKey() + ":" + e.getValue()).toList();
    }

    /**
     * Re-runs family alignment over a stored "G:A:V" pin list. Stored {@code phase2Pins} may
     * predate the family-alignment logic (or fixes to it), so the display/Apply paths must not
     * trust them verbatim — realignment converges the list to the same result a fresh computation
     * would give, and is a no-op on already-aligned pins.
     */
    private List<String> realignStoredPins(List<String> storedPins, List<ScanComponent> components,
                                           Map<String, String> projectDeclared) {
        Map<String, String> pins = new LinkedHashMap<>();
        for (String gav : storedPins) {
            int last = gav.lastIndexOf(':');
            if (last <= 0) continue;
            pins.put(gav.substring(0, last), gav.substring(last + 1));
        }
        // A stored pin for an artifact the project itself manages must be reconciled with the
        // project's declared version, same as a fresh computation would be.
        for (Map.Entry<String, String> e : pins.entrySet()) {
            e.setValue(reconcileWithDeclared(e.getValue(), projectDeclared.get(e.getKey())));
        }
        alignFamilyVersions(pins, components, projectDeclared);
        return pins.entrySet().stream().map(e -> e.getKey() + ":" + e.getValue()).toList();
    }

    /**
     * Aligns every computed pin belonging to a {@link #COORDINATED_FAMILIES} entry onto one
     * version per family. The target is the version the PROJECT itself declares for the family —
     * its own dependencyManagement entries and its direct dependencies — and that target wins
     * outright, raising or LOWERING pins to match: a transitively-observed higher version must
     * not drag the family across a release line the project deliberately avoided (e.g. a project
     * on Netty 4.1.135.Final must not have its Netty modules force-pinned to a 4.2.x observed on
     * some unrelated transitive path). Only when the project declares nothing for the family does
     * alignment fall back to raising every member to the highest version required anywhere for
     * that family (other members' pins, or any resolved component in the tree).
     */
    private void alignFamilyVersions(Map<String, String> pins, List<ScanComponent> components,
                                     Map<String, String> projectDeclared) {
        for (FamilyGroup family : COORDINATED_FAMILIES) {
            // 1) Project-declared target: own dep-management entries + direct dependencies.
            String declaredTarget = null;
            for (Map.Entry<String, String> e : projectDeclared.entrySet()) {
                String[] ga = e.getKey().split(":", 2);
                if (ga.length == 2 && family.matches(ga[0], ga[1])
                        && (declaredTarget == null || compareVersionsSemantic(e.getValue(), declaredTarget) > 0)) {
                    declaredTarget = e.getValue();
                }
            }
            for (ScanComponent c : components) {
                String g = c.coordinate().groupId(), a = c.coordinate().artifactId();
                if (c.direct() && family.matches(g, a)
                        && c.version() != null && !c.version().isBlank()
                        && !c.version().contains("${") && !c.snapshot()
                        && (declaredTarget == null || compareVersionsSemantic(c.version(), declaredTarget) > 0)) {
                    declaredTarget = c.version();
                }
            }
            if (declaredTarget != null) {
                // Computed winners may raise the family WITHIN the declared release line (e.g.
                // logback declared 1.5.25, findings require 1.5.38 → whole family to 1.5.38).
                // Winners on a different line never drag the family across it (Netty declared
                // 4.1.135 stays 4.1.135 even when 4.2.x is observed transitively).
                String target = declaredTarget;
                for (Map.Entry<String, String> e : pins.entrySet()) {
                    String[] ga = e.getKey().split(":", 2);
                    if (ga.length == 2 && family.matches(ga[0], ga[1])
                            && sameReleaseLine(e.getValue(), declaredTarget)
                            && compareVersionsSemantic(e.getValue(), target) > 0) {
                        target = e.getValue();
                    }
                }
                for (Map.Entry<String, String> e : pins.entrySet()) {
                    String[] ga = e.getKey().split(":", 2);
                    if (ga.length == 2 && family.matches(ga[0], ga[1])) {
                        e.setValue(target);
                    }
                }
                continue;
            }

            // 2) Nothing declared: raise-only alignment to the family's highest required version.
            String floor = null;
            for (Map.Entry<String, String> e : pins.entrySet()) {
                String[] ga = e.getKey().split(":", 2);
                if (ga.length == 2 && family.matches(ga[0], ga[1])
                        && (floor == null || compareVersionsSemantic(e.getValue(), floor) > 0)) {
                    floor = e.getValue();
                }
            }
            for (ScanComponent c : components) {
                String g = c.coordinate().groupId(), a = c.coordinate().artifactId();
                if (family.matches(g, a) && c.version() != null && !c.snapshot()
                        && (floor == null || compareVersionsSemantic(c.version(), floor) > 0)) {
                    floor = c.version();
                }
            }
            if (floor == null) continue;
            for (Map.Entry<String, String> e : pins.entrySet()) {
                String[] ga = e.getKey().split(":", 2);
                if (ga.length == 2 && family.matches(ga[0], ga[1]) && compareVersionsSemantic(floor, e.getValue()) > 0) {
                    e.setValue(floor);
                }
            }
        }
    }

    /**
     * Extracts the project's OWN (non-RedKite) dependencyManagement entries from the root POM as
     * a "groupId:artifactId" → version map, resolving single-level {@code ${property}} references
     * against the POM's {@code <properties>}. RedKite-tagged pins are excluded — they're RedKite's
     * previous output, not project intent. Returns an empty map if the POM can't be parsed.
     */
    private Map<String, String> projectDeclaredDepMgmt(String rootPomXml) {
        Map<String, String> declared = new LinkedHashMap<>();
        if (rootPomXml == null || rootPomXml.isBlank()) return declared;
        try {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                    .parse(new InputSource(new StringReader(rootPomXml)));
            Map<String, String> props = new LinkedHashMap<>();
            NodeList propsBlocks = doc.getElementsByTagName("properties");
            for (int i = 0; i < propsBlocks.getLength(); i++) {
                NodeList kids = propsBlocks.item(i).getChildNodes();
                for (int j = 0; j < kids.getLength(); j++) {
                    if (kids.item(j) instanceof Element p) props.put(p.getNodeName(), p.getTextContent().trim());
                }
            }
            NodeList depMgmts = doc.getElementsByTagName("dependencyManagement");
            for (int i = 0; i < depMgmts.getLength(); i++) {
                NodeList deps = ((Element) depMgmts.item(i)).getElementsByTagName("dependency");
                for (int j = 0; j < deps.getLength(); j++) {
                    Element dep = (Element) deps.item(j);
                    if (isRedkiteDepMgmtPin(dep)) continue;
                    String g = childText(dep, "groupId"), a = childText(dep, "artifactId"), v = childText(dep, "version");
                    if (g == null || a == null || v == null) continue;
                    v = v.trim();
                    if (v.startsWith("${") && v.endsWith("}")) {
                        v = props.get(v.substring(2, v.length() - 1));
                    }
                    if (v == null || v.isBlank() || v.contains("${")) continue;
                    declared.put(g.trim() + ":" + a.trim(), v);
                }
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "Could not parse root POM for declared dep-management: " + e.getMessage());
        }
        return declared;
    }

    /**
     * Reconciles a computed winner with the version the project itself declares for the same
     * artifact. The declared version is the project's deliberate choice and wins by default; the
     * computed winner overrides it only when it is a raise WITHIN the declared release line
     * (same major.minor — e.g. logback 1.5.25 declared, 1.5.38 required → 1.5.38). A computed
     * winner on a different line (Netty 4.1.135 declared, 4.2.16 observed transitively) must not
     * displace the declared version.
     */
    private String reconcileWithDeclared(String computed, String declaredVersion) {
        if (declaredVersion == null || declaredVersion.isBlank()) return computed;
        if (computed == null || computed.isBlank()) return declaredVersion;
        if (sameReleaseLine(computed, declaredVersion) && compareVersionsSemantic(computed, declaredVersion) > 0) {
            return computed;
        }
        return declaredVersion;
    }

    /** Whether two versions share a release line (equal first two version tokens, e.g. "1.5"). */
    private static boolean sameReleaseLine(String a, String b) {
        return releaseLineOf(a).equals(releaseLineOf(b));
    }

    private static String releaseLineOf(String version) {
        String[] tokens = version.split("[.\\-]");
        String major = tokens.length > 0 ? tokens[0] : "0";
        String minor = tokens.length > 1 ? tokens[1] : "0";
        return major + "." + minor;
    }

    private static String readFileQuietly(Path path) {
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    /** The root POM's XML from a stored source-POM map (keyed by relative file path). */
    private static String rootPomXml(Map<String, String> sourcePoms) {
        String content = sourcePoms.get("pom.xml");
        if (content != null) return content;
        // Fall back to the shallowest pom.xml path
        String bestKey = null;
        for (String key : sourcePoms.keySet()) {
            if (!key.endsWith("pom.xml")) continue;
            if (bestKey == null || key.length() < bestKey.length()) bestKey = key;
        }
        return bestKey != null ? sourcePoms.get(bestKey) : "";
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

    /**
     * The version RedKite recommends for a TRANSITIVE component, which deliberately does not
     * follow the same "latest compatible" logic as direct dependencies — a transitive dependency
     * was never chosen by the project, so recommending a move for it needs a concrete reason:
     * <ol>
     *   <li>An existing dependencyManagement entry (RedKite-pinned or plain project-declared)
     *       already governs this artifact — respect it as-is, whatever its version.
     *   <li>Otherwise, an active enforcer convergence conflict for this artifact — recommend the
     *       highest version already present among the conflict's resolved/conflicting versions
     *       (never a fresh "latest on Maven Central" lookup, which could cross a release line
     *       nothing in the tree actually requires).
     *   <li>Otherwise, a fixable CVE on this component — recommend the fix's target version
     *       (upgrade, downgrade, or best-effort, whichever direction the fix actually moves). A
     *       known vulnerability with a known fix is exactly the "concrete reason to move" this
     *       method otherwise withholds — unlike a bare "newer version exists" signal, it isn't
     *       optional busywork.
     *   <li>Otherwise, the current version — i.e. no upgrade is recommended at all. A transitive
     *       dependency with no conflict, no existing pin, and no CVE fix has nothing forcing it to
     *       move, so "newer version available" alone isn't reason enough to override it.
     * </ol>
     */
    private String transitiveRecommendedVersion(ComponentView view, String rootPomContent) {
        ScanComponent comp = view.component();
        String pinned = extractDepMgmtVersion(rootPomContent, comp.coordinate().groupId(), comp.coordinate().artifactId());
        if (pinned != null && !pinned.isBlank()) {
            return pinned;
        }
        TransitiveConflictFinding finding = view.convergenceFinding();
        if (finding != null) {
            String winner = finding.resolvedVersion() != null ? finding.resolvedVersion() : "";
            for (String v : finding.conflictingVersions()) {
                if (compareVersionsSemantic(v, winner) > 0) winner = v;
            }
            if (!winner.isBlank()) return winner;
        }
        if (hasFixableCve(view) && view.recommendation() != null
                && view.recommendation().targetVersion() != null && !view.recommendation().targetVersion().isBlank()) {
            return view.recommendation().targetVersion();
        }
        return comp.version();
    }

    /** Extracts the pinned version for g:a from an existing <dependencyManagement> block,
     *  resolving a ${...} property reference against this same POM's <properties> block. Returns
     *  null (rather than the raw "${propName}" text) when the entry is property-backed but the
     *  property can't be found here — callers treat this identically to "no pin exists", instead
     *  of mistaking the unresolved reference for a real version and later writing it back into
     *  the property itself, defining it as a reference to itself. */
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
                if (vs >= 0 && ve > vs) return resolvePomPropertyRef(pomXml, dep.substring(vs + 9, ve).trim());
            }
            pos = depEnd + 1;
        }
        return null;
    }

    /** If {@code value} is a {@code ${propName}} reference, resolves it against {@code pomXml}'s
     *  own <properties> block (single level, no chained/inherited resolution); returns it
     *  unchanged if it isn't a reference, or null if the property can't be found here. */
    private static String resolvePomPropertyRef(String pomXml, String value) {
        if (value == null || !value.startsWith("${") || !value.endsWith("}")) return value;
        String propName = value.substring(2, value.length() - 1);
        int psStart = pomXml.indexOf("<properties>");
        int psEnd = pomXml.indexOf("</properties>");
        if (psStart < 0 || psEnd <= psStart) return null;
        String props = pomXml.substring(psStart, psEnd);
        String openTag = "<" + propName + ">";
        String closeTag = "</" + propName + ">";
        int os = props.indexOf(openTag);
        if (os < 0) return null;
        int oe = props.indexOf(closeTag, os);
        if (oe < 0) return null;
        return props.substring(os + openTag.length(), oe).trim();
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

            // Write the modified POM, plus a refreshed pin-summary comment on every project POM.
            Map<Path, String> modified = new LinkedHashMap<>();
            modified.put(targetPom, updatedPom);
            refreshPinSummaryComments(applier, scanId, projectRoot, modified, null);
            for (Map.Entry<Path, String> entry : modified.entrySet()) {
                Files.writeString(entry.getKey(), entry.getValue(), StandardCharsets.UTF_8);
            }

            sendJson(exchange, 200, "{\"status\":\"ok\"}");
        } catch (Exception e) {
            LOGGER.warning(() -> "Remediation apply failed: " + e.getMessage());
            sendText(exchange, 500, "Apply failed: " + e.getMessage());
        }
    }

    private void handleApiRemediationApplyBatch(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) { sendText(exchange, 405, "Method not allowed"); return; }
        String body = readBody(exchange);
        String scanId = parseJsonField(body, "scanId");
        if (scanId == null) { sendText(exchange, 400, "Missing scanId"); return; }

        List<Map<String, String>> actions = parseJsonObjectArray(body, "remediationActions");
        String patchesSection = extractJsonValue(body, "pomPatches");
        Map<String, String> pomPatches = patchesSection != null ? parseJsonStringMap(patchesSection) : Map.of();

        String jobId = UUID.randomUUID().toString();
        ApplyJob job = new ApplyJob();
        applyJobs.put(jobId, job);
        sendJson(exchange, 200, "{\"jobId\":\"" + jobId + "\"}");

        try {
            ScanEntry scanEntry = store.getScan(scanId);
            Path projectRoot = Path.of(scanEntry.input().workingTreePath()).toAbsolutePath().normalize();
            Path rootPom = projectRoot.resolve("pom.xml");
            ProjectEntry project = store.getProject(scanEntry.projectId());
            List<String> validationMavenArgs = parseMavenArgs(project.validationMavenArgs());
            Map<String, String> validationEnv = parseEnvVars(project.validationEnv());

            new Thread(() -> {
                try {
                    com.redkite.maven.ValidationRunner runner = new com.redkite.maven.ValidationRunner();
                    RemediationApplier applier = new RemediationApplier();

                    // Compute the fully-patched POM set FIRST, before running any build — if it
                    // turns out identical to what's already on disk, there's nothing to validate
                    // or write, and no point spending a build cycle finding that out.
                    Map<Path, String> originals = new java.util.LinkedHashMap<>();
                    for (Map<String, String> action : actions) {
                        Path targetPom = resolveActionPomPath(projectRoot, action.get("pomFile"));
                        if (!originals.containsKey(targetPom))
                            originals.put(targetPom, Files.readString(targetPom, StandardCharsets.UTF_8));
                    }
                    for (String relPath : pomPatches.keySet()) {
                        Path target = projectRoot.resolve(relPath).normalize();
                        if (!target.startsWith(projectRoot)) continue;
                        if (!originals.containsKey(target))
                            originals.put(target, Files.exists(target) ? Files.readString(target, StandardCharsets.UTF_8) : "");
                    }

                    // Record what the original dep-management versions were (for revert reporting).
                    Map<String, String> originalDepMgmtVersions = new java.util.LinkedHashMap<>();
                    for (Map<String, String> action : actions) {
                        if (!"ADD_DEPENDENCY_MANAGEMENT".equals(action.get("actionType"))) continue;
                        String gId = action.get("groupId"), aId = action.get("artifactId");
                        if (gId == null || aId == null) continue;
                        Path targetPom = resolveActionPomPath(projectRoot, action.get("pomFile"));
                        String orig = originals.get(targetPom);
                        if (orig != null) {
                            String existing = extractDepMgmtVersion(orig, gId, aId);
                            originalDepMgmtVersions.put(gId + ":" + aId, existing);
                        }
                    }

                    // Apply each action in memory, accumulating changes per file.
                    Map<Path, String> modified = new java.util.LinkedHashMap<>(originals);
                    String reason = "Remediation applied by RedKite";
                    for (Map<String, String> action : actions) {
                        Path targetPom = resolveActionPomPath(projectRoot, action.get("pomFile"));
                        String current = modified.get(targetPom);
                        String updated;
                        if ("ADD_EXCLUSION".equals(action.get("actionType"))) {
                            String pg = action.get("parentGroupId"), pa = action.get("parentArtifactId");
                            String g = action.get("groupId"), a = action.get("artifactId");
                            if (pg == null || pa == null || g == null || a == null) continue;
                            updated = applier.applyExclusion(current, pg, pa, g, a, reason);
                        } else if ("ADD_DEPENDENCY_MANAGEMENT".equals(action.get("actionType"))) {
                            String g = action.get("groupId"), a = action.get("artifactId"), v = action.get("version");
                            if (g == null || a == null || v == null) continue;
                            updated = applier.applyDependencyManagementPin(current, g, a, v, reason);
                        } else {
                            continue;
                        }
                        modified.put(targetPom, updated);
                    }
                    for (Map.Entry<String, String> patch : pomPatches.entrySet()) {
                        Path target = projectRoot.resolve(patch.getKey()).normalize();
                        if (target.startsWith(projectRoot)) modified.put(target, patch.getValue());
                    }

                    refreshPinSummaryComments(applier, scanId, projectRoot, modified, originals);

                    boolean anyRealChange = modified.entrySet().stream()
                            .anyMatch(e -> !e.getValue().equals(originals.get(e.getKey())));
                    if (!anyRealChange) {
                        job.noChanges = true;
                        job.status = ApplyJob.Status.DONE;
                        return;
                    }

                    // --- PRE-VALIDATE ---
                    // Non-blocking: a failing baseline means we may be Applying changes to a broken project,
                    // which is a valid use case. We record the result and continue; post-validate is the
                    // authoritative gate.
                    job.phase = ApplyJob.Phase.PRE_VALIDATE;
                    com.redkite.maven.ValidationRunner.ValidationResult pre =
                            runner.validateWithStartup(projectRoot, rootPom, 180, validationMavenArgs, validationEnv);
                    job.baselinePassed = pre.passed();
                    if (!pre.passed()) {
                        LOGGER.info(() -> "Pre-apply validation failed (baseline broken) — continuing with apply: " + pre.failureSignature());
                    }

                    // --- APPLYING ---
                    job.phase = ApplyJob.Phase.APPLYING;

                    // Write all changes to disk.
                    for (Map.Entry<Path, String> entry : modified.entrySet()) {
                        Files.writeString(entry.getKey(), entry.getValue(), StandardCharsets.UTF_8);
                    }

                    // --- POST-VALIDATE ---
                    job.phase = ApplyJob.Phase.POST_VALIDATE;
                    com.redkite.maven.ValidationRunner.ValidationResult post =
                            runner.validateWithStartup(projectRoot, rootPom, 180, validationMavenArgs, validationEnv);
                    if (!post.passed()) {
                        // Restore originals.
                        for (Map.Entry<Path, String> entry : originals.entrySet()) {
                            Files.writeString(entry.getKey(), entry.getValue(), StandardCharsets.UTF_8);
                        }
                        // Only attribute to our changes if the baseline was passing before we applied them.
                        String attr = job.baselinePassed
                                ? com.redkite.maven.ValidationRunner.attributeFailure(post.rawOutput())
                                : null;
                        String failedVer = null, revertedVer = null;
                        if (attr != null) {
                            for (Map<String, String> action : actions) {
                                String g = action.get("groupId"), a = action.get("artifactId");
                                if (g != null && a != null && (g + ":" + a).equals(attr)) {
                                    failedVer = action.get("version");
                                    revertedVer = originalDepMgmtVersions.get(attr);
                                    break;
                                }
                            }
                        }
                        job.attribution = attr;
                        job.failedVersion = failedVer;
                        job.revertedVersion = revertedVer;
                        String baselineNote = job.baselinePassed ? "" : " (project was already failing before changes)";
                        job.failureMessage = "Post-apply validation failed (" + post.phase() + ")" + baselineNote + ": " + post.failureSignature();
                        job.failureSignature = post.failureSignature();
                        job.status = ApplyJob.Status.FAILED;
                        return;
                    }

                    job.status = ApplyJob.Status.DONE;
                } catch (Throwable e) {
                    job.failureMessage = causeChain(e);
                    job.status = ApplyJob.Status.ERROR;
                }
            }, "redkite-apply-" + jobId).start();
        } catch (Exception e) {
            applyJobs.remove(jobId);
            LOGGER.warning(() -> "Failed to start apply job: " + e.getMessage());
            sendText(exchange, 500, "Failed to start apply: " + e.getMessage());
        }
    }

    /**
     * Resolves a batch of user selections ("change this coordinate to this version") into
     * {@link CandidateUpdate}s — collapsing selections that share a control set into one proposed
     * edit, per {@link CandidateUpdateResolver}. Read-only: computes candidates from the already-
     * loaded scan data, touches no POM file. Distinct from {@code apply-batch}, which assumes the
     * edits are already fully decided.
     */
    private void handleApiRemediationResolve(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) { sendText(exchange, 405, "Method not allowed"); return; }
        String body = readBody(exchange);
        String scanId = parseJsonField(body, "scanId");
        if (scanId == null) { sendText(exchange, 400, "Missing scanId"); return; }
        List<Map<String, String>> selections = parseJsonObjectArray(body, "selections");
        if (selections.isEmpty()) { sendText(exchange, 400, "Missing selections"); return; }

        try {
            ScanEntry scan = store.getScan(scanId);
            List<ScanComponent> components = scan.report().components();
            Map<Long, ScanComponent> byId = new LinkedHashMap<>();
            for (ScanComponent c : components) byId.put(c.id(), c);

            Map<ComponentCoordinate, String> selectedTargets = new LinkedHashMap<>();
            for (Map<String, String> selection : selections) {
                String idStr = selection.get("componentId");
                String targetVersion = selection.get("targetVersion");
                if (idStr == null || targetVersion == null) continue;
                try {
                    ScanComponent c = byId.get(Long.parseLong(idStr));
                    if (c != null) selectedTargets.put(c.coordinate(), targetVersion);
                } catch (NumberFormatException ignored) {}
            }
            if (selectedTargets.isEmpty()) { sendText(exchange, 400, "No valid selections"); return; }

            Map<ComponentCoordinate, List<DependencyFinding>> findingsByCoordinate =
                    findingsByCoordinate(scan.report(), selectedTargets.keySet());
            Set<ComponentCoordinate> pinnedCoordinates = userPinnedCoordinates(scanId);

            List<CandidateUpdate> candidates = CandidateUpdateResolver.resolve(
                    components, selectedTargets, findingsByCoordinate, pinnedCoordinates);

            StringBuilder json = new StringBuilder("[");
            for (int i = 0; i < candidates.size(); i++) {
                if (i > 0) json.append(",");
                json.append(candidateUpdateJson(candidates.get(i)));
            }
            json.append("]");
            sendJson(exchange, 200, json.toString());
        } catch (Exception e) {
            LOGGER.warning(() -> "Remediation resolve failed: " + e.getMessage());
            sendText(exchange, 500, "Resolve failed: " + e.getMessage());
        }
    }

    /**
     * Builds an {@link UpdatePlan} for one component — alternative strategies (the natural fix, a
     * local-override-only alternative, pin/ignore) for a caller to compare, per
     * {@link UpdatePlanBuilder}. Read-only, same as {@code resolve}.
     */
    private void handleApiRemediationPlan(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) { sendText(exchange, 405, "Method not allowed"); return; }
        // parseJsonField only extracts quoted-string values; componentId is naturally a JSON
        // number, so this uses parseJsonObject (handles both quoted and bare-numeric values) like
        // handleApiRemediationApply already does, rather than silently misparsing a number here.
        Map<String, String> params = parseJsonObject(readBody(exchange));
        String scanId = params.get("scanId");
        String componentIdStr = params.get("componentId");
        String targetVersion = params.get("targetVersion");
        if (scanId == null || componentIdStr == null || targetVersion == null) {
            sendText(exchange, 400, "Missing scanId/componentId/targetVersion");
            return;
        }

        try {
            long componentId = Long.parseLong(componentIdStr);
            ScanEntry scan = store.getScan(scanId);
            List<ScanComponent> components = scan.report().components();
            ScanComponent target = components.stream().filter(c -> c.id() == componentId).findFirst().orElse(null);
            if (target == null) { sendText(exchange, 404, "Component not found"); return; }

            List<DependencyFinding> findings = findingsByCoordinate(scan.report(), Set.of(target.coordinate()))
                    .getOrDefault(target.coordinate(), List.of());
            Set<ComponentCoordinate> pinnedCoordinates = userPinnedCoordinates(scanId);

            UpdatePlan plan = UpdatePlanBuilder.buildForCoordinate(
                    components, target.coordinate(), targetVersion, findings, pinnedCoordinates);

            StringBuilder json = new StringBuilder("{\"findingsAddressed\":[");
            List<DependencyFinding> planFindings = plan.findingsAddressed();
            for (int i = 0; i < planFindings.size(); i++) {
                if (i > 0) json.append(",");
                json.append(findingJson(planFindings.get(i)));
            }
            json.append("],\"candidates\":[");
            List<CandidateUpdate> candidates = plan.candidates();
            for (int i = 0; i < candidates.size(); i++) {
                if (i > 0) json.append(",");
                json.append(candidateUpdateJson(candidates.get(i)));
            }
            json.append("]}");
            sendJson(exchange, 200, json.toString());
        } catch (NumberFormatException e) {
            sendText(exchange, 400, "Invalid componentId");
        } catch (Exception e) {
            LOGGER.warning(() -> "Remediation plan failed: " + e.getMessage());
            sendText(exchange, 500, "Plan failed: " + e.getMessage());
        }
    }

    /** Vulnerability findings for the given coordinates, translated into the newer
     *  {@link DependencyFinding} shape — the real cross-reference against existing CVE data that
     *  {@link CandidateUpdate}'s class-level javadoc notes isn't wired up for CVEs-fixed/introduced
     *  yet; this is the narrower "what finding(s) justify this selection" case, not that broader one. */
    private static Map<ComponentCoordinate, List<DependencyFinding>> findingsByCoordinate(
            ScanReport report, Set<ComponentCoordinate> coordinates) {
        Map<ComponentCoordinate, List<DependencyFinding>> result = new LinkedHashMap<>();
        for (VulnerabilityFinding vf : report.vulnerabilityFindings()) {
            if (vf.coordinate() == null || !coordinates.contains(vf.coordinate())) continue;
            long componentId = -1L;
            for (ScanComponent c : report.components()) {
                if (c.coordinate().equals(vf.coordinate()) && c.version().equals(vf.affectedVersion())) {
                    componentId = c.id();
                    break;
                }
            }
            String description = vf.cves() != null && !vf.cves().isEmpty() ? String.join(", ", vf.cves()) : vf.advisoryId();
            result.computeIfAbsent(vf.coordinate(), k -> new ArrayList<>())
                    .add(new DependencyFinding(componentId, DependencyFindingReason.CVE, description, AdvisoryClassifier.severity(vf)));
        }
        return result;
    }

    /** User-pinned coordinates across every source POM in this scan, as {@link ComponentCoordinate}s
     *  — the same data {@code pinnedCoords} elsewhere derives as raw "g:a" strings, but
     *  {@link CandidateUpdateResolver}/{@link UpdatePlanBuilder} need the typed form. */
    private Set<ComponentCoordinate> userPinnedCoordinates(String scanId) {
        Set<ComponentCoordinate> result = new LinkedHashSet<>();
        RemediationApplier applier = new RemediationApplier();
        for (String pomContent : store.loadSourcePoms(scanId).values()) {
            try {
                for (String coordStr : applier.findUserPinnedCoordinates(pomContent)) {
                    int idx = coordStr.indexOf(':');
                    if (idx > 0) result.add(new ComponentCoordinate(coordStr.substring(0, idx), coordStr.substring(idx + 1)));
                }
            } catch (Exception ignored) {}
        }
        return result;
    }

    private static String candidateUpdateJson(CandidateUpdate c) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"action\":").append(jsonStr(c.action().name())).append(",");
        sb.append("\"editableDeclaration\":").append(jsonStr(c.editableDeclaration())).append(",");
        sb.append("\"oldValue\":").append(jsonStr(c.oldValue())).append(",");
        sb.append("\"proposedValue\":").append(jsonStr(c.proposedValue())).append(",");
        sb.append("\"reason\":").append(jsonStr(c.reason())).append(",");
        sb.append("\"findingsAddressed\":[");
        for (int i = 0; i < c.findingsAddressed().size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(findingJson(c.findingsAddressed().get(i)));
        }
        sb.append("],");
        sb.append("\"resultingChanges\":").append(changeSetJson(c.resultingChanges())).append(",");
        sb.append("\"confidence\":").append(jsonStr(c.confidence().name())).append(",");
        sb.append("\"autoApplySafe\":").append(c.autoApplySafe()).append(",");
        sb.append("\"conflictsWithUserPin\":").append(c.conflictsWithUserPin()).append(",");
        sb.append("\"introducesDowngrade\":").append(c.introducesDowngrade()).append(",");
        sb.append("\"overridesPlatform\":").append(c.overridesPlatform());
        sb.append("}");
        return sb.toString();
    }

    private static String changeSetJson(ProposedChangeSet changeSet) {
        StringBuilder sb = new StringBuilder("{\"movements\":[");
        List<ProposedChangeSet.DependencyMovement> movements = changeSet.movements();
        for (int i = 0; i < movements.size(); i++) {
            if (i > 0) sb.append(",");
            ProposedChangeSet.DependencyMovement m = movements.get(i);
            sb.append("{\"groupId\":").append(jsonStr(m.coordinate().groupId()))
                    .append(",\"artifactId\":").append(jsonStr(m.coordinate().artifactId()))
                    .append(",\"fromVersion\":").append(jsonStr(m.fromVersion()))
                    .append(",\"toVersion\":").append(jsonStr(m.toVersion()))
                    .append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String findingJson(DependencyFinding f) {
        return "{\"componentId\":" + f.componentId()
                + ",\"reason\":" + jsonStr(f.reason().name())
                + ",\"description\":" + jsonStr(f.description())
                + ",\"severity\":" + (f.severity() != null ? jsonStr(f.severity().name()) : "null")
                + "}";
    }

    private void handleApiRemediationApplyStatus(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) { sendText(exchange, 405, "Method not allowed"); return; }
        String jobId = queryParam(exchange.getRequestURI().getQuery(), "jobId");
        if (jobId == null) { sendText(exchange, 400, "Missing jobId"); return; }
        ApplyJob job = applyJobs.get(jobId);
        if (job == null) { sendText(exchange, 404, "Job not found"); return; }
        switch (job.status) {
            case RUNNING -> {
                String phase = switch (job.phase) {
                    case PRE_VALIDATE -> "pre-validate";
                    case APPLYING -> "applying";
                    case POST_VALIDATE -> "post-validate";
                };
                sendJson(exchange, 200, "{\"status\":\"running\",\"phase\":" + jsonStr(phase) + "}");
            }
            case DONE -> {
                boolean baselinePassed = job.baselinePassed;
                boolean noChanges = job.noChanges;
                applyJobs.remove(jobId);
                sendJson(exchange, 200, "{\"status\":\"done\",\"baselinePassed\":" + baselinePassed + ",\"noChanges\":" + noChanges + "}");
            }
            case FAILED -> {
                applyJobs.remove(jobId);
                StringBuilder sb = new StringBuilder("{\"status\":\"failed\"");
                sb.append(",\"message\":").append(jsonStr(job.failureMessage));
                sb.append(",\"failureSignature\":").append(jsonStr(job.failureSignature));
                if (job.attribution != null) sb.append(",\"attribution\":").append(jsonStr(job.attribution));
                if (job.failedVersion != null) sb.append(",\"failedVersion\":").append(jsonStr(job.failedVersion));
                if (job.revertedVersion != null) sb.append(",\"revertedVersion\":").append(jsonStr(job.revertedVersion));
                sb.append("}");
                sendJson(exchange, 200, sb.toString());
            }
            case ERROR -> {
                applyJobs.remove(jobId);
                sendJson(exchange, 200, "{\"status\":\"error\",\"message\":" + jsonStr(job.failureMessage) + "}");
            }
        }
    }

    private static Path resolveActionPomPath(Path projectRoot, String pomFile) {
        if (pomFile != null && !pomFile.isBlank()) {
            Path p = Path.of(pomFile);
            if (p.isAbsolute()) return p;
            return projectRoot.resolve(p).normalize();
        }
        return projectRoot.resolve("pom.xml");
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

    private void handleConfig(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        Map<String, String> values;
        try {
            values = store.loadConfigValues();
        } catch (SQLException e) {
            sendText(exchange, 500, BRAND + " error: " + escape(e.getMessage()));
            return;
        }
        StringBuilder body = new StringBuilder();
        body.append("<section class=\"card\">");
        body.append("<h2>About</h2>");
        body.append("<p class=\"muted\">").append(escape(BRAND)).append(" version ").append(escape(VERSION)).append("</p>");
        body.append("</section>");
        body.append("<section class=\"card\">");
        body.append("<h2>Cache TTLs</h2>");
        body.append("<p class=\"muted\">How long metadata lookups are cached before being refreshed. ")
                .append("Changes apply to the next lookup — no restart needed.</p>");
        body.append("<form method=\"POST\" action=\"/api/config\">");
        for (ConfigTtlEntry entry : CONFIG_TTL_ENTRIES) {
            String current = values.getOrDefault(entry.key(), Long.toString(entry.defaultValue().toMinutes()));
            body.append("<div class=\"config-row\">");
            body.append("<label for=\"").append(escape(entry.key())).append("\">").append(escape(entry.label())).append("</label>");
            body.append("<div class=\"config-row-input\">");
            body.append("<select id=\"").append(escape(entry.key())).append("\" name=\"").append(escape(entry.key())).append("\">");
            boolean matched = false;
            for (Map.Entry<Long, String> option : CONFIG_TTL_OPTIONS) {
                boolean selected = String.valueOf(option.getKey()).equals(current);
                if (selected) matched = true;
                body.append("<option value=\"").append(option.getKey()).append("\"").append(selected ? " selected" : "")
                        .append(">").append(escape(option.getValue())).append("</option>");
            }
            if (!matched) {
                // A previously-set value that isn't one of the presets (e.g. from before the
                // dropdown existed) — keep it selectable rather than silently changing it to the
                // nearest preset the moment this page loads.
                body.append("<option value=\"").append(escape(current)).append("\" selected>")
                        .append(escape(current)).append(" minutes (custom)</option>");
            }
            body.append("</select>");
            body.append("</div></div>");
        }
        body.append("<button class=\"button primary\" type=\"submit\">Save</button>");
        body.append("</form>");
        body.append("</section>");
        sendHtml(exchange, 200, renderPage("config", "Configuration", "Cache TTL settings", body.toString()));
    }

    private void handleApiConfig(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        Map<String, String> form = parseForm(readBody(exchange));
        Set<String> validKeys = CONFIG_TTL_ENTRIES.stream().map(ConfigTtlEntry::key).collect(Collectors.toSet());
        try {
            for (Map.Entry<String, String> field : form.entrySet()) {
                if (!validKeys.contains(field.getKey())) continue;
                long minutes;
                try {
                    minutes = Long.parseLong(field.getValue().trim());
                } catch (NumberFormatException e) {
                    continue; // skip invalid entries rather than fail the whole save
                }
                if (minutes < 1) continue;
                store.updateConfigValue(field.getKey(), Long.toString(minutes));
            }
        } catch (SQLException e) {
            sendText(exchange, 500, BRAND + " error: " + escape(e.getMessage()));
            return;
        }
        sendRedirect(exchange, "/config");
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
        if (parts.length == 5 && "validation".equals(parts[4]) && "POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            String projectId = parts[3];
            Map<String, String> form = parseForm(readBody(exchange));
            store.updateValidationSettings(projectId,
                    form.getOrDefault("mavenArgs", "").trim(),
                    form.getOrDefault("env", "").trim());
            sendRedirect(exchange, "/projects/" + projectId);
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
            // "pinned"/"unpinned" are pseudo-fields carrying comma-separated component IDs whose
            // Pin checkbox state changed this apply — pulled out before the rest is treated as
            // plain compId=version pairs.
            Set<Long> pinnedIds = parseIdList(updates.remove("pinned"));
            Set<Long> unpinnedIds = parseIdList(updates.remove("unpinned"));
            if (updates.isEmpty() && pinnedIds.isEmpty() && unpinnedIds.isEmpty()) { sendText(exchange, 400, "No updates"); return; }
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
                        scan.report(), sourcePoms, scan.input().workingTreePath(), updates, conflictsByKey,
                        pinnedIds, unpinnedIds);
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
        return generatePomPatches(report, sourcePoms, workingTreePath, rawUpdates, conflictsByKey, Set.of(), Set.of());
    }

    private Map<String, String> generatePomPatches(ScanReport report, Map<String, String> sourcePoms, String workingTreePath, Map<String, String> rawUpdates, Map<String, List<TransitiveConflictFinding>> conflictsByKey, Set<Long> pinnedIds, Set<Long> unpinnedIds) throws Exception {
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

        Set<String> pinnedCoords = new LinkedHashSet<>();
        for (Long id : pinnedIds) {
            ScanComponent c = componentsById.get(id);
            if (c != null) pinnedCoords.add(c.coordinate().groupId() + ":" + c.coordinate().artifactId());
        }
        Set<String> unpinnedCoords = new LinkedHashSet<>();
        for (Long id : unpinnedIds) {
            ScanComponent c = componentsById.get(id);
            if (c != null) unpinnedCoords.add(c.coordinate().groupId() + ":" + c.coordinate().artifactId());
        }

        // Direct dependency upgrades stay property-backed through the normal version patch flow.
        // Only transitive convergence fixes should introduce dependencyManagement pins.
        Map<String, List<ScanComponent>> directByFile = new LinkedHashMap<>();
        Map<String, String> allDirectUpdates = new LinkedHashMap<>();
        for (ScanComponent c : report.components()) {
            if (!c.direct() || c.snapshot() || c.sourceFilePath() == null) continue;
            if (!updateById.containsKey(c.id()) && !pinnedIds.contains(c.id()) && !unpinnedIds.contains(c.id())) continue;
            directByFile.computeIfAbsent(c.sourceFilePath(), k -> new ArrayList<>()).add(c);
            String coord = c.coordinate().groupId() + ":" + c.coordinate().artifactId();
            // A newly-pinned component with no explicit version change still needs a concrete
            // version carried through to patchPomXml — if it's currently BOM-managed (no
            // <version> element anywhere), the pin marker can't attach to anything without one
            // being written first, and this is the value it should be written as.
            if (updateById.containsKey(c.id())) allDirectUpdates.put(coord, updateById.get(c.id()));
            else if (pinnedIds.contains(c.id()) && c.version() != null) allDirectUpdates.put(coord, c.version());
        }
        for (Map.Entry<String, List<ScanComponent>> entry : directByFile.entrySet()) {
            String content = sourcePoms.get(entry.getKey());
            if (content == null) continue;
            Map<String, String> fileUpdates = new LinkedHashMap<>();
            for (ScanComponent c : entry.getValue()) {
                String coord = c.coordinate().groupId() + ":" + c.coordinate().artifactId();
                if (updateById.containsKey(c.id())) fileUpdates.put(coord, updateById.get(c.id()));
                else if (pinnedIds.contains(c.id()) && c.version() != null) fileUpdates.put(coord, c.version());
            }
            result.put(entry.getKey(), patchPomXml(content, fileUpdates, pinnedCoords, unpinnedCoords));
        }

        // Sync the root POM's declared version properties to match any direct dep upgrades so
        // project-owned version declarations stay aligned across modules.
        RemediationApplier applier = new RemediationApplier();
        String rootPomKey = selectRootPomKey(sourcePoms, workingTreePath);
        if (rootPomKey != null && (!allDirectUpdates.isEmpty() || !pinnedCoords.isEmpty() || !unpinnedCoords.isEmpty())) {
            String rootContent = result.containsKey(rootPomKey) ? result.get(rootPomKey) : sourcePoms.get(rootPomKey);
            if (rootContent != null) {
                String updated = patchPomXml(rootContent, allDirectUpdates, pinnedCoords, unpinnedCoords);
                if (!updated.equals(rootContent)) {
                    result.put(rootPomKey, updated);
                }
            }
        }

        // Transitive convergence selections are translated into dependencyManagement pins
        // plus exclusions on the parents introducing the non-selected versions. Pin toggles with
        // no version change are handled here too, so a user can pin/unpin a transitive component
        // without altering its resolved version.
        for (ScanComponent component : report.components()) {
            if (component.direct() || component.snapshot()) continue;
            long id = component.id();
            boolean isPinned = pinnedIds.contains(id);
            boolean isUnpinned = unpinnedIds.contains(id);
            String requestedVersion = updateById.get(id);
            boolean versionChanged = requestedVersion != null && !requestedVersion.isBlank()
                    && !requestedVersion.equals(component.version());
            if (!versionChanged && !isPinned && !isUnpinned) {
                continue;
            }
            String selectedVersion = versionChanged ? requestedVersion : component.version();
            boolean changed = false;
            TransitiveConflictFinding finding = findMatchingConflict(conflictsByKey, component);

            if (rootPomKey != null) {
                String content = result.containsKey(rootPomKey) ? result.get(rootPomKey) : sourcePoms.get(rootPomKey);
                if (content != null) {
                    String updated;
                    String g = component.coordinate().groupId(), a = component.coordinate().artifactId();
                    if (isUnpinned) {
                        // Plain "uncheck Pin": removeUserPin deliberately keeps the <dependency>
                        // (just unprotected).
                        updated = applier.removeUserPin(content, g, a);
                        if (versionChanged) {
                            updated = applier.applyDependencyManagementPin(
                                    updated, g, a, selectedVersion, "Enforcer dependency convergence fix by RedKite");
                        }
                    } else if (isPinned) {
                        updated = applier.applyDependencyManagementPin(
                                content, g, a, selectedVersion, "User pinned via RedKite", RemediationApplier.PinKind.USER);
                    } else {
                        updated = applier.applyDependencyManagementPin(
                                content, g, a, selectedVersion,
                                "Enforcer dependency convergence fix by RedKite", RemediationApplier.PinKind.COMPUTED);
                    }
                    if (!updated.equals(content)) {
                        result.put(rootPomKey, updated);
                        changed = true;
                    }
                }
            }
            if (!versionChanged) {
                continue;
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

    /**
     * Refreshes the {@code redkite:pin-summary} comment across every project POM this apply
     * touches or coexists with, so pin counts stay accurate project-wide even when this
     * particular apply only changed a different module. Mutates {@code modified} in place —
     * files whose only change is the summary comment are added to it (and to {@code originals},
     * when non-null, so a post-validate revert restores them too).
     *
     * <p>Files not already in {@code modified} are read live from disk rather than from the
     * scan's stored source POMs, which are a scan-time snapshot and may be stale relative to
     * changes a prior apply already wrote.
     */
    private void refreshPinSummaryComments(RemediationApplier applier, String scanId, Path projectRoot,
                                           Map<Path, String> modified, Map<Path, String> originals) {
        Map<String, String> sourcePomPaths = store.loadSourcePoms(scanId);
        String rootPomKey = selectRootPomKey(sourcePomPaths, projectRoot.toString());
        if (rootPomKey == null) return;

        Map<String, Path> pathByRelPath = new LinkedHashMap<>();
        for (String relPath : sourcePomPaths.keySet()) {
            pathByRelPath.put(relPath, projectRoot.resolve(relPath).normalize());
        }
        for (Path p : modified.keySet()) {
            String relPath = projectRoot.relativize(p).toString().replace('\\', '/');
            pathByRelPath.putIfAbsent(relPath, p);
        }

        Map<String, String> finalByRelPath = new LinkedHashMap<>();
        for (Map.Entry<String, Path> e : pathByRelPath.entrySet()) {
            Path path = e.getValue();
            String content = modified.containsKey(path) ? modified.get(path) : readIfExists(path);
            if (content != null) finalByRelPath.put(e.getKey(), content);
        }

        boolean multiFile = finalByRelPath.size() > 1;
        Map<String, RemediationApplier.PinCounts> perFileCounts = new LinkedHashMap<>();
        int projectTotal = 0, projectUserPinned = 0;
        for (Map.Entry<String, String> e : finalByRelPath.entrySet()) {
            RemediationApplier.PinCounts c = applier.countPins(e.getValue());
            perFileCounts.put(e.getKey(), c);
            projectTotal += c.total();
            projectUserPinned += c.userPinned();
        }
        RemediationApplier.PinCounts projectCounts = new RemediationApplier.PinCounts(projectTotal, projectUserPinned);

        for (Map.Entry<String, String> e : finalByRelPath.entrySet()) {
            String relPath = e.getKey();
            Path path = pathByRelPath.get(relPath);
            boolean isRoot = relPath.equals(rootPomKey);
            String withSummary = applier.applyPinSummaryComment(e.getValue(),
                    perFileCounts.get(relPath), isRoot && multiFile ? projectCounts : null);
            if (!withSummary.equals(e.getValue())) {
                if (originals != null) originals.putIfAbsent(path, e.getValue());
                modified.put(path, withSummary);
            }
        }
    }

    private static String readIfExists(Path path) {
        try {
            return Files.exists(path) ? Files.readString(path, StandardCharsets.UTF_8) : null;
        } catch (IOException e) {
            return null;
        }
    }

    /** Comment tag marking a Maven property (or dependencyManagement entry) as user-pinned —
     *  shared convention with {@link com.redkite.maven.RemediationApplier}'s {@code redkite:user-pin}. */
    private static final String USER_PIN_TAG = "redkite:user-pin";
    private static final String USER_PIN_NOTE = "user pinned — uncheck Pin in RedKite to let it manage this dependency again";

    private static String patchPomXml(String content, Map<String, String> versionUpdates) throws Exception {
        return patchPomXml(content, versionUpdates, Set.of(), Set.of());
    }

    private static String patchPomXml(String content, Map<String, String> versionUpdates,
                                      Set<String> pinnedCoords, Set<String> unpinnedCoords) throws Exception {
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(content)));
        Element root = doc.getDocumentElement();

        // Collect <parent>, <dependency>, and <plugin> elements to patch — excluding RedKite's own
        // dependencyManagement pins, which always keep a hardcoded <version> by design (a pin is
        // meant to be a single, self-contained, independently removable override; normalising it
        // to a ${...} property here would entangle it with the project's own versioning scheme
        // and defeat "remove this comment to stop RedKite managing it").
        NodeList allElements = doc.getElementsByTagName("*");
        List<Element> patchTargets = new ArrayList<>();
        for (int i = 0; i < allElements.getLength(); i++) {
            Node n = allElements.item(i);
            if (n instanceof Element e && ("parent".equals(e.getNodeName()) || "dependency".equals(e.getNodeName()) || "plugin".equals(e.getNodeName()))) {
                if (isRedkiteDepMgmtPin(e)) continue;
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
                // BOM-managed: add explicit <version> only when upgrading (or when pinning, since
                // a pin needs a concrete version to attach its marker to).
                if (upgrade != null) {
                    Element versionEl = doc.createElement("version");
                    if (pinnedCoords.contains(coord) || unpinnedCoords.contains(coord)) {
                        // Route through the same property-backed convention as every other pin,
                        // rather than leaving a bare literal <version> with nothing to mark.
                        String propName = assignPropName(a, g, propNameForCoord);
                        propNameForCoord.put(coord, propName);
                        Element propertiesEl = findOrCreateProperties(doc, root);
                        setProperty(doc, propertiesEl, propName, upgrade);
                        versionEl.setTextContent("${" + propName + "}");
                        markPropertyPin(doc, propertiesEl, propName, upgrade, pinnedCoords.contains(coord));
                    } else {
                        versionEl.setTextContent(upgrade);
                    }
                    dep.appendChild(versionEl);
                }
                continue;
            }

            String versionText = versionNode.getTextContent().trim();
            if (versionText.isEmpty()) continue;

            if ("parent".equals(dep.getNodeName())) {
                // <parent> versions always stay literal, upgrade or not — even when the parent
                // is already declared through a ${...} reference. Maven resolves the parent's
                // coordinates before it processes <properties> (properties can themselves be
                // inherited from that same parent), so a ${...} reference here is never
                // interpolated. Falling through to the property branch below would write the
                // "upgrade" value into the referenced property instead: harmless when it's a
                // real version, but when the parent's current version couldn't be resolved (e.g.
                // an inherited property this POM doesn't itself declare) "upgrade" is that same
                // unresolved "${propName}" text, and the property ends up defined as a reference
                // to itself.
                if (upgrade != null) versionNode.setTextContent(upgrade);
            } else if (versionText.startsWith("${") && versionText.endsWith("}")) {
                // Existing property reference: update the property value when upgrading.
                // If two deps share the same property ref but target different versions,
                // give the second dep its own independent property rather than silently
                // overwriting the shared one.
                String propName = versionText.substring(2, versionText.length() - 1);
                String effectivePropName = propName;
                if (upgrade != null) {
                    String alreadySetTo = propUpgradeTo.get(propName);
                    if (alreadySetTo != null && !alreadySetTo.equals(upgrade)) {
                        // Conflict: create an independent property for this dep
                        String newPropName = assignPropName(a, g, propNameForCoord);
                        propNameForCoord.put(coord, newPropName);
                        setProperty(doc, findOrCreateProperties(doc, root), newPropName, upgrade);
                        versionNode.setTextContent("${" + newPropName + "}");
                        propUpgradeTo.put(newPropName, upgrade);
                        effectivePropName = newPropName;
                    } else {
                        setProperty(doc, findOrCreateProperties(doc, root), propName, upgrade);
                        propUpgradeTo.put(propName, upgrade);
                    }
                }
                if (pinnedCoords.contains(coord) || unpinnedCoords.contains(coord)) {
                    Element propertiesEl = findOrCreateProperties(doc, root);
                    NodeList existingProp = propertiesEl.getElementsByTagName(effectivePropName);
                    String effectiveVersion = upgrade != null ? upgrade
                            : existingProp.getLength() > 0 ? existingProp.item(0).getTextContent().trim() : versionText;
                    markPropertyPin(doc, propertiesEl, effectivePropName, effectiveVersion, pinnedCoords.contains(coord));
                }
            } else {
                // Literal version: normalise to a property reference.
                // Use the upgrade version if selected, otherwise keep the current version.
                String effectiveVersion = upgrade != null ? upgrade : versionText;
                String propName = propNameForCoord.get(coord);
                if (propName == null) {
                    propName = assignPropName(a, g, propNameForCoord);
                    propNameForCoord.put(coord, propName);
                }
                Element propertiesEl = findOrCreateProperties(doc, root);
                setProperty(doc, propertiesEl, propName, effectiveVersion);
                versionNode.setTextContent("${" + propName + "}");
                if (pinnedCoords.contains(coord) || unpinnedCoords.contains(coord)) {
                    markPropertyPin(doc, propertiesEl, propName, effectiveVersion, pinnedCoords.contains(coord));
                }
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

    /** Whether this &lt;dependency&gt; element is immediately preceded (ignoring whitespace) by a
     *  RedKite dependency-management-pin marker comment. Matched by substring rather than the
     *  full current tag text, so it still recognizes pins written by older RedKite versions that
     *  used the marker before it was renamed to include " pin". */
    private static boolean isRedkiteDepMgmtPin(Element dep) {
        Node sibling = dep.getPreviousSibling();
        while (sibling != null && sibling.getNodeType() == Node.TEXT_NODE && sibling.getTextContent().isBlank()) {
            sibling = sibling.getPreviousSibling();
        }
        return sibling != null && sibling.getNodeType() == Node.COMMENT_NODE
                && sibling.getTextContent() != null
                && (sibling.getTextContent().contains("redkite:dependency-management")
                    || sibling.getTextContent().contains(USER_PIN_TAG));
    }

    /** Adds, updates, or removes the {@code redkite:user-pin} marker comment immediately
     *  preceding a {@code <properties>} entry, mirroring RemediationApplier's convention. */
    private static void markPropertyPin(Document doc, Element propertiesEl, String propName, String version, boolean pinned) {
        NodeList existingProp = propertiesEl.getElementsByTagName(propName);
        if (existingProp.getLength() == 0) return;
        Element property = (Element) existingProp.item(0);
        Node prev = property.getPreviousSibling();
        while (prev != null && prev.getNodeType() == Node.TEXT_NODE && prev.getTextContent().isBlank()) {
            prev = prev.getPreviousSibling();
        }
        Comment existing = (prev != null && prev.getNodeType() == Node.COMMENT_NODE
                && prev.getTextContent() != null && prev.getTextContent().strip().startsWith(USER_PIN_TAG))
                ? (Comment) prev : null;
        if (!pinned) {
            if (existing != null) existing.getParentNode().removeChild(existing);
            return;
        }
        String data = " " + USER_PIN_TAG + " version=\"" + version + "\" — " + USER_PIN_NOTE + " ";
        if (existing != null) {
            existing.setData(data);
        } else {
            propertiesEl.insertBefore(doc.createComment(data), property);
        }
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

    private static void sendRedirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(303, -1);
        exchange.getResponseBody().close();
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
    private static String extractJsonValue(String json, String key) {
        if (json == null) return null;
        int keyIdx = json.indexOf("\"" + key + "\"");
        if (keyIdx < 0) return null;
        int colon = json.indexOf(':', keyIdx + key.length() + 2);
        if (colon < 0) return null;
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (start >= json.length()) return null;
        char opening = json.charAt(start);
        if (opening == '{') return extractBalanced(json, start, '{', '}');
        if (opening == '[') return extractBalanced(json, start, '[', ']');
        return null;
    }

    private static String extractBalanced(String json, int start, char open, char close) {
        int depth = 0;
        boolean inString = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') { i++; continue; }
                if (c == '"') inString = false;
            } else {
                if (c == '"') inString = true;
                else if (c == open) depth++;
                else if (c == close) { if (--depth == 0) return json.substring(start, i + 1); }
            }
        }
        return null;
    }

    private static List<Map<String, String>> parseJsonObjectArray(String json, String key) {
        String array = extractJsonValue(json, key);
        if (array == null || array.length() < 2) return List.of();
        List<Map<String, String>> result = new java.util.ArrayList<>();
        int depth = 0;
        int objStart = -1;
        boolean inString = false;
        for (int i = 0; i < array.length(); i++) {
            char c = array.charAt(i);
            if (inString) {
                if (c == '\\') { i++; continue; }
                if (c == '"') inString = false;
            } else {
                if (c == '"') inString = true;
                else if (c == '{') { if (depth++ == 0) objStart = i; }
                else if (c == '}') { if (--depth == 0 && objStart >= 0) { result.add(parseJsonObject(array.substring(objStart, i + 1))); objStart = -1; } }
            }
        }
        return result;
    }

    private static Map<String, String> parseJsonStringMap(String json) {
        Map<String, String> result = new LinkedHashMap<>();
        if (json == null || json.isBlank()) return result;
        int i = 0;
        while (i < json.length()) {
            int kq1 = json.indexOf('"', i);
            if (kq1 < 0) break;
            int kq2 = skipJsonString(json, kq1 + 1);  // position of closing quote
            String key = readJsonString(json, kq1 + 1);
            int colon = json.indexOf(':', kq2 + 1);
            if (colon < 0) break;
            int vq1 = json.indexOf('"', colon + 1);
            if (vq1 < 0) break;
            int vq2 = skipJsonString(json, vq1 + 1);  // position of closing quote
            String value = readJsonString(json, vq1 + 1);
            result.put(key, value);
            i = vq2 + 1;
        }
        return result;
    }

    /** Returns the index of the closing {@code "} for a JSON string starting at {@code from} (after the opening quote). */
    private static int skipJsonString(String json, int from) {
        for (int i = from; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\') { i++; continue; }
            if (c == '"') return i;
        }
        return json.length();
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

    private static Set<Long> parseIdList(String csv) {
        if (csv == null || csv.isBlank()) return Set.of();
        Set<Long> ids = new LinkedHashSet<>();
        for (String part : csv.split(",")) {
            try { ids.add(Long.parseLong(part.trim())); } catch (NumberFormatException ignored) {}
        }
        return ids;
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
                "<span class=\"badge success\" title=\"Dependency management check passed\">No conflicts</span>";
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
        // No "N / M" count is shown here: applying is a single atomic operation (validate, write
        // all changes, validate again), not a per-item loop, so there's no real item count to
        // track — a static "0 / 0" was previously shown here regardless of progress, which was
        // just wrong rather than merely uninformative. The progress bar instead reflects the
        // three real phases (pre-validate/applying/post-validate) reported by the apply job.
        return "<div id=\"apply-overlay\" class=\"scan-overlay\" style=\"display:none\">"
             + "<div class=\"scan-overlay-box\">"
             + "<div style=\"display:flex;align-items:center;gap:10px\">"
             + "<div class=\"scan-spinner\"></div>"
             + "<span>Applying changes…</span>"
             + "</div>"
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
        if (!phase2Pins.isEmpty() || !findings.isEmpty()) {
            List<ScanComponent> scanComponents = store.getScan(scanId).report().components();
            Map<String, String> declared = projectDeclaredDepMgmt(rootPomXml(store.loadSourcePoms(scanId)));
            if (phase2Pins.isEmpty() && !findings.isEmpty()) {
                // Phase 2 hasn't run or data predates this feature — compute planned pins for display
                phase2Pins = computePlannedPins(findings, scanComponents, declared);
            } else {
                // Stored pins may predate family alignment or its fixes — never trust them verbatim
                phase2Pins = realignStoredPins(phase2Pins, scanComponents, declared);
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

    private static String sevChipTitle(ReportSummary summary, AdvisorySeverity severity) {
        List<String> deps = summary.dependenciesBySeverity().getOrDefault(severity, List.of());
        if (deps.isEmpty()) return "";
        return " title=\"" + escape(String.join("\n", deps)) + "\"";
    }

    private static String reasonChipTitle(ReportSummary summary, RemediationReason reason) {
        List<String> deps = summary.dependenciesByReason().getOrDefault(reason, List.of());
        if (deps.isEmpty()) return "";
        return " title=\"" + escape(String.join("\n", deps)) + "\"";
    }


    private String renderRemediationView(ScanReport report, String scanId, boolean pomExists, Map<String, String> moduleArtifactIds, Map<String, String> sourcePoms, Map<String, List<TransitiveConflictFinding>> conflictsByKey) {
        List<ScanComponent> components = report.components();
        if (components.isEmpty()) {
            return "<p class=\"muted\">No dependency inventory is available for this scan.</p>";
        }

        // Computed up front (rather than down where this was historically built) so both
        // summarize() and the per-component classify() loop below can use it — a pinned
        // coordinate's plain "update recommended" reason is suppressed by RemediationClassifier
        // itself, so the summary banner and every per-card/chip count stay consistent instead of
        // separately re-deciding what a pin means.
        Set<String> pinnedCoords = new LinkedHashSet<>();
        RemediationApplier pinScanApplier = new RemediationApplier();
        for (String pomContent : sourcePoms.values()) {
            try {
                pinnedCoords.addAll(pinScanApplier.findUserPinnedCoordinates(pomContent));
            } catch (Exception ignored) {}
        }
        Set<ComponentCoordinate> pinnedCoordinates = new LinkedHashSet<>();
        for (String coordStr : pinnedCoords) {
            int idx = coordStr.indexOf(':');
            if (idx > 0) pinnedCoordinates.add(new ComponentCoordinate(coordStr.substring(0, idx), coordStr.substring(idx + 1)));
        }

        ReportSummary summary = RemediationClassifier.summarize(report, pinnedCoordinates);

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

        String rootPomContent = rootPomXml(sourcePoms);

        List<ComponentView> views = new ArrayList<>();
        for (ScanComponent c : unique.values()) {
            RemediationStatus status = RemediationClassifier.classify(
                    c, report.vulnerabilityFindings(), report.recommendations(), report.metadataResults(), pinnedCoordinates);
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

        // Computed here (rather than solely from summary.recommendationCount(), which is a
        // RemediationClassifier/core computation with no visibility into POM content or conflict
        // findings) so the "Update recommended" banner chip and the Outdated filter chip below
        // both reflect the same, more accurate signal: a transitive dependency with no concrete
        // reason to move (see transitiveRecommendedVersion) is excluded from both, not just one.
        long outdatedCount = views.stream().filter(v -> isEffectivelyOutdatedOnly(v, rootPomContent)).count();

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
        if (summary.criticalCount() > 0) html.append("<span class=\"sev-chip sev-critical\"").append(sevChipTitle(summary, AdvisorySeverity.CRITICAL)).append(">&#9762; ").append(summary.criticalCount()).append(" Critical</span>");
        if (summary.highCount() > 0) html.append("<span class=\"sev-chip sev-high\"").append(sevChipTitle(summary, AdvisorySeverity.HIGH)).append(">&#9760; ").append(summary.highCount()).append(" High</span>");
        if (summary.mediumCount() > 0) html.append("<span class=\"sev-chip sev-medium\"").append(sevChipTitle(summary, AdvisorySeverity.MEDIUM)).append(">&#9888; ").append(summary.mediumCount()).append(" Medium</span>");
        if (summary.lowCount() > 0) html.append("<span class=\"sev-chip sev-low\"").append(sevChipTitle(summary, AdvisorySeverity.LOW)).append(">&#x2139; ").append(summary.lowCount()).append(" Low</span>");
        if (summary.unknownCount() > 0) html.append("<span class=\"sev-chip sev-unknown\"").append(sevChipTitle(summary, AdvisorySeverity.UNKNOWN)).append(">? ").append(summary.unknownCount()).append(" Unknown</span>");
        html.append("</div>");
        // Breakdown of "need remediation" by reason, mirroring the OR-conditions in
        // RemediationClassifier.classify() exactly, except vulnerabilities — those are covered
        // by the deduped-by-CVE severity row above, so they're not repeated here. A component
        // can trip more than one reason at once (e.g. a snapshot with a known CVE), so these
        // chips can legitimately sum to more than "need remediation", and a component whose
        // only reason is a vulnerability won't appear in this row (see the severity row instead).
        html.append("<div class=\"rem-banner-row\">");
        if (summary.snapshotCount() > 0) html.append("<span class=\"sev-chip sev-snap\"").append(reasonChipTitle(summary, RemediationReason.SNAPSHOT)).append(">&#9889; ").append(summary.snapshotCount()).append(" Snapshot</span>");
        if (summary.declaredVersionWarningCount() > 0) html.append("<span class=\"sev-chip sev-declared\"").append(reasonChipTitle(summary, RemediationReason.DECLARED_VERSION)).append(">&#128196; ").append(summary.declaredVersionWarningCount()).append(" Declared version</span>");
        if (outdatedCount > 0) html.append("<span class=\"sev-chip sev-recommended\"").append(reasonChipTitle(summary, RemediationReason.UPGRADE_RECOMMENDED)).append(">&#8593; ").append(outdatedCount).append(" Update recommended</span>");
        if (summary.staleMetadataCount() > 0) html.append("<span class=\"sev-chip sev-stale\"").append(reasonChipTitle(summary, RemediationReason.STALE_METADATA)).append(">&#8635; ").append(summary.staleMetadataCount()).append(" Stale metadata</span>");
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

        // Three workflow-level views (mutually exclusive, like a tab really is one) plus, within
        // Findings, independent multi-select filter chips — CVE/Conflict/Transitive/etc. are
        // overlapping properties a dependency can have at once, not disjoint categories, so they
        // no longer compete for one exclusive tab slot the way Findings/Clean/All genuinely do.
        long cveUpgradeCount = views.stream().filter(this::isCveFixByUpgrade).count();
        long cveDowngradeCount = views.stream().filter(this::isCveFixByDowngrade).count();
        long cveNofixCount = views.stream().filter(this::isCveNofix).count();
        long conflictCount = views.stream().filter(v -> v.convergenceFinding() != null).count();
        long snapshotCount = views.stream().filter(v -> v.status().isSnapshot()).count();
        long directCount = views.stream().filter(v -> v.component().direct()).count();
        long transitiveOriginCount = views.stream().filter(v -> !v.component().direct()).count();
        long cleanCount = views.stream().filter(this::isCardClean).count();
        long findingsCount = views.size() - cleanCount;

        html.append("<div class=\"rem-toggle\">");
        html.append("<button class=\"button primary rem-toggle-btn\" type=\"button\" data-view=\"findings\" onclick=\"setRemView('findings')\">Findings <span class=\"tab-count\">").append(findingsCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-view=\"clean\" onclick=\"setRemView('clean')\">Clean <span class=\"tab-count\">").append(cleanCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-view=\"all\" onclick=\"setRemView('all')\">All <span class=\"tab-count\">").append(views.size()).append("</span></button>");
        html.append("</div>");

        html.append("<div class=\"rem-filters\" id=\"rem-filters\">");
        html.append("<div class=\"filter-group\" data-group=\"reason\">");
        html.append("<span class=\"filter-group-label\">Reason</span>");
        html.append(filterChipHtml("reason", "cveupgrade", "CVE Upgrade", cveUpgradeCount));
        html.append(filterChipHtml("reason", "cvedowngrade", "CVE Downgrade", cveDowngradeCount));
        html.append(filterChipHtml("reason", "cvenofix", "CVE Nofix", cveNofixCount));
        html.append(filterChipHtml("reason", "conflict", "Conflict", conflictCount));
        html.append(filterChipHtml("reason", "outdated", "Outdated", outdatedCount));
        html.append(filterChipHtml("reason", "snapshot", "Snapshot", snapshotCount));
        html.append("</div>");
        html.append("<div class=\"filter-group\" data-group=\"origin\">");
        html.append("<span class=\"filter-group-label\">Origin</span>");
        html.append(filterChipHtml("origin", "direct", "Direct", directCount));
        html.append(filterChipHtml("origin", "transitive", "Transitive", transitiveOriginCount));
        html.append("</div>");
        html.append("<div class=\"filter-rule\" id=\"rem-filter-rule\"></div>");
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
                .append("\"pin\":").append(pinnedCoords.contains(c.coordinate().groupId() + ":" + c.coordinate().artifactId())).append(",")
                .append("\"hasvuln\":").append(s.hasVulnerability());
            String recTarget = c.direct()
                    ? (v.recommendation() != null ? v.recommendation().targetVersion() : null)
                    : transitiveRecommendedVersion(v, rootPomContent);
            if (recTarget != null && !recTarget.equals(c.version())) {
                html.append(",\"rec\":").append(jsonStr(recTarget));
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
            html.append(renderComponentCard(view, mod, hasParents, vulnsByKey, pinnedCoords, rootPomContent));
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

        // Apply preview modal — shown on every "Apply selected" click before the apply-batch job runs
        html.append("<div id=\"apply-preview-modal\" class=\"pom-modal\" style=\"display:none\">");
        html.append("<div class=\"pom-modal-backdrop\" onclick=\"closeApplyPreview()\"></div>");
        html.append("<div class=\"pom-modal-box\" style=\"width:min(560px,92vw)\">");
        html.append("<div class=\"pom-modal-head\">");
        html.append("<span class=\"pom-modal-filename\">Apply changes</span>");
        html.append("<div style=\"display:flex;gap:8px;flex-shrink:0\">");
        html.append("<button class=\"button\" type=\"button\" onclick=\"closeApplyPreview()\">Cancel</button>");
        html.append("<button class=\"button primary\" type=\"button\" id=\"apply-preview-ok\" onclick=\"confirmApplyPreview()\">OK</button>");
        html.append("</div></div>");
        html.append("<div class=\"pom-modal-body\"><div id=\"apply-preview-body\" style=\"padding:20px\"></div></div>");
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

    /** A CVE resolved by upgrading — tier 1 (RecommendationReason.CVE_FIX), or tier 3 best-effort
     *  when its suggested target happens to be above the current version. */
    private boolean isCveFixByUpgrade(ComponentView view) {
        if (!view.status().hasVulnerability() || view.recommendation() == null) return false;
        RecommendationReason reason = view.recommendation().reason();
        if (reason == RecommendationReason.CVE_FIX) return true;
        return reason == RecommendationReason.CVE_BEST_EFFORT
                && compareVersionsSemantic(view.recommendation().targetVersion(), view.component().version()) > 0;
    }

    /** A CVE with no upgrade fix, resolved by downgrading — tier 2 (CVE_FIX_DOWNGRADE), or tier 3
     *  best-effort when its suggested target happens to be below the current version. */
    private boolean isCveFixByDowngrade(ComponentView view) {
        if (!view.status().hasVulnerability() || view.recommendation() == null) return false;
        RecommendationReason reason = view.recommendation().reason();
        if (reason == RecommendationReason.CVE_FIX_DOWNGRADE) return true;
        return reason == RecommendationReason.CVE_BEST_EFFORT
                && compareVersionsSemantic(view.recommendation().targetVersion(), view.component().version()) < 0;
    }

    /** Whether a vulnerability on this component has any recommended target version — a full fix
     *  (upgrade/downgrade) or a best-effort suggestion, which is folded into whichever of those
     *  two directions its target version actually moves. */
    private boolean hasFixableCve(ComponentView view) {
        return isCveFixByUpgrade(view) || isCveFixByDowngrade(view);
    }

    /** A CVE with no recommendation at all — no upgrade, no downgrade, and no best-effort
     *  candidate beat the current version's own severity. Genuinely nothing to suggest. */
    private boolean isCveNofix(ComponentView view) {
        return view.status().hasVulnerability() && view.recommendation() == null;
    }

    /** Matches the "Update recommended" reason counted in RemediationClassifier.summarize() —
     *  the single source of truth for both the "Update recommended" banner chip and the
     *  Outdated filter chip, so the two numbers never diverge like they did when a tab computed
     *  its own definition client-side. */
    private static boolean isUpgradeRecommendedOnly(RemediationStatus status) {
        return status.hasUpgradeRecommendation() && !status.hasVulnerability() && !status.isSnapshot();
    }

    /** {@link #isUpgradeRecommendedOnly}, further narrowed to cases where a target version is
     *  actually offered — matching renderComponentCard's own effectiveRecommendation/upgradeOnly
     *  logic. A transitive dependency's raw recommendation is withheld (see
     *  transitiveRecommendedVersion) when there's no concrete reason to move it, and its version
     *  selector defaults to "No change" accordingly; counting it toward "Outdated" anyway would
     *  advertise an update the UI itself doesn't actually offer. */
    private boolean isEffectivelyOutdatedOnly(ComponentView view, String rootPomContent) {
        if (!isUpgradeRecommendedOnly(view.status())) return false;
        ScanComponent comp = view.component();
        if (comp.direct()) return true;
        String transitiveTarget = transitiveRecommendedVersion(view, rootPomContent);
        return transitiveTarget != null && !transitiveTarget.equals(comp.version());
    }

    /** Whether a card is treated as "clean" for tab-filtering/counting purposes — the single
     *  source of truth shared by the banner counts and the per-card rendering, so the CVE and
     *  Clean tabs can never double-count the same card. */
    private boolean isCardClean(ComponentView view) {
        ScanComponent comp = view.component();
        RemediationStatus status = view.status();
        boolean clean = !status.needsRemediation();
        // Non-conflict transitive deps are only actionable when their CVE has a fix available —
        // suppress upgrade-only recommendations and unfixable CVEs to avoid noise.
        if (!comp.direct() && view.convergenceFinding() == null
                && !hasFixableCve(view) && !status.isSnapshot()) {
            clean = true;
        }
        return clean && view.convergenceFinding() == null;
    }

    private String renderComponentCard(ComponentView view, String module, boolean hasChildren, Map<String, List<VulnerabilityFinding>> vulnsByKey, Set<String> pinnedCoords, String rootPomContent) {
        ScanComponent comp = view.component();
        RemediationStatus status = view.status();
        boolean hasFixableCve = hasFixableCve(view);
        String coordStr = comp.coordinate().groupId() + ":" + comp.coordinate().artifactId();
        boolean pinned = pinnedCoords.contains(coordStr);
        // For transitive components only: override what "recommended" means (see
        // transitiveRecommendedVersion doc) — null when it resolves to a no-op (== current
        // version), so display code can treat "nothing to recommend" and "no recommendation
        // object" identically.
        String transitiveTarget = comp.direct() ? null
                : transitiveRecommendedVersion(view, rootPomContent);
        boolean transitiveHasTarget = transitiveTarget != null && !transitiveTarget.equals(comp.version());
        UpgradeRecommendation effectiveRecommendation = comp.direct() ? view.recommendation()
                : (transitiveHasTarget
                    ? new UpgradeRecommendation(comp.id(), comp.coordinate(), comp.version(), transitiveTarget,
                        view.recommendation() != null ? view.recommendation().reason() : RecommendationReason.MINOR_AVAILABLE,
                        view.recommendation() != null ? view.recommendation().riskLevel() : RiskLevel.ELEVATED,
                        view.recommendation() != null ? view.recommendation().confidence() : RecommendationConfidence.HIGH,
                        view.recommendation() != null ? view.recommendation().fixedCves() : List.of(),
                        List.of(comp.id()))
                    : null);

        StringBuilder html = new StringBuilder();
        String kind = comp.snapshot() ? "snapshot" : comp.direct() ? "declared" : "transitive";
        // Matches effectiveRecommendation above: a transitive dependency with no concrete reason
        // to move has its recommendation withheld there (the version selector defaults to "No
        // change" for it), so it must be withheld here too — otherwise the Outdated chip's count
        // and card-matching would include cards with nothing actually shown as available to apply.
        boolean upgradeOnly = isUpgradeRecommendedOnly(status) && (comp.direct() || transitiveHasTarget);
        boolean actionableConvergence = view.convergenceFinding() != null;
        String conflictJson = actionableConvergence ? buildConflictJson(view.convergenceFinding()) : "";
        boolean dataClean = isCardClean(view);
        // Three-way CVE fix status. isCardClean() guarantees clean and any of these three stay
        // mutually exclusive, and every vulnerable component falls into exactly one of them.
        boolean dataCveUpgrade = isCveFixByUpgrade(view);
        boolean dataCveDowngrade = isCveFixByDowngrade(view);
        boolean dataCveNofix = isCveNofix(view);
        // Origin (direct/transitive) purely from comp.direct() — independent of snapshot status,
        // unlike "kind" below, which conflates the two. A snapshot dependency is still either
        // direct or transitive for filtering purposes; "kind" stays as-is since badge/label text
        // elsewhere still wants snapshot called out as its own thing.
        String origin = comp.direct() ? "direct" : "transitive";
        html.append("<div class=\"rem-card").append(dataClean ? " clean" : "").append("\" data-clean=\"").append(dataClean)
                .append("\" data-module=\"").append(escape(module))
                .append("\" data-kind=\"").append(kind)
                .append("\" data-origin=\"").append(origin)
                .append("\" data-cveupgrade=\"").append(dataCveUpgrade)
                .append("\" data-cvedowngrade=\"").append(dataCveDowngrade)
                .append("\" data-cvenofix=\"").append(dataCveNofix)
                .append("\" data-upgradeonly=\"").append(upgradeOnly)
                .append("\" data-hasconflict=\"").append(actionableConvergence)
                .append("\" data-coord=\"").append(escape(coordStr))
                .append("\" data-pinned=\"").append(pinned)
                .append("\" data-pinned-initial=\"").append(pinned)
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
        html.append(severityBadgeHtml(status.highestSeverity(), dataClean));
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
        if (effectiveRecommendation != null && !status.isSnapshot()) {
            String recLabel = switch (effectiveRecommendation.reason()) {
                case CVE_FIX_DOWNGRADE -> "Downgrade to";
                case CVE_BEST_EFFORT -> "Best available";
                default -> "Recommended";
            };
            html.append("<span>&rarr; ").append(recLabel).append(": <strong>").append(escape(effectiveRecommendation.targetVersion())).append("</strong></span>");
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
                .filter(r -> !"Update recommended".equals(r)).toList();
        boolean showUpgradeBtn = effectiveRecommendation != null && !status.isSnapshot();
        boolean showNoUpgradeChip = !comp.direct() && !status.isSnapshot()
                && effectiveRecommendation == null && view.versionMetadata() != null;
        if (!otherReasons.isEmpty() || showUpgradeBtn || showNoUpgradeChip) {
            html.append("<div class=\"rem-reasons\">");
            for (String reason : otherReasons) {
                html.append("<span class=\"reason-chip\">").append(escape(reason)).append("</span>");
            }
            if (showUpgradeBtn) {
                RecommendationReason recReason = effectiveRecommendation.reason();
                String verb = switch (recReason) {
                    case CVE_FIX_DOWNGRADE -> "Downgrade to";
                    case CVE_BEST_EFFORT -> "Best available:";
                    default -> "Upgrade to";
                };
                if (comp.direct()) {
                    html.append("<button class=\"reason-chip reason-chip-btn\" type=\"button\" onclick=\"applyUpgrade(")
                        .append(comp.id()).append(",'").append(escape(effectiveRecommendation.targetVersion())).append("',this)\">")
                        .append(verb).append(" ").append(escape(effectiveRecommendation.targetVersion())).append("</button>");
                } else {
                    String transitiveChip = switch (recReason) {
                        case CVE_FIX_DOWNGRADE -> "Downgrade available";
                        case CVE_BEST_EFFORT -> "Lower-severity version available";
                        default -> view.canUpgradeViaDirect() ? "Update available" : "Major update available";
                    };
                    html.append("<span class=\"reason-chip\">").append(transitiveChip).append("</span>");
                }
            } else if (showNoUpgradeChip) {
                String noFixChip = status.hasVulnerability() ? "No fix available" : "No upgrade available";
                html.append("<span class=\"reason-chip\">").append(noFixChip).append("</span>");
            }
            html.append("</div>");
        }

        // Show version selector for: direct deps with metadata or conflict, transitive conflict deps,
        // and transitive deps with a fixable CVE (upgrade, downgrade, or best-effort — hasFixableCve
        // covers all three) or a plain upgrade recommendation — in every case there's a concrete
        // target version to apply.
        boolean showVersionSelector = view.convergenceFinding() != null
                || (comp.direct() && view.versionMetadata() != null)
                || (!comp.direct() && (hasFixableCve || isUpgradeRecommendedOnly(status))
                    && view.versionMetadata() != null);
        // A pinned component that's since become fully clean (e.g. already at the version it was
        // pinned to, with nothing left to recommend) would otherwise lose its version selector —
        // and with it, the only way to reach the Pin checkbox and un-pin it. Keep the actions row
        // (checkbox only, no dropdown) for that case.
        if (showVersionSelector || (pinned && !actionableConvergence)) {
            html.append("<div class=\"rem-actions\">");
            if (showVersionSelector && comp.direct()) {
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
                        view.versionMetadata(), view.recommendation(), false, directConflictVersions,
                        view.convergenceFinding() != null));
            } else if (showVersionSelector && (view.versionMetadata() != null || view.convergenceFinding() != null)) {
                // Transitive: the selector's default is exactly transitiveTarget's 3-tier result
                // (existing pin > highest version already in the conflict > current/no-op) — never
                // conflictDefaultVersion's CVE-driven walk beyond what's already in the tree, and
                // never the scan-time recommendation's own target.
                String selectorId = "view_" + comp.id();
                List<String> conflictVersions = view.convergenceFinding() != null
                        ? view.convergenceFinding().conflictingVersions()
                        : List.of();
                String selectedVersion = transitiveTarget != null ? transitiveTarget : comp.version();
                html.append(renderVersionSelect(selectorId, comp.coordinate(), comp.version(), selectedVersion,
                        view.versionMetadata(), effectiveRecommendation, false,
                        conflictVersions, true));
            }
            if (!actionableConvergence) {
                html.append("<label class=\"pin-toggle\" title=\"Keep this dependency at its current/selected version through bulk upgrades\">")
                        .append("<input type=\"checkbox\" class=\"pin-chk\" data-comp-id=\"").append(comp.id())
                        .append("\"").append(pinned ? " checked" : "")
                        .append(" onchange=\"onPinToggle(this)\"> Pin</label>");
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

    /** Whitespace-separated extra {@code mvn} arguments, e.g. {@code -Pdev -Dspring.profiles.active=dev}. */
    private static List<String> parseMavenArgs(String raw) {
        if (raw == null || raw.isBlank()) return List.of();
        List<String> args = new ArrayList<>();
        for (String part : raw.trim().split("\\s+")) {
            if (!part.isEmpty()) args.add(part);
        }
        return args;
    }

    /** Comma-separated {@code KEY=VALUE} pairs set as environment variables on the validation processes. */
    private static Map<String, String> parseEnvVars(String raw) {
        if (raw == null || raw.isBlank()) return Map.of();
        Map<String, String> env = new LinkedHashMap<>();
        for (String pair : raw.split(",")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            env.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
        }
        return env;
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
            boolean includeNameAttr, List<String> conflictVersions,
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
            AdvisorySeverity currentSeverity = severityForVersion(coordinate, currentVersion);
            boolean currentHasCve = currentSeverity != AdvisorySeverity.NONE;
            html.append("<span class=\"version-current").append(currentHasCve ? " cve" : "").append("\">");
            html.append(escape(currentVersion));
            if (currentHasCve) {
                html.append("<span class=\"pill sev-").append(currentSeverity.name().toLowerCase())
                        .append("\">").append(escape(currentSeverity.label())).append("</span>");
            }
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
            AdvisorySeverity severity = severityForVersion(coordinate, version);
            String label = buildVersionOptionLabel(version, recommendedVersion, latestVersion, latestSameMajor,
                    recommendation != null ? recommendation.reason() : null, severity, currentVersion,
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
            String latestSameMajor, RecommendationReason reason, AdvisorySeverity severity, String currentVersion,
            boolean isConflictVersion, boolean isCurrentVersion) {
        List<String> tags = new ArrayList<>();
        if (isCurrentVersion) tags.add("current");
        if (version.equals(recommendedVersion)) {
            tags.add("recommended");
            if (reason == RecommendationReason.CVE_FIX || reason == RecommendationReason.CVE_FIX_DOWNGRADE) {
                tags.add("fixes CVE");
            } else if (reason == RecommendationReason.CVE_BEST_EFFORT) {
                tags.add("lowest known severity");
            }
        }
        if (version.equals(latestVersion)) tags.add("latest");
        if (version.equals(latestSameMajor) && !version.equals(latestVersion)) {
            tags.add(sameMajorMinor(version, currentVersion) ? "latest same minor" : "latest same major");
        }
        // Show the actual severity level rather than a generic "vulnerable" flag, so a Low CVE
        // doesn't read the same as a Critical one when comparing candidates in the dropdown.
        if (severity != null && severity != AdvisorySeverity.NONE) {
            tags.add(severity.label().toLowerCase() + " severity");
        }
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

    /** Whether a card shows up in the default view (Findings) — used only to pick which module
     *  tab is initially selected, so it should match exactly what the Findings view itself shows. */
    private boolean isDefaultVisibleRemediationCard(ComponentView view) {
        return view != null && !isCardClean(view);
    }

    /** One checkbox filter chip — a pill, not a button, since several can be active in the same
     *  group at once. {@code dataFilterValue} matches what {@code applyRemediationFilters} in
     *  scripts.js reads off each card's own {@code data-*} attributes for this group. */
    private static String filterChipHtml(String group, String dataFilterValue, String label, long count) {
        return "<label class=\"filter-chip\"><input type=\"checkbox\" data-filter-group=\"" + group
                + "\" data-filter-value=\"" + dataFilterValue + "\" onchange=\"toggleFilterChip(this)\">"
                + "<span class=\"filter-chip-check\" aria-hidden=\"true\"></span>"
                + escape(label) + " <span class=\"tab-count\" data-chip-count=\"" + group + ":" + dataFilterValue + "\">"
                + count + "</span></label>";
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
                html.append(renderVersionButtonGroup(component.coordinate(), component.version(), component.id(), versionMetadata, recommendation, versionChoices(versionMetadata, recommendation), recommendation == null ? component.version() : recommendation.targetVersion(), false));
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
            if (!phase2Pins.isEmpty() || !enforcerResult.findings().isEmpty()) {
                Map<String, String> declared = projectDeclaredDepMgmt(rootPomXml(store.loadSourcePoms(scanId)));
                if (phase2Pins.isEmpty() && !enforcerResult.findings().isEmpty()) {
                    phase2Pins = computePlannedPins(enforcerResult.findings(), report.components(), declared);
                } else {
                    // Stored pins may predate family alignment or its fixes — never trust them verbatim
                    phase2Pins = realignStoredPins(phase2Pins, report.components(), declared);
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

    private String renderVersionButtonGroup(ComponentCoordinate coordinate, String currentVersion, long selectorKey, MetadataResult versionMetadata, UpgradeRecommendation recommendation, List<String> choices, String selectedVersion, boolean includeHiddenInput) {
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
            AdvisorySeverity currentSeverity = severityForVersion(coordinate, currentVersion);
            html.append(versionChoiceButton(selectorId, currentVersion, currentVersion, currentVersion.equals(selectedVersion), currentSeverity, true));
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
            AdvisorySeverity severity = severityForVersion(coordinate, version);
            html.append(versionChoiceButton(selectorId, version, version, active, severity, false));
        }
        if (includeHiddenInput) {
            html.append("<input type=\"hidden\" id=\"").append(escape(selectorId)).append("\" name=\"").append(escape(selectorId)).append("\" value=\"").append(escape(selectedVersion == null ? "" : selectedVersion)).append("\"/>");
        }
        html.append("</div>");
        return html.toString();
    }

    private String versionChoiceButton(String selectorId, String version, String label, boolean active, AdvisorySeverity severity, boolean current) {
        boolean cve = severity != null && severity != AdvisorySeverity.NONE;
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
            html.append("<span class=\"pill sev-").append(severity.name().toLowerCase())
                    .append("\">").append(escape(severity.label())).append("</span>");
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

    /** Highest known severity for a specific candidate version (not just the currently-scanned
     *  one) — a real per-version lookup (cached, so repeat renders and versions already checked
     *  during the scan's CVE fix resolution are typically free) rather than string-matching
     *  against the current version's own findings, which could never be true for any other
     *  version in the dropdown and made every non-current choice look falsely clean. Returns
     *  the actual severity level rather than a boolean so the dropdown can distinguish a Low
     *  residual CVE from a Critical one instead of showing them identically. */
    private AdvisorySeverity severityForVersion(ComponentCoordinate coordinate, String candidateVersion) {
        if (coordinate == null || candidateVersion == null || candidateVersion.isBlank()) {
            return AdvisorySeverity.NONE;
        }
        return AdvisoryClassifier.highest(store.vulnerabilityProvider.vulnerabilities(coordinate, candidateVersion));
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
            // Also offer older releases, not just the automated upgrade/downgrade path, so the
            // user can always manually pick something different — the algorithm's choice is a
            // default, not the only option. Capped to the N closest below the current version
            // (configurable, default 10) rather than the entire release history, which for a
            // long-lived library can run to hundreds of entries and swamp the dropdown.
            if (versionMetadata.allStableVersions() != null && versionMetadata.currentVersion() != null) {
                List<String> olderVersions = new ArrayList<>();
                for (String version : versionMetadata.allStableVersions()) {
                    if (version == null || version.isBlank() || isPreRelease(version)) continue;
                    if (compareVersionsSemantic(version, versionMetadata.currentVersion()) < 0) {
                        olderVersions.add(version);
                    }
                }
                olderVersions.sort((a, b) -> compareVersionsSemantic(b, a)); // descending — closest first
                for (int i = 0; i < Math.min(versionLookbackLimit(), olderVersions.size()); i++) {
                    choices.add(olderVersions.get(i));
                }
            }
        }
        if (recommendation != null && recommendation.currentVersion() != null) {
            choices.remove(recommendation.currentVersion());
        }
        return List.copyOf(choices);
    }

    /** How many older releases the version-selector dropdown offers below the current version.
     *  Read fresh on each call (cheap) rather than cached, so it can be changed without a
     *  restart. Defaults to 10; override with -Dredkite.version.lookback=N. */
    private static int versionLookbackLimit() {
        try {
            return Integer.parseInt(System.getProperty("redkite.version.lookback", "10"));
        } catch (NumberFormatException e) {
            return 10;
        }
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
            case CVE_FIX_DOWNGRADE -> "CVE FIX (DOWNGRADE)";
            case CVE_BEST_EFFORT -> "CVE BEST EFFORT";
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
            seedConfigDefaults();
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
                         select id, name, root_path, created_at, updated_at, validation_maven_args, validation_env
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
                            rs.getTimestamp("updated_at").toInstant(),
                            rs.getString("validation_maven_args"),
                            rs.getString("validation_env")));
                }
                return projects;
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to list projects", e);
            }
        }

        synchronized ProjectEntry getProject(String id) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, name, root_path, created_at, updated_at, validation_maven_args, validation_env
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
                            rs.getTimestamp("updated_at").toInstant(),
                            rs.getString("validation_maven_args"),
                            rs.getString("validation_env"));
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to fetch project", e);
            }
        }

        synchronized void updateValidationSettings(String projectId, String mavenArgs, String env) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement(
                         "update projects set validation_maven_args = ?, validation_env = ? where id = ?")) {
                statement.setString(1, mavenArgs);
                statement.setString(2, env);
                statement.setString(3, projectId);
                statement.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to update validation settings", e);
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
            return new MetadataResult(scanId, result.componentId(), result.metadataType(), result.provider(), result.currentVersion(), result.latestVersion(), result.latestSameMajorVersion(), result.upgradePathVersions(), result.allStableVersions(), result.complete(), result.status(), result.cacheState(), result.lastSuccessfulCheckAt(), result.cacheExpiryAt(), result.attemptedRefreshAt(), result.suggestedRetryAt(), result.message());
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

            // Pass 3: update analysis
            progress.accept("Updates");
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
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, "none", component.version(), "unknown", "unknown", List.of(), List.of(), false, MetadataStatus.NOT_APPLICABLE, CacheState.MISSING, null, null, Instant.now(), null, "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata."));
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VULNERABILITY, "none", component.version(), "unknown", "unknown", List.of(), List.of(), false, MetadataStatus.NOT_APPLICABLE, CacheState.MISSING, null, null, Instant.now(), null, "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata."));
                } else {
                    VersionMetadata versionMetadata = versionMap.get(component.id());
                    LOGGER.info(() -> "Maven version metadata for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " => latest=" + versionMetadata.latestVersion() + ", sameMajor=" + versionMetadata.latestSameMajorVersion() + ", complete=" + versionMetadata.complete() + ", status=" + versionMetadata.status());
                    String versionMessage = versionMetadata.complete()
                            ? "Latest Maven release is " + versionMetadata.latestVersion() + "."
                            : "No cached Maven metadata was available; version is unknown.";
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, versionMetadata.source(), component.version(), versionMetadata.latestVersion(), versionMetadata.latestSameMajorVersion(), versionMetadata.upgradePathVersions(), versionMetadata.allStableVersions(), versionMetadata.complete(), versionMetadata.status(), versionMetadata.cacheState(), versionMetadata.checkedAt(), null, Instant.now(), null, versionMessage));
                    if (!versionMetadata.complete()) {
                        complete = false;
                    }

                    List<VulnerabilityFinding> compVulns = vulnMap.getOrDefault(component.id(), List.of());
                    boolean hasVulns = !compVulns.isEmpty();
                    String vulnMessage = hasVulns
                            ? "Found " + compVulns.size() + " vulnerabilit" + (compVulns.size() == 1 ? "y" : "ies") + "."
                            : "No known vulnerabilities.";
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VULNERABILITY, "osv.dev", component.version(), "unknown", "unknown", List.of(), List.of(), true, MetadataStatus.FRESH, CacheState.FRESH, Instant.now(), null, Instant.now(), null, vulnMessage));
                    for (VulnerabilityFinding f : compVulns) {
                        vulnerabilityFindings.add(new VulnerabilityFinding(f.advisoryId(), f.severity(), f.coordinate(), f.affectedVersion(), f.fixedVersion(), f.introducedVersion(), component.direct(), component.owningVersionControlPoint(), f.cves(), null));
                    }

                    if (versionMetadata.complete() && canPlanUpgrade(component) && hasVulns) {
                        CveFixResult fix = resolveCveFix(component, compVulns, versionMetadata, input.allowMajorUpgrades());
                        if (fix != null) {
                            RiskLevel risk = component.direct() ? upgradeRisk(component.version(), fix.target()) : RiskLevel.ELEVATED;
                            recs.add(new UpgradeRecommendation(component.id(), component.coordinate(), component.version(),
                                    fix.target(), fix.reason(), risk, RecommendationConfidence.HIGH, List.of(), List.of(component.id())));
                            LOGGER.info(() -> "Resolved CVE fix (" + fix.reason() + ") for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " => " + component.version() + " -> " + fix.target());
                        } else {
                            LOGGER.info(() -> "No CVE fix found (upgrade, downgrade, or best-effort) for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                        }
                    } else if (versionMetadata.complete() && canPlanUpgrade(component)) {
                        String target = selectUpgradeTarget(component.version(), versionMetadata);
                        if (target != null && isUpgradeable(component.version(), target)) {
                            if (!input.allowMajorUpgrades() && isMajorUpgrade(component.version(), target)) {
                                LOGGER.info(() -> "Skipping major upgrade recommendation for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " because the scan did not allow major upgrades");
                            } else {
                                RecommendationReason reason = upgradeReason(component.version(), target);
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
                case CVE_FIX_DOWNGRADE -> "No upgrade fixes this CVE; downgrading to " + target + " avoids it.";
                case CVE_BEST_EFFORT -> "No version fully resolves this CVE; " + target + " has the lowest known severity.";
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

        private record CveFixResult(String target, RecommendationReason reason) {}

        /**
         * Resolves a fix for a vulnerable component's CVE(s): tries an upgrade first (the smallest
         * version at or above every finding's fixedVersion), then a downgrade (the largest version
         * below every finding's introducedVersion) if no upgrade clears all findings, then a bounded
         * best-effort search of nearby versions for the lowest residual severity. Returns null only
         * when the current version is already the best available.
         */
        /** Bounds how many candidates each tier will verify with a live vulnerability query, so
         *  a component with a genuinely unfixable CVE doesn't trigger unbounded OSV lookups. */
        private static final int MAX_FIX_VERIFY_CANDIDATES = 6;

        private CveFixResult resolveCveFix(ScanComponent component, List<VulnerabilityFinding> compVulns,
                VersionMetadata versionMetadata, boolean allowMajorUpgrades) {
            String current = component.version();
            List<String> allVersions = versionMetadata.allStableVersions() == null
                    ? List.of() : versionMetadata.allStableVersions();

            String upgradeTarget = smallestCleanUpgrade(component, current, compVulns, allVersions, allowMajorUpgrades);
            if (upgradeTarget != null) {
                return new CveFixResult(upgradeTarget, RecommendationReason.CVE_FIX);
            }

            String downgradeTarget = largestCleanDowngrade(component, current, compVulns, allVersions);
            if (downgradeTarget != null) {
                return new CveFixResult(downgradeTarget, RecommendationReason.CVE_FIX_DOWNGRADE);
            }

            String bestEffort = bestEffortLowestSeverity(component, current, allVersions);
            if (bestEffort != null) {
                return new CveFixResult(bestEffort, RecommendationReason.CVE_BEST_EFFORT);
            }
            return null;
        }

        /** Smallest available version that clears every finding's fixedVersion AND is itself
         *  verified free of any known vulnerability (a version can escape *this* CVE's range
         *  while carrying an entirely unrelated one of its own, especially further from current).
         *  Null if any finding has no known fixedVersion (open-ended — upgrading can never
         *  resolve it), or no verified-clean candidate is found within the search bound. */
        private String smallestCleanUpgrade(ScanComponent component, String current,
                List<VulnerabilityFinding> compVulns, List<String> allVersions, boolean allowMajorUpgrades) {
            String requiredFix = null;
            for (VulnerabilityFinding f : compVulns) {
                if (f.fixedVersion() == null || f.fixedVersion().isBlank()) return null;
                if (requiredFix == null || compareVersions(f.fixedVersion(), requiredFix) > 0) {
                    requiredFix = f.fixedVersion();
                }
            }
            if (requiredFix == null) return null;
            List<String> candidates = new ArrayList<>();
            for (String v : allVersions) {
                if (isPreRelease(v) || compareVersions(v, requiredFix) < 0) continue;
                if (!allowMajorUpgrades && isMajorUpgrade(current, v)) continue;
                candidates.add(v);
            }
            candidates.sort(this::compareVersions); // ascending — verify the smallest (closest) first
            return firstVerifiedClean(component, candidates);
        }

        /** Largest available version strictly below every finding's introducedVersion — the
         *  newest release that predates the CVE being introduced — AND itself verified free of
         *  any known vulnerability (older releases are especially likely to carry their own,
         *  unrelated CVEs, so escaping this advisory's range is not sufficient on its own). Null
         *  if any finding has no known introducedVersion (affected since the dependency's first
         *  release — no downgrade can help), or no verified-clean candidate is found.*/
        private String largestCleanDowngrade(ScanComponent component, String current,
                List<VulnerabilityFinding> compVulns, List<String> allVersions) {
            String requiredBelow = null;
            for (VulnerabilityFinding f : compVulns) {
                if (f.introducedVersion() == null || f.introducedVersion().isBlank()) return null;
                if (requiredBelow == null || compareVersions(f.introducedVersion(), requiredBelow) < 0) {
                    requiredBelow = f.introducedVersion();
                }
            }
            if (requiredBelow == null) return null;
            List<String> candidates = new ArrayList<>();
            for (String v : allVersions) {
                if (isPreRelease(v) || compareVersions(v, current) >= 0) continue;
                if (compareVersions(v, requiredBelow) >= 0) continue;
                candidates.add(v);
            }
            candidates.sort((a, b) -> compareVersions(b, a)); // descending — verify the largest (closest) first
            return firstVerifiedClean(component, candidates);
        }

        /** Walks candidates in the order given, querying live vulnerability data for each (cached
         *  thereafter) until one comes back with zero findings, bounded to avoid unbounded lookups
         *  against a component with no genuinely clean version nearby. */
        private String firstVerifiedClean(ScanComponent component, List<String> candidates) {
            int checked = 0;
            for (String candidate : candidates) {
                if (checked++ >= MAX_FIX_VERIFY_CANDIDATES) break;
                if (vulnerabilityProvider.vulnerabilities(component.coordinate(), candidate).isEmpty()) {
                    return candidate;
                }
            }
            return null;
        }

        /** Neither direction fully clears the CVE(s). Checks a bounded window of nearby versions
         *  on each side plus the true latest release (live OSV queries, cached thereafter).
         *  Upgrade candidates that only *tie* the current severity are still eligible — a CVE
         *  with no known fix at all (unbounded advisory range) affects every later release
         *  identically, and moving to a newer release is still preferable to staying put even
         *  without a severity win (it's likely to carry other, unrelated fixes). Downgrade
         *  candidates are held to a stricter bar: a downgrade must *strictly* beat the current
         *  severity to be worth suggesting — an older release with no CVE improvement is pure
         *  downside (missing later fixes) and should never be offered just because it ties.
         *  Within whichever direction wins, ties are broken toward the candidate closest to
         *  current. Returns null if nothing at least as good as current is found. */
        private String bestEffortLowestSeverity(ScanComponent component, String current, List<String> allVersions) {
            // Located by value, not by exact string match against allVersions — the current
            // version's string may not literally appear there (different qualifier formatting,
            // filtered out by the stable-version regex, cache staleness, etc.), and indexOf
            // silently aborting the whole search on a mismatch was the earlier bug: it looked
            // like no fix existed even when a strictly better nearby version clearly did.
            List<String> below = new ArrayList<>();
            List<String> above = new ArrayList<>();
            for (String v : allVersions) {
                if (isPreRelease(v)) continue;
                int cmp = compareVersions(v, current);
                if (cmp < 0) below.add(v);
                else if (cmp > 0) above.add(v);
            }
            below.sort((a, b) -> compareVersions(b, a)); // descending — closest below first
            above.sort(this::compareVersions); // ascending — closest above first
            List<String> aboveWindow = new ArrayList<>(above.subList(0, Math.min(MAX_FIX_VERIFY_CANDIDATES, above.size())));
            // Always check the true latest release too, even if it fell outside the window above —
            // it's the one version most likely to have picked up an eventual fix.
            if (!above.isEmpty()) {
                String latest = above.get(above.size() - 1);
                if (!aboveWindow.contains(latest)) aboveWindow.add(latest);
            }
            List<String> belowWindow = below.subList(0, Math.min(3, below.size()));

            AdvisorySeverity currentSeverity = AdvisoryClassifier.highest(
                    vulnerabilityProvider.vulnerabilities(component.coordinate(), current));
            String best = null;
            AdvisorySeverity bestSeverity = null;

            // Upgrades first (closest-first) — ties with current severity are acceptable.
            for (String candidate : aboveWindow) {
                AdvisorySeverity candidateSeverity = AdvisoryClassifier.highest(
                        vulnerabilityProvider.vulnerabilities(component.coordinate(), candidate));
                if (candidateSeverity.ordinal() > currentSeverity.ordinal()) continue; // never regress
                if (bestSeverity == null || candidateSeverity.ordinal() < bestSeverity.ordinal()) {
                    best = candidate;
                    bestSeverity = candidateSeverity;
                }
            }
            // Downgrades only count if they strictly improve on both current and whatever
            // upgrade was already found — no free pass for ties in this direction.
            for (String candidate : belowWindow) {
                AdvisorySeverity candidateSeverity = AdvisoryClassifier.highest(
                        vulnerabilityProvider.vulnerabilities(component.coordinate(), candidate));
                if (candidateSeverity.ordinal() >= currentSeverity.ordinal()) continue;
                if (bestSeverity == null || candidateSeverity.ordinal() < bestSeverity.ordinal()) {
                    best = candidate;
                    bestSeverity = candidateSeverity;
                }
            }
            return best;
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
                          enforcer_use_verify boolean not null default false,
                          validation_maven_args varchar(1024) not null default '',
                          validation_env varchar(2048) not null default ''
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

                st.executeUpdate("""
                        create table if not exists rk_config (
                          config_key varchar(100) primary key,
                          config_value varchar(255) not null,
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
                st.executeUpdate("alter table projects add column if not exists validation_maven_args varchar(1024) not null default ''");
                st.executeUpdate("alter table projects add column if not exists validation_env varchar(2048) not null default ''");

            } catch (SQLException e) {
                throw new IllegalStateException("Failed to initialize schema", e);
            }
        }

        /** Inserts each configurable TTL's compiled-in default into rk_config, but only if that
         *  key has no row yet — never overwrites a value the user has already changed from the
         *  config page. Runs on every startup; idempotent after the first. */
        private void seedConfigDefaults() {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement(
                         "insert into rk_config (config_key, config_value) " +
                         "select ?, ? where not exists (select 1 from rk_config where config_key = ?)")) {
                for (ConfigTtlEntry entry : CONFIG_TTL_ENTRIES) {
                    ps.setString(1, entry.key());
                    ps.setString(2, Long.toString(entry.defaultValue().toMinutes()));
                    ps.setString(3, entry.key());
                    ps.addBatch();
                }
                ps.executeBatch();
            } catch (SQLException e) {
                LOGGER.warning(() -> "Failed to seed config defaults: " + e.getMessage());
            }
        }

        /** All rk_config rows as key -> value (minutes, as stored). Missing keys are simply
         *  absent from the map — callers fall back to the compiled-in default. */
        synchronized Map<String, String> loadConfigValues() throws SQLException {
            Map<String, String> values = new LinkedHashMap<>();
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement("select config_key, config_value from rk_config");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    values.put(rs.getString("config_key"), rs.getString("config_value"));
                }
            }
            return values;
        }

        synchronized void updateConfigValue(String key, String value) throws SQLException {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement(
                         "merge into rk_config (config_key, config_value, updated_at) key (config_key) values (?, ?, current_timestamp)")) {
                ps.setString(1, key);
                ps.setString(2, value);
                ps.executeUpdate();
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

    record ProjectEntry(String id, String name, String rootPath, Instant createdAt, Instant updatedAt,
                        String validationMavenArgs, String validationEnv) implements java.io.Serializable {
    }

    record ScanEntry(String id, String projectId, ScanInput input, ScanReport report, Instant createdAt) implements java.io.Serializable {
    }
}
