package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.core.service.SerializationSupport;
import com.redkite.maven.MavenProjectScanner;
import com.redkite.maven.MavenSettingsReader;
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

    private final Store store;
    private final HttpServer server;
    private final ConcurrentHashMap<String, ScanJob> scanJobs = new ConcurrentHashMap<>();

    private static final class ScanJob {
        enum Status { RUNNING, DONE, ERROR }
        volatile Status status = Status.RUNNING;
        volatile String message = "Starting…";
        volatile long scanId;
        volatile String errorMessage;
    }

    public RedKiteServerMain(String jdbcUrl, String dbUser, String dbPassword, int port) throws IOException {
        this.store = Store.connect(jdbcUrl, dbUser, dbPassword);
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.setExecutor(Executors.newCachedThreadPool());
        registerContexts();
    }

    public static void main(String[] args) throws Exception {
        String jdbcUrl = System.getProperty("redkite.db.url", "jdbc:h2:./data/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE");
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
        server.createContext("/api/metadata/clear", exchange -> safeHandle(exchange, this::handleApiMetadataClear));
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
        StringBuilder html = new StringBuilder();
        html.append(pageShellStart(BRAND, "Projects", "Local Maven dependency scans, version checks, and upgrade planning."));
        html.append("<div class=\"hero\">");
        html.append("<div><h1>RedKite</h1><p>Local dependency reporting and upgrade planning for checked-out Maven repositories.</p></div>");
        html.append("<div class=\"hero-actions\"><a class=\"button primary\" href=\"/projects\">Projects</a></div>");
        html.append("</div>");

        // Scan new project section
        html.append("<section class=\"card\" style=\"margin-bottom:18px\">");
        html.append("<h2>Scan project</h2>");
        html.append("<div class=\"scan-path-row\">");
        html.append("<input id=\"scan-path\" class=\"scan-path-input\" type=\"text\" placeholder=\"/full/path/to/project\" autocomplete=\"off\" spellcheck=\"false\" onkeydown=\"if(event.key==='Enter')startScan()\"/>");
        html.append("<button class=\"button primary\" type=\"button\" onclick=\"startScan()\">Scan</button>");
        html.append("</div>");
        html.append("<div id=\"scan-error\" class=\"scan-error\" style=\"display:none\"></div>");
        html.append("</section>");

        // Existing projects
        html.append("<section class=\"card\"><h2>Projects</h2><div class=\"list\">");
        try {
            for (ProjectEntry project : store.listProjects()) {
                html.append("<div class=\"list-row\">")
                        .append("<a href=\"/projects/").append(project.id()).append("\" class=\"list-row-link\">")
                        .append("<span class=\"list-title\">").append(escape(project.name())).append("</span>")
                        .append("<span class=\"list-meta\">").append(escape(project.rootPath())).append("</span>")
                        .append("</a>")
                        .append("<button class=\"button\" type=\"button\" onclick=\"triggerScan(").append(escape(jsString(project.rootPath()))).append(")\">Scan</button>")
                        .append("</div>");
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "Unable to list projects for dashboard: " + e.getMessage());
            html.append("<div class=\"result-row\"><div><strong>No project data</strong><div class=\"muted\">")
                    .append(escape(e.getMessage()))
                    .append("</div></div><div class=\"badge warn\">database</div></div>");
        }
        html.append("</div></section>");

        // Blocking overlay shown during scan
        html.append("<div id=\"scan-overlay\" class=\"scan-overlay\" style=\"display:none\">");
        html.append("<div class=\"scan-overlay-box\">");
        html.append("<div class=\"scan-spinner\"></div>");
        html.append("<span>Scanning&hellip;</span>");
        html.append("<span id=\"scan-status\" class=\"muted\" style=\"font-size:.88rem;max-width:480px;text-align:center\"></span>");
        html.append("</div>");
        html.append("</div>");

        html.append("<script>");
        html.append("function startScan(){var path=document.getElementById('scan-path').value.trim();if(!path){showScanError('Enter the full path to the project.');return;}hideScanError();triggerScan(path);}");
        html.append("function showScanError(msg){var el=document.getElementById('scan-error');if(el){el.textContent=msg;el.style.display='block';}}");
        html.append("function hideScanError(){var el=document.getElementById('scan-error');if(el){el.textContent='';el.style.display='none';}}");
        html.append("</script>");

        html.append(pageShellEnd());
        sendHtml(exchange, 200, html.toString());
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
            long projectId = Long.parseLong(parts[2]);
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendText(exchange, 405, "Method not allowed");
                return;
            }
            ProjectEntry project = store.getProject(projectId);
            ScanEntry scan = store.latestScanForProject(projectId);
            StringBuilder html = new StringBuilder();
            html.append(pageShellStart(BRAND, project.name(), "Project dashboard"));
            html.append("<div class=\"page-grid\">");
            html.append("<section class=\"card span-2\"><h1>").append(escape(project.name())).append("</h1><p class=\"muted\">").append(escape(project.rootPath())).append("</p></section>");
            html.append("<section class=\"card\">");
            html.append("<h2>Actions</h2>");
            if (scan != null) {
                html.append("<a class=\"button primary\" href=\"/scans/").append(scan.id()).append("\">View latest scan</a>");
            } else {
                html.append("<p class=\"muted\">No scans yet.</p>");
            }
            html.append("</section>");
            if (scan != null) {
                ScanReport report = scan.report();
                html.append("<section class=\"card\"><h2>Latest scan</h2>");
                html.append(statGrid(
                        statCard("Scan", String.valueOf(scan.id())),
                        statCard("Components", String.valueOf(report.components().size())),
                        statCard("Recommendations", String.valueOf(report.recommendations().size())),
                        statCard("Metadata", report.complete() ? "Complete" : "Incomplete")));
                html.append("<p class=\"muted\">").append(escape(report.completenessMessage())).append("</p>");
                html.append("</section>");
            }
            html.append("</div>");
            html.append(pageShellEnd());
            sendHtml(exchange, 200, html.toString());
            return;
        }
        sendText(exchange, 404, "Not found");
    }

    private void handleScans(HttpExchange exchange) throws IOException {
        URI uri = exchange.getRequestURI();
        String[] parts = uri.getPath().split("/");
        if (parts.length == 3) {
            long scanId = Long.parseLong(parts[2]);
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
            StringBuilder html = new StringBuilder();
            html.append(pageShellStart(BRAND, "Scan report", "Dependency inventory and upgrade recommendations."));
            html.append("<div class=\"page-grid\">");
            html.append("<section class=\"card span-2\"><div class=\"headline\">");
            html.append("<div><p class=\"eyebrow\">Scan ").append(report.scanId()).append("</p><h1>Scan report</h1></div>");
            html.append("<div style=\"display:flex;align-items:center;gap:10px\">");
            html.append(report.complete() ? "<span class=\"badge success\">Complete</span>" : "<span class=\"badge warn\">Incomplete</span>");
            html.append("<button class=\"button\" type=\"button\" onclick=\"triggerScan(").append(escape(jsString(projectPath))).append(")\">Rescan</button>");
            html.append("<button class=\"button\" type=\"button\" onclick=\"triggerFreshScan(").append(escape(jsString(projectPath))).append(")\" title=\"Clear version metadata cache then rescan\">Rescan (fresh)</button>");
            html.append("</div>");
            html.append("</div><p class=\"muted\">").append(escape(report.completenessMessage())).append("</p>");
            html.append("<details style=\"margin-top:8px;font-size:.85rem\"><summary style=\"color:var(--muted);cursor:pointer\">Maven repositories</summary>");
            if (store.mavenSettingsPath != null) {
                html.append("<p style=\"margin:6px 0 2px;color:var(--muted);font-family:monospace\">").append(escape(store.mavenSettingsPath)).append("</p>");
            }
            html.append("<ul style=\"margin:4px 0 0 1.2em;padding:0\">");
            for (String repo : store.effectiveMavenRepos) {
                html.append("<li style=\"font-family:monospace\">").append(escape(repo)).append("</li>");
            }
            html.append("</ul></details>");
            html.append("<div id=\"scan-error\" class=\"scan-error\" style=\"display:none;margin-top:12px\"></div>");
            html.append("</section>");
            html.append("<section class=\"card span-2\">");
            html.append(renderRemediationView(report, scanId, !sourcePoms.isEmpty(), moduleArtifactIds));
            html.append("</section>");
            html.append("</div>");
            html.append("<div id=\"scan-overlay\" class=\"scan-overlay\" style=\"display:none\"><div class=\"scan-overlay-box\"><div class=\"scan-spinner\"></div><span>Scanning&hellip;</span><span id=\"scan-status\" class=\"muted\" style=\"font-size:.88rem;max-width:480px;text-align:center\"></span></div></div>");
            html.append(pageShellEnd());
            sendHtml(exchange, 200, html.toString());
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
                Consumer<String> progress = msg -> job.message = msg;
                store.reconfigureForProject(projectRoot);
                ScanInput input = new MavenProjectScanner().scan(projectRoot, progress);
                ScanReport report = store.ingest(input, progress);
                job.scanId = report.scanId();
                job.status = ScanJob.Status.DONE;
            } catch (Throwable e) {
                job.errorMessage = causeChain(e);
                job.status = ScanJob.Status.ERROR;
            }
        }, "redkite-scan-" + jobId).start();
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
            case RUNNING -> sendJson(exchange, 200, "{\"status\":\"running\",\"message\":" + jsonStr(job.message) + "}");
            case DONE -> {
                scanJobs.remove(jobId);
                sendJson(exchange, 200, "{\"status\":\"done\",\"scanId\":" + job.scanId + "}");
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

    private void handleApiMetadataClear(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        store.versionProvider.clearAll();
        sendJson(exchange, 200, "{\"cleared\":true}");
    }

    private void handleApiScanPom(HttpExchange exchange) throws IOException {
        String scanIdParam = queryParam(exchange.getRequestURI().getQuery(), "scanId");
        if (scanIdParam == null) { sendText(exchange, 400, "Missing scanId"); return; }
        long scanId;
        try { scanId = Long.parseLong(scanIdParam); } catch (NumberFormatException e) { sendText(exchange, 400, "Bad scanId"); return; }

        if ("POST".equals(exchange.getRequestMethod())) {
            Map<String, String> updates = parseForm(readBody(exchange));
            if (updates.isEmpty()) { sendText(exchange, 400, "No updates"); return; }
            try {
                ScanEntry scan = store.getScan(scanId);
                Map<String, String> sourcePoms = store.loadSourcePoms(scanId);
                Map<String, String> patchedFiles = generatePomPatches(scan.report(), sourcePoms, scan.input().workingTreePath(), updates);
                if (patchedFiles.isEmpty()) { sendText(exchange, 400, "No matching source POMs for the selected components"); return; }
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

    private Map<String, String> generatePomPatches(ScanReport report, Map<String, String> sourcePoms, String workingTreePath, Map<String, String> rawUpdates) throws Exception {
        // rawUpdates keys are component IDs (from the client) — resolve each to its exact component
        Map<Long, String> updateById = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : rawUpdates.entrySet()) {
            try { updateById.put(Long.parseLong(e.getKey()), e.getValue()); } catch (NumberFormatException ignored) {}
        }
        Map<String, List<ScanComponent>> byFile = new LinkedHashMap<>();
        for (ScanComponent c : report.components()) {
            if (!c.direct() || c.snapshot() || c.sourceFilePath() == null) continue;
            if (!updateById.containsKey(c.id())) continue;
            byFile.computeIfAbsent(c.sourceFilePath(), k -> new ArrayList<>()).add(c);
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<ScanComponent>> entry : byFile.entrySet()) {
            String content = sourcePoms.get(entry.getKey());
            if (content == null) continue;
            Map<String, String> fileUpdates = new LinkedHashMap<>();
            for (ScanComponent c : entry.getValue()) {
                String coord = c.coordinate().groupId() + ":" + c.coordinate().artifactId();
                fileUpdates.put(coord, updateById.get(c.id()));
            }
            result.put(entry.getKey(), patchPomXml(content, fileUpdates));
        }
        return result;
    }

    private static String patchPomXml(String content, Map<String, String> versionUpdates) throws Exception {
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(content)));
        Element root = doc.getDocumentElement();

        // Find or create <properties> as a direct child of root
        Element propertiesEl = null;
        for (int i = 0; i < root.getChildNodes().getLength(); i++) {
            Node n = root.getChildNodes().item(i);
            if (n instanceof Element e && "properties".equals(e.getNodeName())) {
                propertiesEl = e;
                break;
            }
        }
        if (propertiesEl == null) {
            propertiesEl = doc.createElement("properties");
            // Insert before <dependencyManagement> or <dependencies> or <build>, else append
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
        }

        // Pre-populate known property→version from existing <properties> children
        Map<String, String> propToVersion = new LinkedHashMap<>();
        for (int i = 0; i < propertiesEl.getChildNodes().getLength(); i++) {
            Node n = propertiesEl.getChildNodes().item(i);
            if (n instanceof Element e) propToVersion.put(e.getNodeName(), e.getTextContent().trim());
        }

        // Process every <dependency> element
        NodeList allVersionedElements = doc.getElementsByTagName("*");
        List<Element> patchTargets = new ArrayList<>();
        for (int i = 0; i < allVersionedElements.getLength(); i++) {
            Node n = allVersionedElements.item(i);
            if (n instanceof Element e && ("dependency".equals(e.getNodeName()) || "plugin".equals(e.getNodeName()))) {
                patchTargets.add(e);
            }
        }
        for (Element dep : patchTargets) {
            String g = childText(dep, "groupId");
            String a = childText(dep, "artifactId");
            if (g == null || a == null) continue;
            if ("plugin".equals(dep.getNodeName()) && g.trim().isEmpty()) g = "org.apache.maven.plugins";
            g = g.trim(); a = a.trim();
            String coord = g + ":" + a;

            // Find <version> child node
            Node versionNode = null;
            for (int j = 0; j < dep.getChildNodes().getLength(); j++) {
                Node child = dep.getChildNodes().item(j);
                if ("version".equals(child.getNodeName())) { versionNode = child; break; }
            }
            if (versionNode == null) {
                // No explicit version (BOM-managed): only add one when upgrading
                String upgrade = versionUpdates.get(coord);
                if (upgrade != null) {
                    String propName = a + ".version";
                    if (propToVersion.containsKey(propName) && !propToVersion.get(propName).equals(upgrade)) {
                        propName = g + "." + a + ".version";
                    }
                    setProperty(doc, propertiesEl, propName, upgrade);
                    propToVersion.put(propName, upgrade);
                    Element versionEl = doc.createElement("version");
                    versionEl.setTextContent("${" + propName + "}");
                    dep.appendChild(versionEl);
                }
                continue;
            }
            String versionText = versionNode.getTextContent().trim();
            if (versionText.isEmpty()) continue;

            String upgrade = versionUpdates.get(coord);

            if (versionText.startsWith("${") && versionText.endsWith("}")) {
                // Already a property reference — update the property value if upgrading
                if (upgrade != null) {
                    String propName = versionText.substring(2, versionText.length() - 1);
                    setProperty(doc, propertiesEl, propName, upgrade);
                    propToVersion.put(propName, upgrade);
                }
            } else {
                // Literal version — normalise to a named property
                String effectiveVersion = upgrade != null ? upgrade : versionText;
                String propName = a + ".version";
                // Conflict: same name already used for a different version
                if (propToVersion.containsKey(propName) && !propToVersion.get(propName).equals(effectiveVersion)) {
                    propName = g + "." + a + ".version";
                }
                setProperty(doc, propertiesEl, propName, effectiveVersion);
                propToVersion.put(propName, effectiveVersion);
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
            boolean canUpgradeViaDirect) {}

    private String renderRemediationView(ScanReport report, long scanId, boolean pomExists, Map<String, String> moduleArtifactIds) {
        ReportSummary summary = RemediationClassifier.summarize(report);
        List<ScanComponent> components = report.components();
        if (components.isEmpty()) {
            return "<p class=\"muted\">No dependency inventory is available for this scan.</p>";
        }

        // Build lookup maps
        Map<Long, UpgradeRecommendation> recByComponent = new LinkedHashMap<>();
        for (UpgradeRecommendation rec : report.recommendations()) {
            if (!rec.affectedComponentIds().isEmpty()) {
                recByComponent.put(rec.affectedComponentIds().get(0), rec);
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
            views.add(new ComponentView(c, status, versionMeta, rec, vulns, canUpgradeViaDirect));
        }

        // Sort: CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN advisory → SNAPSHOT → STALE → VERSION_MGMT → UPGRADE → CLEAN
        // Within same bucket: direct before transitive, then alphabetical
        views.sort((a, b) -> {
            int ka = remediationSortKey(a.component(), a.status());
            int kb = remediationSortKey(b.component(), b.status());
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
                    .filter(m -> !byModule.getOrDefault(m, List.of()).isEmpty())
                    .findFirst()
                    .orElse(moduleOrder.get(0));
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

        // Filter toggle: CVE | Snapshot | Upgrade | Transitive | Clean | All
        long cveCount = views.stream().filter(v -> v.status().hasVulnerability()).count();
        long snapshotCount = views.stream().filter(v -> v.status().isSnapshot()).count();
        long upgradeCount = views.stream().filter(v -> v.status().needsRemediation() && !v.status().hasVulnerability() && !v.status().isSnapshot()).count();
        long transitiveCount = views.stream().filter(v -> !v.component().direct() && !v.component().snapshot()).count();
        long cleanCount = views.stream().filter(v -> !v.status().needsRemediation()).count();
        html.append("<div class=\"rem-toggle\">");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"cve\" onclick=\"setRemediationMode('cve')\">CVE <span class=\"tab-count\">").append(cveCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"snapshot\" onclick=\"setRemediationMode('snapshot')\">Snapshot <span class=\"tab-count\">").append(snapshotCount).append("</span></button>");
        html.append("<button class=\"button primary rem-toggle-btn\" type=\"button\" data-mode=\"upgrade\" onclick=\"setRemediationMode('upgrade')\">Upgrade <span class=\"tab-count\">").append(upgradeCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"transitive\" onclick=\"setRemediationMode('transitive')\">Transitive <span class=\"tab-count\">").append(transitiveCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"clean\" onclick=\"setRemediationMode('clean')\">Clean <span class=\"tab-count\">").append(cleanCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"all\" onclick=\"setRemediationMode('all')\">All <span class=\"tab-count\">").append(views.size()).append("</span></button>");
        html.append("</div>");

        // Apply bar
        html.append("<div class=\"pom-actions\">");
        html.append("<button class=\"button primary\" type=\"button\"");
        if (!pomExists) html.append(" disabled title=\"No source POMs available for this scan\"");
        html.append(" onclick=\"applyPomChanges()\">Apply</button>");
        html.append("</div>");

        // Emit component index + edge map for client-side tree expansion
        html.append("<script>const rk_scanId=").append(scanId).append(";const rk_comps={");
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
                .append("\"kind\":").append(jsonStr(c.snapshot() ? "snapshot" : c.direct() ? "direct" : "transitive")).append(",")
                .append("\"clean\":").append(!s.needsRemediation()).append(",")
                .append("\"hasvuln\":").append(s.hasVulnerability())
                .append("}");
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
        html.append("};</script>");

        // Component cards
        html.append("<div class=\"rem-list\">");
        for (ComponentView view : views) {
            String mod = view.component().modulePath() == null || view.component().modulePath().isBlank()
                    ? "(root)" : view.component().modulePath();
            boolean hasParents = !parentIdsByChild.getOrDefault(view.component().id(), List.of()).isEmpty();
            html.append(renderComponentCard(view, mod, hasParents));
        }
        html.append("</div>");

        // POM preview modal
        html.append("<div id=\"pom-modal\" class=\"pom-modal\" style=\"display:none\">");
        html.append("<div class=\"pom-modal-backdrop\" onclick=\"closePomModal()\"></div>");
        html.append("<div class=\"pom-modal-box\">");
        html.append("<div class=\"pom-modal-head\">");
        html.append("<span id=\"pom-modal-filename\" class=\"pom-modal-filename\"></span>");
        html.append("<div style=\"display:flex;gap:8px;flex-shrink:0\">");
        html.append("<button class=\"button\" type=\"button\" onclick=\"copyPomContent()\">Copy</button>");
        html.append("<button class=\"button\" type=\"button\" onclick=\"closePomModal()\">Close</button>");
        html.append("</div></div>");
        html.append("<div class=\"pom-modal-body\"><pre id=\"pom-modal-content\"></pre></div>");
        html.append("</div></div>");

        return html.toString();
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

    private String renderComponentCard(ComponentView view, String module, boolean hasChildren) {
        ScanComponent comp = view.component();
        RemediationStatus status = view.status();
        boolean clean = !status.needsRemediation();
        String coordStr = comp.coordinate().groupId() + ":" + comp.coordinate().artifactId();

        StringBuilder html = new StringBuilder();
        String kind = comp.snapshot() ? "snapshot" : comp.direct() ? "direct" : "transitive";
        boolean upgradeOnly = status.hasUpgradeRecommendation()
                && !status.hasVulnerability() && !status.isSnapshot()
                && !status.hasDeclaredVersionDeclaration() && !status.hasStaleMetadata();
        html.append("<div class=\"rem-card").append(clean ? " clean" : "").append("\" data-clean=\"").append(clean)
                .append("\" data-module=\"").append(escape(module))
                .append("\" data-kind=\"").append(kind)
                .append("\" data-hasvuln=\"").append(status.hasVulnerability())
                .append("\" data-upgradeonly=\"").append(upgradeOnly)
                .append("\" data-coord=\"").append(escape(coordStr))
                .append("\" data-comp-id=\"").append(comp.id()).append("\">");

        // Header: coordinate + badges
        html.append("<div class=\"rem-header\">");
        html.append("<span class=\"rem-title\">").append(escape(coordStr)).append("</span>");
        html.append("<div class=\"rem-badges\">");
        html.append(severityBadgeHtml(status.highestSeverity(), clean));
        String kindClass = comp.snapshot() ? "warn" : comp.direct() ? "success" : "neutral";
        String kindLabel = comp.snapshot() ? "snapshot" : comp.direct() ? "direct" : "transitive";
        html.append("<span class=\"badge ").append(kindClass).append("\">").append(kindLabel).append("</span>");
        html.append("<span class=\"badge neutral\">").append(comp.scope().name().toLowerCase()).append("</span>");
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
                .filter(r -> !"Upgrade available".equals(r)).toList();
        boolean showUpgradeBtn = view.recommendation() != null && !status.isSnapshot();
        if (!otherReasons.isEmpty() || showUpgradeBtn) {
            html.append("<div class=\"rem-reasons\">");
            for (String reason : otherReasons) {
                html.append("<span class=\"reason-chip\">").append(escape(reason)).append("</span>");
            }
            if (showUpgradeBtn) {
                if (comp.direct()) {
                    html.append("<button class=\"reason-chip reason-chip-btn\" type=\"button\" onclick=\"applyUpgrade(")
                        .append(comp.id()).append(",'").append(escape(view.recommendation().targetVersion())).append("',this)\">")
                        .append("Upgrade available</button>");
                } else {
                    String transitiveChip = view.canUpgradeViaDirect() ? "Upgradable via direct" : "Needs major bump on direct";
                    html.append("<span class=\"reason-chip\">").append(transitiveChip).append("</span>");
                }
            }
            html.append("</div>");
        }

        // Version selector for direct deps only; transitive deps cannot be edited in the POM
        if (!clean && view.versionMetadata() != null) {
            html.append("<div class=\"rem-actions\">");
            if (comp.direct()) {
                String selectorId = "view_" + comp.id();
                String selectedVersion = view.recommendation() != null
                        ? view.recommendation().targetVersion() : comp.version();
                html.append(renderVersionSelect(selectorId, comp.coordinate(), comp.version(), selectedVersion,
                        view.versionMetadata(), view.recommendation(), view.findings(), false));
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

    private int remediationSortKey(ScanComponent component, RemediationStatus status) {
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
            List<VulnerabilityFinding> vulnFindings, boolean includeNameAttr) {
        List<String> choices = versionChoices(versionMetadata, recommendation);
        // Build deduplicated ordered set: recommended first, then choices, then latest
        LinkedHashSet<String> ordered = new LinkedHashSet<>();
        if (recommendation != null && recommendation.targetVersion() != null && !recommendation.targetVersion().isBlank()) {
            ordered.add(recommendation.targetVersion());
        }
        ordered.addAll(choices);
        if (versionMetadata != null && versionMetadata.latestVersion() != null
                && !versionMetadata.latestVersion().isBlank()
                && !"unknown".equalsIgnoreCase(versionMetadata.latestVersion())
                && !isPreRelease(versionMetadata.latestVersion())) {
            ordered.add(versionMetadata.latestVersion());
        }

        if (ordered.isEmpty()) {
            return "<span class=\"version-note muted\">No upgrade candidates</span>";
        }

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

        String nameAttr = includeNameAttr ? " name=\"" + escape(selectorId) + "\"" : "";
        html.append("<select class=\"version-sel\" id=\"").append(escape(selectorId)).append("\"").append(nameAttr)
                .append(" onchange=\"this.dataset.chosen='true'\">");
        // Blank placeholder — dep is only included in Apply when the user explicitly picks a version
        html.append("<option value=\"\" selected>Select version…</option>");
        for (String version : ordered) {
            boolean hasCve = hasCveForVersion(coordinate, version, vulnFindings);
            String label = buildVersionOptionLabel(version, recommendedVersion, latestVersion, latestSameMajor,
                    recommendation != null ? recommendation.reason() : null, hasCve, currentVersion);
            html.append("<option value=\"").append(escape(version)).append("\"")
                    .append(">").append(escape(label)).append("</option>");
        }
        html.append("</select>");
        html.append("</div>");
        return html.toString();
    }

    private String buildVersionOptionLabel(String version, String recommendedVersion, String latestVersion,
            String latestSameMajor, RecommendationReason reason, boolean hasCve, String currentVersion) {
        List<String> tags = new ArrayList<>();
        if (version.equals(recommendedVersion)) {
            tags.add("recommended");
            if (reason == RecommendationReason.CVE_FIX) tags.add("fixes CVE");
        }
        if (version.equals(latestVersion)) tags.add("latest");
        if (version.equals(latestSameMajor) && !version.equals(latestVersion)) {
            tags.add(sameMajorMinor(version, currentVersion) ? "latest same minor" : "latest same major");
        }
        if (hasCve) tags.add("vulnerable");
        if (version.contains("-SNAPSHOT") || version.contains("-alpha") || version.contains("-beta") || version.contains("-rc")) {
            tags.add("pre-release");
        }
        return tags.isEmpty() ? version : version + " — " + String.join(", ", tags);
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
        html.append("<button class=\"button inventory-tab\" type=\"button\" data-kind=\"direct\" onclick=\"filterInventoryKind('direct')\">Direct <span class=\"tab-count\">").append(directCount).append("</span></button>");
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
                String kind = component.snapshot() ? "snapshot" : (component.direct() ? "direct" : "transitive");
                html.append("<div class=\"inventory-row\" data-kind=\"").append(kind).append("\">");
                html.append("<div class=\"inventory-main\">");
                html.append("<div class=\"inventory-title\">").append(escape(component.coordinate().groupId() + ":" + component.coordinate().artifactId())).append("</div>");
                html.append("<div class=\"inventory-subtitle\">current ").append(escape(component.version())).append("</div>");
                html.append(renderVersionButtonGroup(component.coordinate(), component.version(), component.id(), versionMetadata, recommendation, versionChoices(versionMetadata, recommendation), recommendation == null ? component.version() : recommendation.targetVersion(), vulnerabilitiesByComponent.get(component.coordinate().groupId() + ":" + component.coordinate().artifactId() + "@" + component.version()), false));
                html.append("</div>");
                html.append("<div class=\"inventory-badges\">");
                html.append("<span class=\"badge ").append(component.snapshot() ? "warn" : component.direct() ? "success" : "neutral").append("\">");
                html.append(component.snapshot() ? "snapshot" : component.direct() ? "direct" : "transitive");
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
        html.append(component.direct() ? "direct" : "transitive");
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

    private String pageShellStart(String brand, String title, String subtitle) {
        return "<html><head><meta charset=\"utf-8\"/>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
                + "<title>" + escape(brand) + " - " + escape(title) + "</title>"
                + "<style>"
                + ":root { color-scheme: dark; --bg:#0b1020; --panel:#121a32; --panel-2:#18213d; --text:#eef2ff; --muted:#a7b0d4; --line:#263252; --accent:#7dd3fc; --accent-2:#a78bfa; --good:#34d399; --warn:#fbbf24; }"
                + "* { box-sizing:border-box; }"
                + "body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; background: radial-gradient(circle at top left, rgba(125,211,252,.15), transparent 28%), linear-gradient(180deg, #070b16, var(--bg)); color:var(--text); }"
                + "a { color:inherit; text-decoration:none; }"
                + ".shell { width: 100%; max-width: 1400px; margin: 0 auto; padding: 28px 32px 48px; box-sizing: border-box; }"
                + ".topbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; gap:20px; }"
                + ".brand { display:flex; align-items:center; gap:12px; }"
                + ".brand-mark { width:44px; height:44px; display:inline-flex; align-items:center; justify-content:center; border-radius:14px; background: rgba(255,255,255,.04); border:1px solid var(--line); overflow:hidden; flex:0 0 auto; }"
                + ".brand-mark img { width:100%; height:100%; display:block; }"
                + ".brand-copy { display:flex; flex-direction:column; gap:4px; }"
                + ".brand-copy strong { letter-spacing:.12em; text-transform:uppercase; font-size:.76rem; color:var(--accent); }"
                + ".brand-copy span { font-size:1.15rem; color:var(--text); }"
                + ".nav { display:flex; gap:12px; flex-wrap:wrap; }"
                + ".nav a, .button { padding:10px 14px; border:1px solid var(--line); border-radius:14px; background: rgba(18,26,50,.72); }"
                + ".nav a:hover, .button:hover { border-color: rgba(125,211,252,.5); transform: translateY(-1px); }"
                + ".button.primary { background: linear-gradient(135deg, var(--accent), var(--accent-2)); color:#08111f; font-weight:700; border-color: transparent; }"
                + ".hero { display:flex; justify-content:space-between; align-items:flex-end; gap:24px; margin:18px 0 28px; padding:28px; border:1px solid var(--line); border-radius:24px; background: linear-gradient(135deg, rgba(18,26,50,.95), rgba(15,22,41,.95)); box-shadow: 0 18px 60px rgba(0,0,0,.25); }"
                + ".hero h1, h1 { margin:0; font-size: clamp(2rem, 3vw, 3.5rem); }"
                + ".hero p, p { line-height:1.6; color:var(--muted); }"
                + ".hero-actions { display:flex; gap:12px; flex-wrap:wrap; }"
                + ".page-grid { display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap:18px; }"
                + ".span-2 { grid-column: span 2; }"
                + ".card { padding:20px; border:1px solid var(--line); border-radius:22px; background: linear-gradient(180deg, rgba(18,26,50,.92), rgba(13,20,39,.92)); box-shadow: 0 12px 40px rgba(0,0,0,.18); }"
                + ".card h2 { margin-top:0; font-size:1rem; letter-spacing:.04em; text-transform:uppercase; color:var(--accent); }"
                + ".headline { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:14px; }"
                + ".eyebrow { margin:0 0 6px; color:var(--accent); text-transform:uppercase; letter-spacing:.16em; font-size:.72rem; }"
                + ".muted { color:var(--muted); }"
                + ".subhead { margin: 0 0 12px; }"
                + ".mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }"
                + ".stack { display:flex; flex-direction:column; gap:12px; }"
                + ".list { display:flex; flex-direction:column; gap:12px; }"
                + ".list-row, .result-row { display:flex; justify-content:space-between; align-items:center; gap:16px; padding:14px 16px; border:1px solid var(--line); border-radius:18px; background: rgba(255,255,255,.02); }"
                + ".list-row:hover, .result-row:hover { border-color: rgba(125,211,252,.45); }"
                + ".list-row-link { flex:1; display:flex; flex-direction:column; gap:2px; min-width:0; }"
                + ".list-title { display:block; font-weight:700; margin-bottom:4px; }"
                + ".list-meta { display:block; color:var(--muted); font-size:.95rem; }"
                + ".inventory-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:14px; }"
                + ".inventory-tabs { display:flex; flex-wrap:wrap; gap:10px; grid-column: 1 / -1; margin-bottom:6px; }"
                + ".inventory-tab { cursor:pointer; display:inline-flex; gap:8px; align-items:center; }"
                + ".inventory-tab.active { border-color: rgba(125,211,252,.55); box-shadow: inset 0 0 0 1px rgba(125,211,252,.18); }"
                + ".tab-count { display:inline-flex; align-items:center; justify-content:center; min-width: 1.7rem; padding:2px 8px; border-radius:999px; background: rgba(255,255,255,.08); color: var(--text); font-size:.82rem; }"
                + ".inventory-group { padding:16px; border:1px solid var(--line); border-radius:20px; background: rgba(255,255,255,.02); }"
                + ".inventory-header { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; margin-bottom:14px; }"
                + ".inventory-header h3 { margin:0; font-size:1.05rem; color:var(--text); text-transform:none; }"
                + ".inventory-items { display:flex; flex-direction:column; gap:12px; }"
                + ".inventory-row { padding:14px 14px 12px; border:1px solid var(--line); border-radius:18px; background: rgba(255,255,255,.02); }"
                + ".inventory-main { display:flex; flex-direction:column; gap:4px; }"
                + ".inventory-title { font-weight:700; font-size:1rem; }"
                + ".inventory-subtitle { color:var(--muted); }"
                + ".inventory-meta { color:var(--muted); font-size:.9rem; }"
                + ".inventory-badges { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }"
                + ".inventory-note { margin-top:10px; color:var(--muted); font-size:.92rem; }"
                + ".badge { display:inline-flex; align-items:center; justify-content:center; padding:6px 10px; border-radius:999px; border:1px solid var(--line); background: rgba(255,255,255,.04); font-size:.78rem; letter-spacing:.06em; text-transform:uppercase; }"
                + ".badge.success { background: rgba(52,211,153,.16); border-color: rgba(52,211,153,.35); color: #9ef2c8; }"
                + ".badge.warn { background: rgba(251,191,36,.16); border-color: rgba(251,191,36,.35); color: #fde68a; }"
                + ".badge.neutral { background: rgba(167,139,250,.12); border-color: rgba(167,139,250,.25); color: #d8c8ff; }"
                + ".stat-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:12px; }"
                + ".stat { padding:14px; border:1px solid var(--line); border-radius:18px; background: rgba(255,255,255,.02); }"
                + ".stat strong { display:block; font-size:1.4rem; margin-top:6px; }"
                + ".tree, .tree ul { list-style:none; margin:0; padding-left:18px; }"
                + ".tree-node { margin:12px 0; }"
                + ".tree-card { padding:14px 16px; border:1px solid var(--line); border-radius:18px; background: rgba(255,255,255,.02); }"
                + ".tree-meta { margin-top:10px; color:var(--muted); font-size:.92rem; }"
                + ".selectable { cursor:pointer; width:100%; text-align:left; }"
                + ".selectable input { transform: translateY(1px); margin-right:8px; }"
                + ".selectable-target { display:flex; flex-direction:column; gap:6px; flex: 1 1 auto; }"
                + ".upgrade-choice { display:flex; flex-direction:column; gap:8px; min-width: 13rem; }"
                + ".upgrade-choice select { width:100%; padding:10px 12px; border-radius:12px; border:1px solid var(--line); background: rgba(8,15,30,.9); color: var(--text); }"
                + ".version-selector { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-top:8px; }"
                + ".version-label { color:var(--muted); font-size:.85rem; text-transform:uppercase; letter-spacing:.08em; }"
                + ".version-choice { display:inline-flex; align-items:center; gap:6px; padding:7px 10px; border-radius:999px; border:1px solid var(--line); background: rgba(255,255,255,.04); color:var(--text); }"
                + ".version-choice.current { opacity:.8; }"
                + ".version-choice.active { border-color: rgba(125,211,252,.65); background: rgba(125,211,252,.15); color: #d9f5ff; }"
                + ".version-choice.cve { border-color: rgba(248,113,113,.6); }"
                + ".version-choice .pill { display:inline-flex; align-items:center; justify-content:center; padding:2px 7px; border-radius:999px; background: rgba(255,255,255,.12); font-size:.72rem; text-transform:uppercase; }"
                + ".footer { margin-top:24px; color:var(--muted); font-size:.9rem; }"
                + ".inventory-group.is-hidden, .inventory-row.is-hidden { display:none; }"
                + ".rem-banner { padding:14px 18px; border:1px solid var(--line); border-radius:18px; background:rgba(255,255,255,.02); margin-bottom:16px; display:flex; flex-direction:column; gap:10px; }"
                + ".rem-banner-row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }"
                + ".rem-stat { font-size:.95rem; } .rem-stat strong { font-size:1.1rem; }"
                + ".sev-chip { display:inline-flex; align-items:center; gap:5px; padding:4px 10px; border-radius:999px; font-size:.8rem; font-weight:600; }"
                + ".sev-chip.sev-critical,.sev-badge.sev-critical { background:rgba(220,38,38,.2); border:1px solid rgba(220,38,38,.45); color:#fca5a5; }"
                + ".sev-chip.sev-high,.sev-badge.sev-high { background:rgba(234,88,12,.2); border:1px solid rgba(234,88,12,.45); color:#fdba74; }"
                + ".sev-chip.sev-medium,.sev-badge.sev-medium { background:rgba(234,179,8,.18); border:1px solid rgba(234,179,8,.4); color:#fde68a; }"
                + ".sev-chip.sev-low,.sev-badge.sev-low { background:rgba(59,130,246,.18); border:1px solid rgba(59,130,246,.35); color:#93c5fd; }"
                + ".sev-chip.sev-unknown,.sev-badge.sev-unknown { background:rgba(107,114,128,.18); border:1px solid rgba(107,114,128,.4); color:#d1d5db; }"
                + ".sev-chip.sev-none,.sev-badge.sev-none { background:rgba(52,211,153,.12); border:1px solid rgba(52,211,153,.3); color:#6ee7b7; }"
                + ".sev-chip.sev-snap { background:rgba(139,92,246,.18); border:1px solid rgba(139,92,246,.4); color:#c4b5fd; }"
                + ".sev-chip.sev-stale { background:rgba(75,85,99,.18); border:1px solid rgba(75,85,99,.4); color:#9ca3af; }"
                + ".rem-module-select { padding:8px 14px; border-radius:14px; border:1px solid var(--line); background:rgba(18,26,50,.9); color:var(--text); font-size:.9rem; cursor:pointer; outline:none; margin-bottom:12px; }"
                + ".rem-module-select:focus { border-color:rgba(125,211,252,.55); }"
                + ".rem-toggle { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:16px; }"
                + ".pom-actions { display:flex; gap:10px; align-items:center; margin-bottom:20px; }"
                + ".rem-list { display:flex; flex-direction:column; gap:10px; }"
                + ".rem-card { padding:15px 18px; border:1px solid var(--line); border-radius:20px; background:rgba(255,255,255,.02); display:flex; flex-direction:column; gap:9px; }"
                + ".rem-card.clean { opacity:.7; }"
                + ".rem-header { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }"
                + ".rem-title { font-weight:700; font-size:1rem; font-family:ui-monospace,monospace; }"
                + ".rem-badges { display:flex; flex-wrap:wrap; gap:6px; align-items:center; }"
                + ".sev-badge { display:inline-flex; align-items:center; gap:4px; padding:4px 10px; border-radius:999px; font-size:.82rem; font-weight:700; }"
                + ".rem-meta { font-size:.93rem; color:var(--muted); display:flex; flex-wrap:wrap; gap:10px; align-items:center; }"
                + ".rem-meta strong { color:var(--text); }"
                + ".card-expand-row { display:flex; justify-content:flex-end; margin-top:8px; }"
                + ".card-expand-btn { width:24px; height:24px; border-radius:50%; background:none; border:1px solid var(--line); color:var(--muted); cursor:pointer; font-size:.9rem; line-height:1; padding:0; transition:all .15s; }"
                + ".card-expand-btn:hover { border-color:var(--accent); color:var(--accent); }"
                + ".dep-tree-panel { margin-top:12px; padding-top:12px; border-top:1px solid var(--line); display:flex; flex-direction:column; gap:8px; }"
                + ".sub-card { padding:10px 14px; border:1px solid var(--line); border-radius:14px; background:rgba(255,255,255,.015); }"
                + ".card-highlight { outline:2px solid var(--accent) !important; outline-offset:3px; }"
                + ".rem-cves { font-size:.85rem; color:var(--muted); font-family:ui-monospace,monospace; word-break:break-all; }"
                + ".rem-reasons { display:flex; flex-wrap:wrap; gap:6px; }"
                + ".reason-chip { padding:3px 9px; border-radius:999px; border:1px solid rgba(167,139,250,.3); background:rgba(167,139,250,.1); color:#d8c8ff; font-size:.78rem; }"
                + ".reason-chip-btn { cursor:pointer; transition:border-color .15s,background .15s; }"
                + ".reason-chip-btn:hover { border-color:rgba(167,139,250,.7); background:rgba(167,139,250,.22); }"
                + ".reason-chip-btn.selected { background:rgba(167,139,250,.35); border-color:rgba(167,139,250,.8); color:#ede9fe; }"
                + ".rem-actions { display:flex; flex-wrap:wrap; gap:8px; align-items:center; padding-top:2px; }"
                + ".action-btn { display:inline-flex; align-items:center; padding:7px 15px; border-radius:12px; font-size:.86rem; font-weight:600; border:1px solid transparent; cursor:pointer; text-decoration:none; }"
                + ".action-btn:hover { filter:brightness(1.12); }"
                + ".action-btn.sev-critical { background:rgba(220,38,38,.25); color:#fca5a5; border-color:rgba(220,38,38,.45); }"
                + ".action-btn.sev-high { background:rgba(234,88,12,.25); color:#fdba74; border-color:rgba(234,88,12,.45); }"
                + ".action-btn.sev-medium { background:rgba(234,179,8,.2); color:#fde68a; border-color:rgba(234,179,8,.4); }"
                + ".action-btn.sev-low { background:rgba(59,130,246,.2); color:#93c5fd; border-color:rgba(59,130,246,.35); }"
                + ".action-btn.sev-unknown { background:rgba(107,114,128,.2); color:#d1d5db; border-color:rgba(107,114,128,.4); }"
                + ".action-btn.sev-none { background:rgba(52,211,153,.14); color:#6ee7b7; border-color:rgba(52,211,153,.3); }"
                + ".action-btn.sev-snap { background:rgba(139,92,246,.2); color:#c4b5fd; border-color:rgba(139,92,246,.4); }"
                + ".version-sel-wrap { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }"
                + ".version-sel { padding:7px 10px; border-radius:12px; border:1px solid var(--line); background:rgba(8,15,30,.9); color:var(--text); font-size:.88rem; min-width:200px; max-width:100%; }"
                + ".version-current { padding:4px 10px; border-radius:999px; border:1px solid var(--line); font-size:.86rem; color:var(--muted); display:inline-flex; align-items:center; gap:5px; white-space:nowrap; }"
                + ".version-current.cve { border-color:rgba(248,113,113,.6); color:#fca5a5; }"
                + ".version-note { font-size:.9rem; color:var(--muted); }"
                + "@media (max-width: 700px) { .page-grid { grid-template-columns: 1fr; } .span-2 { grid-column: auto; } .hero { flex-direction:column; align-items:flex-start; } .inventory-grid { grid-template-columns: 1fr; } }"
                + ".scan-path-row { display:flex; gap:10px; align-items:center; }"
                + ".scan-path-input { flex:1 1 auto; padding:10px 14px; border-radius:14px; border:1px solid var(--line); background:rgba(8,15,30,.9); color:var(--text); font-size:.97rem; font-family:ui-monospace,monospace; outline:none; }"
                + ".scan-path-input:focus { border-color:rgba(125,211,252,.55); }"
                + ".scan-error { margin-top:10px; color:#fca5a5; font-size:.9rem; padding:10px 14px; border-radius:12px; background:rgba(220,38,38,.12); border:1px solid rgba(220,38,38,.3); }"
                + ".scan-overlay { position:fixed; inset:0; background:rgba(7,11,22,.82); backdrop-filter:blur(4px); z-index:9999; display:flex; align-items:center; justify-content:center; }"
                + ".scan-overlay-box { display:flex; flex-direction:column; gap:14px; align-items:center; padding:36px 48px; border:1px solid var(--line); border-radius:24px; background:var(--panel); font-size:1.05rem; font-weight:600; }"
                + "@keyframes rk-spin { to { transform:rotate(360deg); } }"
                + ".scan-spinner { width:36px; height:36px; border:3px solid rgba(125,211,252,.2); border-top-color:var(--accent); border-radius:50%; animation:rk-spin .8s linear infinite; }"
                + ".pom-modal { position:fixed; inset:0; z-index:9990; display:flex; align-items:center; justify-content:center; }"
                + ".pom-modal-backdrop { position:absolute; inset:0; background:rgba(7,11,22,.85); backdrop-filter:blur(6px); cursor:pointer; }"
                + ".pom-modal-box { position:relative; z-index:1; background:var(--panel); border:1px solid var(--line); border-radius:22px; width:min(900px,92vw); max-height:85vh; display:flex; flex-direction:column; box-shadow:0 24px 80px rgba(0,0,0,.4); overflow:hidden; }"
                + ".pom-modal-head { display:flex; justify-content:space-between; align-items:center; padding:16px 20px; border-bottom:1px solid var(--line); gap:12px; flex-shrink:0; }"
                + ".pom-modal-filename { font-family:ui-monospace,monospace; font-size:.9rem; color:var(--accent); min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }"
                + ".pom-modal-body { flex:1; overflow:auto; background:rgba(0,0,0,.3); }"
                + ".pom-modal-body pre { margin:0; padding:20px; font-family:ui-monospace,monospace; font-size:.83rem; line-height:1.65; white-space:pre; color:var(--text); }"
                + "</style><script>let inventoryModule='all';let inventoryKind='all';function setActiveTabs(selector, attr, value){document.querySelectorAll(selector).forEach(b=>b.classList.toggle('active', b.dataset[attr]===value));}function applyInventoryFilters(){setActiveTabs('.module-tabs .inventory-tab','module',inventoryModule);setActiveTabs('.kind-tabs .inventory-tab','kind',inventoryKind);document.querySelectorAll('.inventory-group').forEach(group=>{const moduleOk=inventoryModule==='all'||group.dataset.module===inventoryModule;let visible=0;group.querySelectorAll('.inventory-row').forEach(row=>{const kindOk=inventoryKind==='all'||(row.dataset.kind||'transitive')===inventoryKind;const show=moduleOk&&kindOk;row.classList.toggle('is-hidden',!show);if(show)visible++;});group.classList.toggle('is-hidden', !moduleOk||visible===0);});}function filterInventoryModule(module){inventoryModule=module;applyInventoryFilters();}function filterInventoryKind(kind){inventoryKind=kind;applyInventoryFilters();}function selectVersionChoice(button, selectorId){const selector=document.querySelector('[data-selector-id=\"'+selectorId+'\"]');if(!selector){return;}selector.querySelectorAll('.version-choice').forEach(b=>b.classList.toggle('active', b===button));const hidden=document.getElementById(selectorId);if(hidden){hidden.value=button.dataset.version||'';}}let remMode='upgrade';let remModule='all';function applyRemediationFilters(){let cveN=0,snapN=0,upgradeN=0,transitiveN=0,cleanN=0,allN=0;document.querySelectorAll('.rem-list>.rem-card').forEach(card=>{const modOk=remModule==='all'||card.dataset.module===remModule;let modeOk=true;if(remMode==='cve')modeOk=card.dataset.hasvuln==='true';else if(remMode==='snapshot')modeOk=card.dataset.kind==='snapshot';else if(remMode==='upgrade')modeOk=card.dataset.clean!=='true'&&card.dataset.hasvuln!=='true'&&card.dataset.kind!=='snapshot';else if(remMode==='transitive')modeOk=card.dataset.kind==='transitive';else if(remMode==='clean')modeOk=card.dataset.clean==='true';card.style.display=modOk&&modeOk?'':'none';if(modOk){if(card.dataset.hasvuln==='true')cveN++;if(card.dataset.kind==='snapshot')snapN++;if(card.dataset.clean!=='true'&&card.dataset.hasvuln!=='true'&&card.dataset.kind!=='snapshot')upgradeN++;if(card.dataset.kind==='transitive')transitiveN++;if(card.dataset.clean==='true')cleanN++;allN++;}});document.querySelectorAll('.rem-toggle-btn').forEach(btn=>{btn.classList.toggle('primary',btn.dataset.mode===remMode);const el=btn.querySelector('.tab-count');if(!el)return;if(btn.dataset.mode==='cve')el.textContent=cveN;else if(btn.dataset.mode==='snapshot')el.textContent=snapN;else if(btn.dataset.mode==='upgrade')el.textContent=upgradeN;else if(btn.dataset.mode==='transitive')el.textContent=transitiveN;else if(btn.dataset.mode==='clean')el.textContent=cleanN;else if(btn.dataset.mode==='all')el.textContent=allN;});}function setRemediationMode(mode){remMode=mode;applyRemediationFilters();}function filterRemediationModule(mod){remModule=mod;applyRemediationFilters();}function applyPomChanges(){const parts=[];document.querySelectorAll('.rem-list>.rem-card').forEach(card=>{if(remModule!=='all'&&card.dataset.module!==remModule)return;const compId=card.dataset.compId;const comp=rk_comps[compId];if(!comp)return;if(comp.kind==='transitive')return;const hidden=document.getElementById('view_'+compId);if(!hidden||!hidden.value||hidden.value===comp.v)return;parts.push(encodeURIComponent(compId)+'='+encodeURIComponent(hidden.value));});if(!parts.length)return;const btn=document.querySelector('.pom-actions .button.primary');btn.disabled=true;btn.textContent='Generating...';fetch('/api/scans/pom?scanId='+rk_scanId,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:parts.join('&')}).then(r=>r.ok?r.json():r.text().then(t=>{throw new Error(t);})).then(data=>{btn.textContent='Apply';btn.disabled=false;showPomModal(data);}).catch(err=>{btn.textContent='Apply';btn.disabled=false;alert(err.message||'Failed to generate POM.');});}function showPomModal(files){var keys=Object.keys(files);if(!keys.length)return;document.getElementById('pom-modal-filename').textContent=keys[0];document.getElementById('pom-modal-content').textContent=files[keys[0]];document.getElementById('pom-modal').style.display='flex';}function closePomModal(){document.getElementById('pom-modal').style.display='none';}function copyPomContent(){var pre=document.getElementById('pom-modal-content');if(!pre)return;navigator.clipboard.writeText(pre.textContent).then(function(){var btn=document.querySelector('.pom-modal-head .button');if(btn){var orig=btn.textContent;btn.textContent='Copied!';setTimeout(function(){btn.textContent=orig;},1500);}}).catch(function(){});}function applyUpgrade(compId,version,chip){if(chip){chip.textContent='Upgrading';chip.classList.add('selected');}const selectorId='view_'+compId;const sel=document.querySelector('[data-selector-id=\"'+selectorId+'\"]');if(sel){const btn=sel.querySelector('.version-choice[data-version=\"'+version+'\"]');if(btn)selectVersionChoice(btn,selectorId);sel.scrollIntoView({behavior:'smooth',block:'nearest'});}}function toggleTree(btn){const panel=btn.parentElement.nextElementSibling;if(!panel||!panel.classList.contains('dep-tree-panel'))return;if(panel.style.display!=='none'){panel.style.display='none';btn.textContent='+';return;}if(!panel.hasChildNodes()){const id=btn.dataset.compId;const visited=new Set();let p=btn.closest('.sub-card,.rem-card');while(p){visited.add(p.dataset.compId);p=p.parentElement&&p.parentElement.closest('.sub-card,.rem-card');}panel.innerHTML=(rk_edges[id]||[]).filter(c=>!visited.has(String(c))).map(c=>renderSubCard(String(c),new Set(visited))).join('');}panel.style.display='block';btn.textContent='−';}function renderSubCard(id,visited){const comp=rk_comps[id];if(!comp)return'';const parents=(rk_edges[id]||[]).filter(c=>!visited.has(String(c)));const sevCls='sev-'+comp.sev;const kindCls=comp.kind==='snapshot'?'warn':comp.kind==='direct'?'success':'neutral';const expand=parents.length?'<div class=\"card-expand-row\"><button class=\"card-expand-btn\" type=\"button\" data-comp-id=\"'+id+'\" onclick=\"toggleTree(this)\">+</button></div><div class=\"dep-tree-panel\" style=\"display:none\"></div>':'';return'<div class=\"sub-card\" data-comp-id=\"'+id+'\"><div class=\"rem-header\"><span class=\"rem-title\">'+comp.g+':'+comp.a+'</span><div class=\"rem-badges\"><span class=\"sev-badge '+sevCls+'\">'+comp.icon+' '+comp.label+'</span><span class=\"badge '+kindCls+'\">'+comp.kind+'</span></div></div><div class=\"rem-meta\"><span>Current: <strong>'+comp.v+'</strong></span></div>'+expand+'</div>';}window.addEventListener('DOMContentLoaded',function(){applyInventoryFilters();applyRemediationFilters();});function triggerScan(path){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='flex';fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path})}).then(function(r){return r.ok?r.json():r.text().then(function(t){throw new Error(t);});}).then(function(d){pollScan(d.jobId);}).catch(function(err){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';var e=document.getElementById('scan-error');if(e){e.textContent=err.message||'Scan failed.';e.style.display='block';}});}function triggerFreshScan(path){fetch('/api/metadata/clear',{method:'POST'}).catch(function(){}).finally(function(){triggerScan(path);});}function pollScan(jobId){fetch('/api/scan-status?jobId='+encodeURIComponent(jobId)).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error('Status check failed ('+r.status+'): '+t);});return r.json();}).then(function(d){if(d.status==='running'){var el=document.getElementById('scan-status');if(el)el.textContent=d.message||'';setTimeout(function(){pollScan(jobId);},500);}else if(d.status==='done'){window.location.href='/scans/'+d.scanId;}else if(d.status==='error'){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';var e=document.getElementById('scan-error');if(e){e.textContent=d.message||'Scan failed.';e.style.display='block';}}}).catch(function(err){var ov=document.getElementById('scan-overlay');if(ov)ov.style.display='none';var e=document.getElementById('scan-error');if(e){e.textContent=err.message||'Status check failed.';e.style.display='block';}});}</script></head><body><div class=\"shell\">"
                + "<div class=\"topbar\"><div class=\"brand\"><a class=\"brand-mark\" href=\"/\" aria-label=\"" + escape(brand) + "\">" + logoSvgInline() + "</a><div class=\"brand-copy\"><strong>" + escape(brand) + "</strong><span>" + escape(title) + "</span></div></div><div class=\"nav\"><a href=\"/\">Projects</a></div></div>"
                + "<div class=\"subhead muted\">" + escape(subtitle) + "</div>";
    }

    private String pageShellEnd() {
        return "<div class=\"footer\">RedKite local dependency reporting</div></div></body></html>";
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
        private volatile HttpVersionMetadataProvider versionProvider;
        private final HttpVulnerabilityProvider vulnerabilityProvider;
        volatile List<String> effectiveMavenRepos;
        volatile String mavenSettingsPath;

        private Store(String jdbcUrl, String dbUser, String dbPassword) {
            this.jdbcUrl = jdbcUrl;
            this.dbUser = dbUser;
            this.dbPassword = dbPassword;
            String mavenRepos = System.getProperty("redkite.maven.repositories");
            if (mavenRepos != null) {
                this.versionProvider = new HttpVersionMetadataProvider(mavenRepos);
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
            this.vulnerabilityProvider = new HttpVulnerabilityProvider(System.getProperty("redkite.osv.url", "https://api.osv.dev"));
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
            this.versionProvider = buildVersionProvider(projectRoot);
            this.effectiveMavenRepos = this.versionProvider.getRepositoryBaseUrls();
            LOGGER.info(() -> "Effective Maven repositories: " + effectiveMavenRepos);
        }

        private static HttpVersionMetadataProvider buildVersionProvider(java.nio.file.Path projectRoot) {
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
            return new HttpVersionMetadataProvider(urls, repoUser, repoPass);
        }

        static Store connect(String jdbcUrl, String dbUser, String dbPassword) {
            return new Store(jdbcUrl, dbUser, dbPassword);
        }

        synchronized List<ProjectEntry> listProjects() {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, name, root_path, created_at, updated_at
                         from projects
                         order by id desc
                         """);
                 ResultSet rs = statement.executeQuery()) {
                List<ProjectEntry> projects = new ArrayList<>();
                while (rs.next()) {
                    projects.add(new ProjectEntry(
                            rs.getLong("id"),
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

        synchronized ProjectEntry getProject(long id) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, name, root_path, created_at, updated_at
                         from projects
                         where id = ?
                         """)) {
                statement.setLong(1, id);
                try (ResultSet rs = statement.executeQuery()) {
                    if (!rs.next()) {
                        throw new IllegalArgumentException("project not found");
                    }
                    return new ProjectEntry(
                            rs.getLong("id"),
                            rs.getString("name"),
                            rs.getString("root_path"),
                            rs.getTimestamp("created_at").toInstant(),
                            rs.getTimestamp("updated_at").toInstant());
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to fetch project", e);
            }
        }

        synchronized ScanEntry latestScanForProject(long projectId) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, project_id, raw_input_json, report_json, created_at
                         from scans
                         where project_id = ?
                         order by id desc
                         fetch first 1 row only
                         """)) {
                statement.setLong(1, projectId);
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

        synchronized ScanEntry getScan(long scanId) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, project_id, raw_input_json, report_json, created_at
                         from scans
                         where id = ?
                         """)) {
                statement.setLong(1, scanId);
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
                    long projectId = upsertProject(connection, input.projectName(), input.projectRootPath());
                    ScanReport draft = buildReport(input, projectId, 0L, progress);
                    long scanId = insertScan(connection, projectId, input, draft);
                    List<MetadataResult> metadataResults = draft.metadataResults().stream().map(result -> withScanId(result, scanId)).toList();
                    ScanReport finalReport = new ScanReport(scanId, projectId, draft.complete(), draft.completenessMessage(), draft.createdAt(), draft.components(), draft.dependencyEdges(), draft.vulnerabilityFindings(), draft.recommendations(), draft.snapshotDependencyRisks(), metadataResults);
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

        private MetadataResult withScanId(MetadataResult result, long scanId) {
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
                    insert.setLong(1, result.scanId());
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

        private ScanReport buildReport(ScanInput input, long projectId, long scanId, Consumer<String> progress) {
            List<SnapshotDependencyRisk> snapshotRisks = new ArrayList<>();
            List<UpgradeRecommendation> recs = new ArrayList<>();
            List<MetadataResult> metadata = new ArrayList<>();
            List<VulnerabilityFinding> vulnerabilityFindings = new ArrayList<>();
            boolean complete = true;
            List<ScanComponent> components = input.components();
            int total = components.size();
            int n = 0;
            for (ScanComponent component : components) {
                n++;
                progress.accept("Checking metadata " + n + "/" + total + " — " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
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
                    VersionMetadata versionMetadata = versionProvider.latestVersion(component.coordinate(), component.version());
                    LOGGER.info(() -> "Maven version metadata for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " => latest=" + versionMetadata.latestVersion() + ", sameMajor=" + versionMetadata.latestSameMajorVersion() + ", complete=" + versionMetadata.complete() + ", status=" + versionMetadata.status());
                    String versionMessage = versionMetadata.complete()
                            ? "Latest Maven release is " + versionMetadata.latestVersion() + "."
                            : "No cached Maven metadata was available; version is unknown.";
                    metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, versionMetadata.source(), component.version(), versionMetadata.latestVersion(), versionMetadata.latestSameMajorVersion(), versionMetadata.upgradePathVersions(), versionMetadata.complete(), versionMetadata.status(), versionMetadata.cacheState(), versionMetadata.checkedAt(), null, Instant.now(), null, versionMessage));
                    if (!versionMetadata.complete()) {
                        complete = false;
                    }

                    List<VulnerabilityFinding> compVulns = vulnerabilityProvider.vulnerabilities(component.coordinate(), component.version());
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
            String message;
            if (complete) {
                message = "Report complete. Dependency and vulnerability metadata was checked using fresh provider data or fresh cache.";
            } else {
                message = "Report incomplete. Some Maven metadata could not be refreshed or was unavailable. The report is still shown with unknown metadata and rescan is suggested.";
            }
            return new ScanReport(scanId, projectId, complete, message, Instant.now(), input.components(), input.dependencyEdges(), List.copyOf(vulnerabilityFindings), recs, snapshotRisks, metadata);
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
            if (isUpgradeable(currentVersion, sameMajor)) {
                return sameMajor;
            }
            if (versionMetadata.upgradePathVersions() == null || versionMetadata.upgradePathVersions().isEmpty()) {
                return versionMetadata == null ? null : versionMetadata.latestVersion();
            }
            for (String candidate : versionMetadata.upgradePathVersions()) {
                if (candidate == null || candidate.isBlank()) {
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
                if (candidate == null || candidate.isBlank()) {
                    continue;
                }
                if (!isUpgradeable(currentVersion, candidate)) {
                    continue;
                }
                return candidate;
            }
            if (isUpgradeable(currentVersion, versionMetadata.latestVersion())) {
                return versionMetadata.latestVersion();
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
                 Statement statement = connection.createStatement()) {
                statement.executeUpdate("""
                        create table if not exists projects (
                          id bigint generated by default as identity primary key,
                          name varchar(255) not null,
                          root_path varchar(1024) not null unique,
                          created_at timestamp not null default current_timestamp,
                          updated_at timestamp not null default current_timestamp
                        )
                        """);
                statement.executeUpdate("""
                        create table if not exists scans (
                          id bigint generated by default as identity primary key,
                          project_id bigint not null,
                          project_name varchar(255) not null,
                          repo_path varchar(1024) not null,
                          branch_name varchar(255) not null,
                          head_commit varchar(128) not null,
                          working_tree_clean boolean not null,
                          raw_input_json text not null,
                          report_json text not null,
                          complete boolean not null,
                          completeness_message text not null,
                          created_at timestamp not null default current_timestamp
                        )
                        """);
                statement.executeUpdate("""
                        create table if not exists metadata_cache_entries (
                          id bigint generated by default as identity primary key,
                          scan_id bigint not null,
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
                          unique (scan_id, component_id, metadata_type)
                        )
                        """);
                statement.executeUpdate("""
                        alter table metadata_cache_entries
                        add column if not exists latest_version varchar(255)
                        """);
                statement.executeUpdate("""
                        alter table metadata_cache_entries
                        add column if not exists latest_same_major_version varchar(255)
                        """);
                statement.executeUpdate("""
                        update metadata_cache_entries
                        set latest_version = coalesce(latest_version, component_version),
                            latest_same_major_version = coalesce(latest_same_major_version, component_version)
                        where latest_version is null or latest_same_major_version is null
                        """);
                statement.executeUpdate("""
                        create table if not exists source_poms (
                          id bigint generated by default as identity primary key,
                          scan_id bigint not null,
                          file_path varchar(1024) not null,
                          pom_xml text not null,
                          unique (scan_id, file_path)
                        )
                        """);
                statement.executeUpdate("""
                        create table if not exists generated_poms (
                          id bigint generated by default as identity primary key,
                          scan_id bigint not null,
                          file_path varchar(1024) not null,
                          pom_xml text not null,
                          generated_at timestamp not null default current_timestamp,
                          unique (scan_id, file_path)
                        )
                        """);
                statement.executeUpdate("""
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
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to initialize schema", e);
            }
        }

        private Connection connection() throws SQLException {
            return DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
        }

        private long upsertProject(Connection connection, String name, String rootPath) throws SQLException {
            try (PreparedStatement select = connection.prepareStatement("select id from projects where root_path = ?")) {
                select.setString(1, rootPath);
                try (ResultSet rs = select.executeQuery()) {
                    if (rs.next()) {
                        long id = rs.getLong(1);
                        try (PreparedStatement update = connection.prepareStatement("update projects set name = ?, updated_at = current_timestamp where id = ?")) {
                            update.setString(1, name);
                            update.setLong(2, id);
                            update.executeUpdate();
                        }
                        return id;
                    }
                }
            }
            try (PreparedStatement insert = connection.prepareStatement("insert into projects(name, root_path) values (?, ?)", Statement.RETURN_GENERATED_KEYS)) {
                insert.setString(1, name);
                insert.setString(2, rootPath);
                insert.executeUpdate();
                try (ResultSet keys = insert.getGeneratedKeys()) {
                    if (keys.next()) {
                        return keys.getLong(1);
                    }
                }
            }
            throw new IllegalStateException("failed to upsert project");
        }

        private long insertScan(Connection connection, long projectId, ScanInput input, ScanReport report) throws SQLException {
            try (PreparedStatement insert = connection.prepareStatement("""
                    insert into scans(project_id, project_name, repo_path, branch_name, head_commit, working_tree_clean, raw_input_json, report_json, complete, completeness_message)
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, Statement.RETURN_GENERATED_KEYS)) {
                insert.setLong(1, projectId);
                insert.setString(2, input.projectName());
                insert.setString(3, input.projectRootPath());
                insert.setString(4, input.currentBranch());
                insert.setString(5, input.currentHeadCommit());
                insert.setBoolean(6, input.workingTreeClean());
                insert.setString(7, SerializationSupport.toBase64(input));
                insert.setString(8, SerializationSupport.toBase64(report));
                insert.setBoolean(9, report.complete());
                insert.setString(10, report.completenessMessage());
                insert.executeUpdate();
                try (ResultSet keys = insert.getGeneratedKeys()) {
                    if (keys.next()) {
                        return keys.getLong(1);
                    }
                }
            }
            throw new IllegalStateException("failed to insert scan");
        }

        private void updateScanReport(Connection connection, long scanId, ScanReport report) throws SQLException {
            try (PreparedStatement update = connection.prepareStatement("update scans set report_json = ?, complete = ?, completeness_message = ? where id = ?")) {
                update.setString(1, SerializationSupport.toBase64(report));
                update.setBoolean(2, report.complete());
                update.setString(3, report.completenessMessage());
                update.setLong(4, scanId);
                update.executeUpdate();
            }
        }

        private ScanEntry scanFromRow(ResultSet rs) throws SQLException {
            ScanInput input = SerializationSupport.fromBase64(rs.getString("raw_input_json"), ScanInput.class);
            ScanReport report = SerializationSupport.fromBase64(rs.getString("report_json"), ScanReport.class);
            return new ScanEntry(rs.getLong("id"), rs.getLong("project_id"), input, report, rs.getTimestamp("created_at").toInstant());
        }

        private void persistSourcePoms(Connection connection, long scanId, ScanInput input) throws SQLException {
            java.util.Set<String> paths = new LinkedHashSet<>();
            // Include all discovered POM files, not just those with components
            paths.addAll(input.fileHashes().keySet());
            for (ScanComponent c : input.components()) {
                if (c.sourceFilePath() != null && !c.sourceFilePath().isBlank()) {
                    paths.add(c.sourceFilePath());
                }
            }
            try (PreparedStatement del = connection.prepareStatement("delete from source_poms where scan_id = ?")) {
                del.setLong(1, scanId);
                del.executeUpdate();
            }
            try (PreparedStatement ins = connection.prepareStatement(
                    "insert into source_poms(scan_id, file_path, pom_xml) values (?, ?, ?)")) {
                for (String filePath : paths) {
                    try {
                        Path pomPath = Path.of(filePath);
                        if (!pomPath.isAbsolute()) pomPath = Path.of(input.workingTreePath()).resolve(pomPath);
                        String raw = Files.readString(pomPath);
                        String normalized;
                        try {
                            normalized = RedKiteServerMain.patchPomXml(raw, Map.of());
                        } catch (Exception e) {
                            LOGGER.warning(() -> "Could not normalise POM: " + filePath + " — " + e.getMessage());
                            normalized = raw;
                        }
                        ins.setLong(1, scanId);
                        ins.setString(2, filePath);
                        ins.setString(3, normalized);
                        ins.executeUpdate();
                    } catch (IOException e) {
                        LOGGER.warning(() -> "Could not snapshot POM: " + filePath + " — " + e.getMessage());
                    }
                }
            }
        }

        synchronized Map<String, String> loadSourcePoms(long scanId) {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement(
                         "select file_path, pom_xml from source_poms where scan_id = ? order by file_path")) {
                ps.setLong(1, scanId);
                Map<String, String> result = new LinkedHashMap<>();
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) result.put(rs.getString("file_path"), rs.getString("pom_xml"));
                }
                return result;
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to load source POMs", e);
            }
        }

        synchronized boolean hasSourcePoms(long scanId) {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement("select count(*) from source_poms where scan_id = ?")) {
                ps.setLong(1, scanId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() && rs.getLong(1) > 0;
                }
            } catch (SQLException e) {
                return false;
            }
        }

        synchronized boolean hasSavedPom(long scanId) {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement("select count(*) from generated_poms where scan_id = ?")) {
                ps.setLong(1, scanId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() && rs.getLong(1) > 0;
                }
            } catch (SQLException e) {
                return false;
            }
        }

        synchronized void savePomFiles(long scanId, Map<String, String> files) {
            try (Connection connection = connection()) {
                try (PreparedStatement del = connection.prepareStatement("delete from generated_poms where scan_id = ?")) {
                    del.setLong(1, scanId);
                    del.executeUpdate();
                }
                try (PreparedStatement ins = connection.prepareStatement(
                        "insert into generated_poms(scan_id, file_path, pom_xml) values (?, ?, ?)")) {
                    for (Map.Entry<String, String> e : files.entrySet()) {
                        ins.setLong(1, scanId);
                        ins.setString(2, e.getKey());
                        ins.setString(3, e.getValue());
                        ins.executeUpdate();
                    }
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to save generated POMs", e);
            }
        }

        synchronized Map<String, String> loadPomFiles(long scanId) {
            try (Connection connection = connection();
                 PreparedStatement ps = connection.prepareStatement(
                         "select file_path, pom_xml from generated_poms where scan_id = ? order by file_path")) {
                ps.setLong(1, scanId);
                Map<String, String> result = new LinkedHashMap<>();
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) result.put(rs.getString("file_path"), rs.getString("pom_xml"));
                }
                return result;
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to load generated POMs", e);
            }
        }

    }

    record ProjectEntry(long id, String name, String rootPath, Instant createdAt, Instant updatedAt) implements java.io.Serializable {
    }

    record ScanEntry(long id, long projectId, ScanInput input, ScanReport report, Instant createdAt) implements java.io.Serializable {
    }
}
