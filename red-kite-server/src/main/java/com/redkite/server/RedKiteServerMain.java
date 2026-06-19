package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.core.service.SerializationSupport;
import com.redkite.maven.MavenProjectScanner;
import com.redkite.metadata.HttpVersionMetadataProvider;
import com.redkite.metadata.HttpVulnerabilityProvider;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.core.service.RemediationClassifier;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

public class RedKiteServerMain {
    private static final Logger LOGGER = Logger.getLogger(RedKiteServerMain.class.getName());
    private static final String BRAND = "RedKite";

    @FunctionalInterface
    private interface ExchangeHandler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private final Store store;
    private final HttpServer server;

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
        server.createContext("/upgrade-planner", exchange -> safeHandle(exchange, this::handlePlanner));
        server.createContext("/upgrade-plans", exchange -> safeHandle(exchange, this::handleUpgradePlans));
        server.createContext("/api/scans/input", exchange -> safeHandle(exchange, this::handleApiScanInput));
        server.createContext("/api/upgrade-plans", exchange -> safeHandle(exchange, this::handleApiUpgradePlans));
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
        html.append("<div class=\"hero-actions\"><a class=\"button primary\" href=\"/upgrade-planner\">Open planner</a><a class=\"button\" href=\"/projects\">Projects</a></div>");
        html.append("</div>");
        html.append("<section class=\"card\"><h2>Projects</h2><div class=\"list\">");
        try {
            for (ProjectEntry project : store.listProjects()) {
                html.append("<a class=\"list-row\" href=\"/projects/").append(project.id()).append("\">")
                        .append("<span class=\"list-title\">").append(escape(project.name())).append("</span>")
                        .append("<span class=\"list-meta\">").append(escape(project.rootPath())).append("</span>")
                        .append("</a>");
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "Unable to list projects for dashboard: " + e.getMessage());
            html.append("<div class=\"result-row\"><div><strong>No project data</strong><div class=\"muted\">")
                    .append(escape(e.getMessage()))
                    .append("</div></div><div class=\"badge warn\">database</div></div>");
        }
        html.append("</div></section>");
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
                html.append("<div class=\"stack\">");
                html.append("<a class=\"button primary\" href=\"/scans/").append(scan.id()).append("\">View latest scan</a>");
                html.append("<a class=\"button\" href=\"/upgrade-planner/").append(scan.id()).append("\">Create plan</a>");
                html.append("</div>");
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
            ScanReport report = store.getScan(scanId).report();
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
            html.append(report.complete() ? "<span class=\"badge success\">Complete</span>" : "<span class=\"badge warn\">Incomplete</span>");
            html.append("</div><p class=\"muted\">").append(escape(report.completenessMessage())).append("</p></section>");
            html.append("<section class=\"card span-2\">");
            html.append(renderRemediationView(report));
            html.append("</section>");
            html.append("</div>");
            html.append(pageShellEnd());
            sendHtml(exchange, 200, html.toString());
            return;
        }
        sendText(exchange, 404, "Not found");
    }

    private void handlePlanner(HttpExchange exchange) throws IOException {
        URI uri = exchange.getRequestURI();
        String[] parts = uri.getPath().split("/");
        if (parts.length != 3) {
            sendText(exchange, 404, "Not found");
            return;
        }
        long scanId = Long.parseLong(parts[2]);
        if ("GET".equals(exchange.getRequestMethod())) {
            ScanEntry scan = store.getScan(scanId);
            ScanInput input = scan.input();
            ScanReport report = scan.report();
            StringBuilder html = new StringBuilder();
            html.append(pageShellStart(BRAND, "Upgrade planner", "Choose recommendations and create a local upgrade plan."));
            html.append("<div class=\"page-grid\">");
            html.append("<section class=\"card span-2\"><div class=\"headline\"><div><p class=\"eyebrow\">Scan ").append(report.scanId()).append("</p><h1>Upgrade planner</h1></div><span class=\"badge\">").append(report.recommendations().size()).append(" recommendations</span></div>");
            html.append("<p class=\"muted\">Select one or more recommendations to generate a local plan.</p></section>");
            html.append("<section class=\"card span-2\">");
            html.append("<form method=\"post\" action=\"/upgrade-planner/").append(scanId).append("\">");
            html.append("<input type=\"hidden\" name=\"proposedBranchName\" value=\"red-kite/security-upgrades-").append(LocalDate.now()).append("\"/>");
            html.append("<input type=\"hidden\" name=\"baseBranchAtScanTime\" value=\"").append(escape(input.currentBranch())).append("\"/>");
            html.append("<input type=\"hidden\" name=\"baseHeadAtScanTime\" value=\"").append(escape(input.currentHeadCommit())).append("\"/>");
            html.append("<input type=\"hidden\" name=\"expectedWorkingTreePath\" value=\"").append(escape(input.workingTreePath())).append("\"/>");
            html.append("<h2>Recommendations</h2><div class=\"stack\">");
            if (report.recommendations().isEmpty()) {
                html.append("<p class=\"muted\">No recommendations available for this scan.</p>");
            } else {
                Map<Long, MetadataResult> versionByComponent = new LinkedHashMap<>();
                Map<String, List<VulnerabilityFinding>> vulnerabilitiesByComponent = new LinkedHashMap<>();
                for (MetadataResult result : report.metadataResults()) {
                    if (result.metadataType() == MetadataType.VERSION) {
                        versionByComponent.put(result.componentId(), result);
                    }
                }
                for (VulnerabilityFinding finding : report.vulnerabilityFindings()) {
                    String key = finding.coordinate().groupId() + ":" + finding.coordinate().artifactId() + "@" + finding.affectedVersion();
                    vulnerabilitiesByComponent.computeIfAbsent(key, k -> new ArrayList<>()).add(finding);
                }
                for (UpgradeRecommendation rec : report.recommendations()) {
                    MetadataResult versionMetadata = versionByComponent.get(rec.id());
                    List<String> choices = versionChoices(versionMetadata, rec);
                    String defaultTarget = rec.targetVersion();
                    html.append("<div class=\"result-row selectable\">");
                    html.append("<label class=\"selectable-target\"><input type=\"checkbox\" name=\"recommendationIds\" value=\"").append(rec.id()).append("\"/> ");
                    html.append("<strong>").append(escape(rec.coordinate().groupId() + ":" + rec.coordinate().artifactId())).append("</strong>");
                    html.append("<div class=\"muted\">").append(escape(rec.currentVersion())).append("</div></label>");
                    html.append("<div class=\"upgrade-choice\">");
                    if (rec.reason() == RecommendationReason.SNAPSHOT_REPLACEMENT || choices.isEmpty()) {
                        html.append("<label class=\"muted\" for=\"targetVersion_").append(rec.id()).append("\">Release version</label>");
                        html.append("<input id=\"targetVersion_").append(rec.id()).append("\" name=\"targetVersion_").append(rec.id()).append("\" type=\"text\" placeholder=\"Enter release version\" value=\"").append(escape(defaultTarget)).append("\"/>");
                    } else {
                        html.append(renderVersionSelect("targetVersion_" + rec.id(), rec.coordinate(), rec.currentVersion(), defaultTarget, versionMetadata, rec, vulnerabilitiesByComponent.get(rec.coordinate().groupId() + ":" + rec.coordinate().artifactId() + "@" + rec.currentVersion()), true));
                    }
                    html.append("</div>");
                    html.append("<span class=\"badge\">").append(escape(reasonLabel(rec.reason()))).append("</span>");
                    html.append("</div>");
                }
            }
            html.append("</div><button class=\"button primary\" type=\"submit\">Create plan</button></form></section>");
            html.append("</div>");
            html.append(pageShellEnd());
            sendHtml(exchange, 200, html.toString());
            return;
        }
        if ("POST".equals(exchange.getRequestMethod())) {
            Map<String, String> form = parseForm(readBody(exchange));
            List<Long> recommendationIds = parseLongList(form.getOrDefault("recommendationIds", ""));
            Map<Long, String> targetVersions = parseTargetVersions(form);
            UpgradePlan plan = store.createPlan(scanId, recommendationIds, targetVersions, form.get("proposedBranchName"), form.get("baseBranchAtScanTime"), form.get("baseHeadAtScanTime"), form.get("expectedWorkingTreePath"));
            StringBuilder html = new StringBuilder();
            html.append(pageShellStart(BRAND, "Upgrade plan", "Plan created and ready for local application."));
            html.append("<div class=\"page-grid\">");
            html.append("<section class=\"card span-2\"><div class=\"headline\"><div><p class=\"eyebrow\">Plan ").append(plan.id()).append("</p><h1>Upgrade plan created</h1></div><span class=\"badge success\">Created</span></div>");
            html.append("<p class=\"muted\">Apply it locally from the repository checkout.</p></section>");
            html.append("<section class=\"card\"><h2>Branch</h2><p class=\"mono\">").append(escape(plan.proposedBranchName())).append("</p></section>");
            html.append("<section class=\"card\"><h2>Command</h2><p class=\"mono\">red-kite apply-plan ").append(plan.id()).append("</p></section>");
            html.append("<section class=\"card span-2\"><h2>Planned changes</h2><div class=\"stack\">");
            for (PlannedFileChange change : plan.plannedFileChanges()) {
                html.append("<div class=\"result-row\"><div><strong>").append(escape(change.relativeFilePath())).append("</strong>");
                html.append("<div class=\"muted\">").append(escape(change.oldVersion() + " → " + change.newVersion())).append("</div></div>");
                html.append("<div class=\"badge\">").append(escape(change.changeType().name())).append("</div></div>");
            }
            html.append("</div></section>");
            html.append("</div>");
            html.append(pageShellEnd());
            sendHtml(exchange, 200, html.toString());
            return;
        }
        sendText(exchange, 405, "Method not allowed");
    }

    private void handleUpgradePlans(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String[] parts = path.split("/");
        if (parts.length == 3 && "GET".equals(exchange.getRequestMethod())) {
            long planId = Long.parseLong(parts[2]);
            UpgradePlan plan = store.getPlan(planId);
            sendBase64(exchange, 200, plan);
            return;
        }
        if (parts.length == 3 && "POST".equals(exchange.getRequestMethod())) {
            PlanCreationRequest request = SerializationSupport.fromBase64(readBody(exchange), PlanCreationRequest.class);
            UpgradePlan plan = store.createPlan(request.scanId(), request.recommendationIds(), request.targetVersions(), request.proposedBranchName(), request.baseBranchAtScanTime(), request.baseHeadAtScanTime(), request.expectedWorkingTreePath());
            sendBase64(exchange, 200, plan);
            return;
        }
        if (parts.length == 5 && "POST".equals(exchange.getRequestMethod()) && "application-result".equals(parts[4])) {
            long planId = Long.parseLong(parts[3]);
            PlanApplicationResult result = SerializationSupport.fromBase64(readBody(exchange), PlanApplicationResult.class);
            store.saveApplicationResult(planId, result);
            sendText(exchange, 200, "");
            return;
        }
        sendText(exchange, 404, "Not found");
    }

    private void handleApiScanInput(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        ScanInput input = SerializationSupport.fromBase64(readBody(exchange), ScanInput.class);
        ScanReport report = store.ingest(input);
        sendBase64(exchange, 200, report);
    }

    private void handleApiUpgradePlans(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String[] parts = path.split("/");
        if (parts.length == 4 && "GET".equals(exchange.getRequestMethod())) {
            long planId = Long.parseLong(parts[3]);
            sendBase64(exchange, 200, store.getPlan(planId));
            return;
        }
        if (parts.length == 3 && "POST".equals(exchange.getRequestMethod())) {
            PlanCreationRequest request = SerializationSupport.fromBase64(readBody(exchange), PlanCreationRequest.class);
            UpgradePlan plan = store.createPlan(request.scanId(), request.recommendationIds(), request.targetVersions(), request.proposedBranchName(), request.baseBranchAtScanTime(), request.baseHeadAtScanTime(), request.expectedWorkingTreePath());
            sendBase64(exchange, 200, plan);
            return;
        }
        if (parts.length == 5 && "POST".equals(exchange.getRequestMethod()) && "application-result".equals(parts[4])) {
            long planId = Long.parseLong(parts[3]);
            PlanApplicationResult result = SerializationSupport.fromBase64(readBody(exchange), PlanApplicationResult.class);
            store.saveApplicationResult(planId, result);
            sendText(exchange, 200, "");
            return;
        }
        sendText(exchange, 404, "Not found");
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
                result.merge(key, value, (left, right) -> left.isBlank() ? right : left + "," + right);
            }
        }
        return result;
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static List<Long> parseLongList(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        List<Long> out = new ArrayList<>();
        for (String part : value.split(",")) {
            if (!part.isBlank()) {
                out.add(Long.parseLong(part.trim()));
            }
        }
        return out;
    }

    private static Map<Long, String> parseTargetVersions(Map<String, String> form) {
        Map<Long, String> targetVersions = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : form.entrySet()) {
            String key = entry.getKey();
            if (key == null || !key.startsWith("targetVersion_")) {
                continue;
            }
            String suffix = key.substring("targetVersion_".length());
            if (suffix.isBlank() || entry.getValue() == null || entry.getValue().isBlank()) {
                continue;
            }
            try {
                targetVersions.put(Long.parseLong(suffix), entry.getValue().trim());
            } catch (NumberFormatException ignored) {
                // Ignore malformed row ids; the scan report stays usable.
            }
        }
        return targetVersions;
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
            List<VulnerabilityFinding> findings) {}

    private String renderRemediationView(ScanReport report) {
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
        for (DependencyEdge edge : report.dependencyEdges()) {
            if (edge.fromComponentId() == null || edge.fromComponentId().startsWith("module:")) continue;
            try {
                long fromId = Long.parseLong(edge.fromComponentId());
                long toId = Long.parseLong(edge.toComponentId());
                parentIdsByChild.computeIfAbsent(toId, k -> new ArrayList<>()).add(fromId);
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
            views.add(new ComponentView(c, status, versionMeta, rec, vulns));
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

        // Build module index (preserve urgency sort within each module)
        Map<String, List<ComponentView>> byModule = new LinkedHashMap<>();
        for (ComponentView v : views) {
            String mod = v.component().modulePath() == null || v.component().modulePath().isBlank()
                    ? "(root)" : v.component().modulePath();
            byModule.computeIfAbsent(mod, k -> new ArrayList<>()).add(v);
        }

        // Module tabs (only if more than one module)
        if (byModule.size() > 1) {
            html.append("<div class=\"rem-module-tabs\">");
            html.append("<button class=\"button primary rem-module-tab\" type=\"button\" data-module=\"all\" onclick=\"filterRemediationModule('all')\">All modules <span class=\"tab-count\">").append(byModule.size()).append("</span></button>");
            for (Map.Entry<String, List<ComponentView>> entry : byModule.entrySet()) {
                String mod = entry.getKey();
                html.append("<button class=\"button rem-module-tab\" type=\"button\" data-module=\"").append(escape(mod))
                        .append("\" onclick=\"filterRemediationModule('").append(escape(mod)).append("')\">")
                        .append(escape(mod)).append(" <span class=\"tab-count\">").append(entry.getValue().size()).append("</span></button>");
            }
            html.append("</div>");
        }

        // Filter toggle: CVE | Upgrades | All
        long cveCount = views.stream().filter(v -> v.status().hasVulnerability()).count();
        long upgradeCount = views.stream().filter(v -> v.status().needsRemediation() && !v.status().hasVulnerability()).count();
        html.append("<div class=\"rem-toggle\">");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"cve\" onclick=\"setRemediationMode('cve')\">CVE <span class=\"tab-count\">").append(cveCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-mode=\"upgrade\" onclick=\"setRemediationMode('upgrade')\">Upgrades <span class=\"tab-count\">").append(upgradeCount).append("</span></button>");
        html.append("<button class=\"button primary rem-toggle-btn\" type=\"button\" data-mode=\"all\" onclick=\"setRemediationMode('all')\">All <span class=\"tab-count\">").append(views.size()).append("</span></button>");
        html.append("<label class=\"rem-check-label\"><input type=\"checkbox\" id=\"rem-show-upgrades\" onchange=\"applyRemediationFilters()\"> Show upgrades</label>");
        html.append("<label class=\"rem-check-label\"><input type=\"checkbox\" id=\"rem-show-transitive\" onchange=\"applyRemediationFilters()\"> Show transitive</label>");
        html.append("</div>");

        // Component cards (flat list; JS handles module + mode visibility)
        html.append("<div class=\"rem-list\">");
        for (ComponentView view : views) {
            String mod = view.component().modulePath() == null || view.component().modulePath().isBlank()
                    ? "(root)" : view.component().modulePath();
            String pulledInBy = null;
            if (!view.component().direct() && !view.component().snapshot()) {
                List<Long> parentIds = parentIdsByChild.getOrDefault(view.component().id(), List.of());
                List<String> parentNames = new ArrayList<>();
                for (Long pid : parentIds) {
                    ScanComponent parent = componentsById.get(pid);
                    if (parent != null) {
                        parentNames.add(parent.coordinate().groupId() + ":" + parent.coordinate().artifactId());
                    }
                    if (parentNames.size() == 3) break;
                }
                if (!parentNames.isEmpty()) pulledInBy = String.join(", ", parentNames);
            }
            html.append(renderComponentCard(view, mod, pulledInBy));
        }
        html.append("</div>");

        return html.toString();
    }

    private String renderComponentCard(ComponentView view, String module, String pulledInBy) {
        ScanComponent comp = view.component();
        RemediationStatus status = view.status();
        boolean clean = !status.needsRemediation();
        String coordStr = comp.coordinate().groupId() + ":" + comp.coordinate().artifactId();

        StringBuilder html = new StringBuilder();
        String kind = comp.snapshot() ? "snapshot" : comp.direct() ? "direct" : "transitive";
        boolean upgradeOnly = status.hasUpgradeRecommendation()
                && !status.hasVulnerability() && !status.isSnapshot()
                && !status.hasDirectVersionDeclaration() && !status.hasStaleMetadata();
        html.append("<div class=\"rem-card").append(clean ? " clean" : "").append("\" data-clean=\"").append(clean)
                .append("\" data-module=\"").append(escape(module))
                .append("\" data-kind=\"").append(kind)
                .append("\" data-hasvuln=\"").append(status.hasVulnerability())
                .append("\" data-upgradeonly=\"").append(upgradeOnly).append("\">");

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

        // Pulled in by (transitive only)
        if (pulledInBy != null) {
            html.append("<div class=\"rem-via\">via ").append(escape(pulledInBy)).append("</div>");
        }

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
        if (!status.reasons().isEmpty()) {
            html.append("<div class=\"rem-reasons\">");
            for (String reason : status.reasons()) {
                html.append("<span class=\"reason-chip\">").append(escape(reason)).append("</span>");
            }
            html.append("</div>");
        }

        // Version selector (display-only on scan page) + planner link
        if (!clean && view.versionMetadata() != null) {
            String selectorId = "view_" + comp.id();
            String selectedVersion = view.recommendation() != null ? view.recommendation().targetVersion() : comp.version();
            html.append("<div class=\"rem-actions\">");
            html.append(renderVersionSelect(selectorId, comp.coordinate(), comp.version(), selectedVersion,
                    view.versionMetadata(), view.recommendation(), view.findings(), false));
            html.append("</div>");
        }

        html.append("</div>");
        return html.toString();
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
        if (status.hasDirectVersionDeclaration()) return 70;
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
        String effectiveSelected = selectedVersion != null ? selectedVersion : recommendedVersion;

        String nameAttr = includeNameAttr ? " name=\"" + escape(selectorId) + "\"" : "";
        html.append("<select class=\"version-sel\" id=\"").append(escape(selectorId)).append("\"").append(nameAttr).append(">");
        for (String version : ordered) {
            boolean isSelected = version.equals(effectiveSelected);
            boolean hasCve = hasCveForVersion(coordinate, version, vulnFindings);
            String label = buildVersionOptionLabel(version, recommendedVersion, latestVersion, latestSameMajor,
                    recommendation != null ? recommendation.reason() : null, hasCve, currentVersion);
            html.append("<option value=\"").append(escape(version)).append("\"")
                    .append(isSelected ? " selected" : "")
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
                + ".shell { width: 100%; padding: 28px 32px 48px; box-sizing: border-box; }"
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
                + ".rem-module-tabs { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; }"
                + ".rem-toggle { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:16px; }"
                + ".rem-check-label { display:inline-flex; align-items:center; gap:6px; font-size:.9rem; color:var(--muted); cursor:pointer; padding:6px 4px; user-select:none; }"
                + ".rem-check-label input { accent-color:var(--accent); width:15px; height:15px; cursor:pointer; }"
                + ".rem-list { display:flex; flex-direction:column; gap:10px; }"
                + ".rem-card { padding:15px 18px; border:1px solid var(--line); border-radius:20px; background:rgba(255,255,255,.02); display:flex; flex-direction:column; gap:9px; }"
                + ".rem-card.clean { opacity:.7; }"
                + ".rem-header { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }"
                + ".rem-title { font-weight:700; font-size:1rem; font-family:ui-monospace,monospace; }"
                + ".rem-badges { display:flex; flex-wrap:wrap; gap:6px; align-items:center; }"
                + ".sev-badge { display:inline-flex; align-items:center; gap:4px; padding:4px 10px; border-radius:999px; font-size:.82rem; font-weight:700; }"
                + ".rem-meta { font-size:.93rem; color:var(--muted); display:flex; flex-wrap:wrap; gap:10px; align-items:center; }"
                + ".rem-meta strong { color:var(--text); }"
                + ".rem-via { font-size:.83rem; color:var(--muted); font-style:italic; }"
                + ".rem-cves { font-size:.85rem; color:var(--muted); font-family:ui-monospace,monospace; word-break:break-all; }"
                + ".rem-reasons { display:flex; flex-wrap:wrap; gap:6px; }"
                + ".reason-chip { padding:3px 9px; border-radius:999px; border:1px solid rgba(167,139,250,.3); background:rgba(167,139,250,.1); color:#d8c8ff; font-size:.78rem; }"
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
                + "</style><script>let inventoryModule='all';let inventoryKind='all';function setActiveTabs(selector, attr, value){document.querySelectorAll(selector).forEach(b=>b.classList.toggle('active', b.dataset[attr]===value));}function applyInventoryFilters(){setActiveTabs('.module-tabs .inventory-tab','module',inventoryModule);setActiveTabs('.kind-tabs .inventory-tab','kind',inventoryKind);document.querySelectorAll('.inventory-group').forEach(group=>{const moduleOk=inventoryModule==='all'||group.dataset.module===inventoryModule;let visible=0;group.querySelectorAll('.inventory-row').forEach(row=>{const kindOk=inventoryKind==='all'||(row.dataset.kind||'transitive')===inventoryKind;const show=moduleOk&&kindOk;row.classList.toggle('is-hidden',!show);if(show)visible++;});group.classList.toggle('is-hidden', !moduleOk||visible===0);});}function filterInventoryModule(module){inventoryModule=module;applyInventoryFilters();}function filterInventoryKind(kind){inventoryKind=kind;applyInventoryFilters();}function selectVersionChoice(button, selectorId){const selector=document.querySelector('[data-selector-id=\"'+selectorId+'\"]');if(!selector){return;}selector.querySelectorAll('.version-choice').forEach(b=>b.classList.toggle('active', b===button));const hidden=document.getElementById(selectorId);if(hidden){hidden.value=button.dataset.version||'';}}let remMode='all';let remModule='all';function applyRemediationFilters(){const showTransitive=document.getElementById('rem-show-transitive')?.checked??false;const showUpgrades=document.getElementById('rem-show-upgrades')?.checked??false;document.querySelectorAll('.rem-card').forEach(card=>{const modOk=remModule==='all'||card.dataset.module===remModule;const kindOk=showTransitive||card.dataset.kind!=='transitive';const upgradeOk=showUpgrades||remMode==='upgrade'||card.dataset.upgradeonly!=='true';let modeOk=true;if(remMode==='cve')modeOk=card.dataset.hasvuln==='true';else if(remMode==='upgrade')modeOk=card.dataset.clean!=='true'&&card.dataset.hasvuln!=='true';card.style.display=modOk&&kindOk&&upgradeOk&&modeOk?'':'none';});document.querySelectorAll('.rem-toggle-btn').forEach(btn=>btn.classList.toggle('primary',btn.dataset.mode===remMode));document.querySelectorAll('.rem-module-tab').forEach(btn=>btn.classList.toggle('primary',btn.dataset.module===remModule));}function setRemediationMode(mode){remMode=mode;applyRemediationFilters();}function filterRemediationModule(mod){remModule=mod;applyRemediationFilters();}window.addEventListener('DOMContentLoaded',function(){applyInventoryFilters();applyRemediationFilters();});</script></head><body><div class=\"shell\">"
                + "<div class=\"topbar\"><div class=\"brand\"><a class=\"brand-mark\" href=\"/\" aria-label=\"" + escape(brand) + "\">" + logoSvgInline() + "</a><div class=\"brand-copy\"><strong>" + escape(brand) + "</strong><span>" + escape(title) + "</span></div></div><div class=\"nav\"><a href=\"/\">Projects</a><a href=\"/upgrade-planner\">Planner</a></div></div>"
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
        private final HttpVersionMetadataProvider versionProvider;
        private final HttpVulnerabilityProvider vulnerabilityProvider;

        private Store(String jdbcUrl, String dbUser, String dbPassword) {
            this.jdbcUrl = jdbcUrl;
            this.dbUser = dbUser;
            this.dbPassword = dbPassword;
            this.versionProvider = new HttpVersionMetadataProvider(System.getProperty("redkite.maven.repositories", "https://repo1.maven.org/maven2"));
            this.vulnerabilityProvider = new HttpVulnerabilityProvider(System.getProperty("redkite.osv.url", "https://api.osv.dev"));
            initializeSchema();
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

        synchronized UpgradePlan getPlan(long planId) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         select id, project_id, scan_id, recommendation_ids, proposed_branch_name, base_branch_at_scan_time,
                                base_head_at_scan_time, expected_working_tree_path, expected_file_hashes,
                                planned_file_changes, warnings, metadata_completeness_notes, created_at, status,
                                application_result_json
                         from upgrade_plans
                         where id = ?
                         """)) {
                statement.setLong(1, planId);
                try (ResultSet rs = statement.executeQuery()) {
                    if (!rs.next()) {
                        throw new IllegalArgumentException("plan not found");
                    }
                    UpgradePlan plan = planFromRow(rs);
                    String resultJson = rs.getString("application_result_json");
                    return resultJson == null ? plan : withStatus(plan, mapStatus(SerializationSupport.fromBase64(resultJson, PlanApplicationResult.class).status()));
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to fetch plan", e);
            }
        }

        synchronized ScanReport ingest(ScanInput input) {
            try (Connection connection = connection()) {
                connection.setAutoCommit(false);
                try {
                    long projectId = upsertProject(connection, input.projectName(), input.projectRootPath());
                    ScanReport draft = buildReport(input, projectId, 0L);
                    long scanId = insertScan(connection, projectId, input, draft);
                    List<MetadataResult> metadataResults = draft.metadataResults().stream().map(result -> withScanId(result, scanId)).toList();
                    ScanReport finalReport = new ScanReport(scanId, projectId, draft.complete(), draft.completenessMessage(), draft.createdAt(), draft.components(), draft.dependencyEdges(), draft.vulnerabilityFindings(), draft.recommendations(), draft.snapshotDependencyRisks(), metadataResults);
                    updateScanReport(connection, scanId, finalReport);
                    persistMetadataCache(connection, finalReport);
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

        synchronized UpgradePlan createPlan(long scanId, List<Long> recommendationIds, Map<Long, String> targetVersions, String proposedBranchName, String baseBranchAtScanTime, String baseHeadAtScanTime, String expectedWorkingTreePath) {
            ScanEntry scan = getScan(scanId);
            Map<Long, UpgradeRecommendation> recommendationById = new LinkedHashMap<>();
            for (UpgradeRecommendation recommendation : scan.report().recommendations()) {
                recommendationById.put(recommendation.id(), recommendation);
            }
            List<UpgradeRecommendation> selected = new ArrayList<>();
            List<PlannedFileChange> changes = new ArrayList<>();
            for (Long recommendationId : recommendationIds) {
                UpgradeRecommendation recommendation = recommendationById.get(recommendationId);
                if (recommendation == null) {
                    continue;
                }
                selected.add(recommendation);
                String chosenTarget = targetVersions == null ? null : targetVersions.get(recommendationId);
                if (chosenTarget == null || chosenTarget.isBlank()) {
                    chosenTarget = recommendation.targetVersion();
                }
                PlannedFileChange baseChange = recommendation.plannedFileChange();
                String reason = reasonMessage(upgradeReason(recommendation.currentVersion(), chosenTarget), chosenTarget);
                changes.add(new PlannedFileChange(
                        baseChange.relativeFilePath(),
                        baseChange.expectedSha256Before(),
                        baseChange.changeType(),
                        baseChange.groupId(),
                        baseChange.artifactId(),
                        baseChange.propertyName(),
                        baseChange.oldVersion(),
                        chosenTarget,
                        reason,
                        baseChange.relatedRecommendationId()));
            }
            List<Long> selectedRecommendationIds = selected.stream().map(UpgradeRecommendation::id).toList();
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         insert into upgrade_plans(
                           project_id, scan_id, recommendation_ids, proposed_branch_name, base_branch_at_scan_time,
                           base_head_at_scan_time, expected_working_tree_path, expected_file_hashes, planned_file_changes,
                           warnings, metadata_completeness_notes, status
                         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                         """, Statement.RETURN_GENERATED_KEYS)) {
                statement.setLong(1, scan.projectId());
                statement.setLong(2, scanId);
                statement.setString(3, SerializationSupport.toBase64((java.io.Serializable) selectedRecommendationIds));
                statement.setString(4, proposedBranchName);
                statement.setString(5, baseBranchAtScanTime);
                statement.setString(6, baseHeadAtScanTime);
                statement.setString(7, expectedWorkingTreePath);
                statement.setString(8, SerializationSupport.toBase64((java.io.Serializable) scan.input().fileHashes()));
                statement.setString(9, SerializationSupport.toBase64((java.io.Serializable) changes));
                statement.setString(10, SerializationSupport.toBase64((java.io.Serializable) List.of()));
                statement.setString(11, SerializationSupport.toBase64((java.io.Serializable) List.of()));
                statement.setString(12, PlanStatus.CREATED.name());
                statement.executeUpdate();
                try (ResultSet keys = statement.getGeneratedKeys()) {
                    if (!keys.next()) {
                        throw new IllegalStateException("failed to create plan");
                    }
                    long planId = keys.getLong(1);
                    return new UpgradePlan(planId, scan.projectId(), scanId, selectedRecommendationIds, proposedBranchName, baseBranchAtScanTime, baseHeadAtScanTime, expectedWorkingTreePath, scan.input().fileHashes(), List.copyOf(changes), List.of(), List.of(), Instant.now(), PlanStatus.CREATED);
                }
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to create plan", e);
            }
        }

        synchronized void saveApplicationResult(long planId, PlanApplicationResult result) {
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement("""
                         update upgrade_plans
                         set application_result_json = ?, status = ?
                         where id = ?
                         """)) {
                statement.setString(1, SerializationSupport.toBase64(result));
                statement.setString(2, result.status());
                statement.setLong(3, planId);
                statement.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("Failed to store application result", e);
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

        private ScanReport buildReport(ScanInput input, long projectId, long scanId) {
            List<SnapshotDependencyRisk> snapshotRisks = new ArrayList<>();
            List<UpgradeRecommendation> recs = new ArrayList<>();
            List<MetadataResult> metadata = new ArrayList<>();
            List<VulnerabilityFinding> vulnerabilityFindings = new ArrayList<>();
            boolean complete = true;
            for (ScanComponent component : input.components()) {
                LOGGER.info(() -> "Enriching component " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " version=" + component.version());
                if (component.snapshot()) {
                    LOGGER.info(() -> "Component is SNAPSHOT; recording unverified dependency risk for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                    snapshotRisks.add(new SnapshotDependencyRisk(component.id(), "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata.", "Use release.", severity(component.scope())));
                    String target = component.version() == null ? "1.0.0" : component.version().replace("-SNAPSHOT", "");
                    PlannedFileChange change = new PlannedFileChange(component.sourceFilePath(), input.fileHashes().get(component.sourceFilePath()), ChangeType.MAVEN_DIRECT_DEPENDENCY_VERSION_UPDATE, component.coordinate().groupId(), component.coordinate().artifactId(), null, component.version(), target, "Use release.", component.id());
                    recs.add(new UpgradeRecommendation(component.id(), component.coordinate(), component.version(), target, RecommendationReason.SNAPSHOT_REPLACEMENT, RiskLevel.MAJOR, RecommendationConfidence.MEDIUM, List.of(), List.of(component.id()), change));
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
                                PlannedFileChange change = plannedChangeFor(component, input, target, reasonMessage(reason, target));
                                recs.add(new UpgradeRecommendation(component.id(), component.coordinate(), component.version(), target, reason, risk, confidence, List.of(), List.of(component.id()), change));
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

        private PlannedFileChange plannedChangeFor(ScanComponent component, ScanInput input, String targetVersion, String reason) {
            String propertyName = propertyName(component);
            ChangeType changeType = switch (component.versionSource()) {
                case PROPERTY -> ChangeType.MAVEN_PROPERTY_UPDATE;
                case PARENT_MANAGED -> ChangeType.MAVEN_PARENT_VERSION_UPDATE;
                case BOM_MANAGED -> ChangeType.MAVEN_BOM_VERSION_UPDATE;
                case LITERAL, UNKNOWN -> ChangeType.MAVEN_DIRECT_DEPENDENCY_VERSION_UPDATE;
            };
            return new PlannedFileChange(
                    component.sourceFilePath(),
                    input.fileHashes().get(component.sourceFilePath()),
                    changeType,
                    component.coordinate().groupId(),
                    component.coordinate().artifactId(),
                    propertyName,
                    component.version(),
                    targetVersion,
                    reason,
                    component.id());
        }

        private String propertyName(ScanComponent component) {
            if (component.owningVersionControlPoint() == null) {
                return null;
            }
            int hash = component.owningVersionControlPoint().indexOf('#');
            if (hash < 0 || hash == component.owningVersionControlPoint().length() - 1) {
                return null;
            }
            return component.owningVersionControlPoint().substring(hash + 1);
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

        private UpgradePlan withStatus(UpgradePlan plan, PlanStatus status) {
            return new UpgradePlan(plan.id(), plan.projectId(), plan.scanId(), plan.recommendationIds(), plan.proposedBranchName(), plan.baseBranchAtScanTime(), plan.baseHeadAtScanTime(), plan.expectedWorkingTreePath(), plan.expectedFileHashes(), plan.plannedFileChanges(), plan.warnings(), plan.metadataCompletenessNotes(), plan.createdAt(), status);
        }

        private PlanStatus mapStatus(String status) {
            return PlanStatus.valueOf(status);
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
                        create table if not exists upgrade_plans (
                          id bigint generated by default as identity primary key,
                          project_id bigint not null,
                          scan_id bigint not null,
                          recommendation_ids text not null,
                          proposed_branch_name varchar(255) not null,
                          base_branch_at_scan_time varchar(255) not null,
                          base_head_at_scan_time varchar(128) not null,
                          expected_working_tree_path varchar(1024) not null,
                          expected_file_hashes text not null,
                          planned_file_changes text not null,
                          warnings text not null,
                          metadata_completeness_notes text not null,
                          application_result_json text,
                          status varchar(32) not null,
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

        @SuppressWarnings("unchecked")
        private UpgradePlan planFromRow(ResultSet rs) throws SQLException {
            List<Long> recommendationIds = SerializationSupport.fromBase64(rs.getString("recommendation_ids"), List.class);
            Map<String, String> expectedHashes = SerializationSupport.fromBase64(rs.getString("expected_file_hashes"), Map.class);
            List<PlannedFileChange> changes = SerializationSupport.fromBase64(rs.getString("planned_file_changes"), List.class);
            List<String> warnings = SerializationSupport.fromBase64(rs.getString("warnings"), List.class);
            List<String> notes = SerializationSupport.fromBase64(rs.getString("metadata_completeness_notes"), List.class);
            return new UpgradePlan(
                    rs.getLong("id"),
                    rs.getLong("project_id"),
                    rs.getLong("scan_id"),
                    recommendationIds,
                    rs.getString("proposed_branch_name"),
                    rs.getString("base_branch_at_scan_time"),
                    rs.getString("base_head_at_scan_time"),
                    rs.getString("expected_working_tree_path"),
                    expectedHashes,
                    changes,
                    warnings,
                    notes,
                    rs.getTimestamp("created_at").toInstant(),
                    PlanStatus.valueOf(rs.getString("status")));
        }
    }

    record ProjectEntry(long id, String name, String rootPath, Instant createdAt, Instant updatedAt) implements java.io.Serializable {
    }

    record ScanEntry(long id, long projectId, ScanInput input, ScanReport report, Instant createdAt) implements java.io.Serializable {
    }

    record PlanEntry(UpgradePlan plan, PlanApplicationResult result) implements java.io.Serializable {
    }
}
