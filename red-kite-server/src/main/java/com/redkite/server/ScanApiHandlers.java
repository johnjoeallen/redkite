package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.maven.MavenProjectScanner;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.redkite.server.Http.*;
import static com.redkite.server.Json.*;
import static com.redkite.server.ScanJob.*;

/** Starting analyses and polling them, enforcer results, POM download/preview/write, project deletion and cache clearing. */
final class ScanApiHandlers {
    private static final Logger LOGGER = Logger.getLogger(ScanApiHandlers.class.getName());
    private final ConcurrentHashMap<String, ScanJob> scanJobs = new ConcurrentHashMap<>();
    private final Store store;
    private final EnforcerAnalysis analysis;
    private final PomChanges pomChanges;

    ScanApiHandlers(Store store, EnforcerAnalysis analysis, PomChanges pomChanges) {
        this.store = store;
        this.analysis = analysis;
        this.pomChanges = pomChanges;
    }

    void handleApiScan(HttpExchange exchange) throws IOException {
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
                com.redkite.maven.ProjectConfigFile.ensureDefaultExists(projectRoot);
                com.redkite.maven.ProjectConfigFile.ensureGitignoreEntries(projectRoot);

                // Phase 0: dependency scan
                int[] scanMods = {0}, scanDone = {0};
                Consumer<String> scanProg = msg -> {
                    if (msg.startsWith("Found ")) {
                        try { scanMods[0] = Integer.parseInt(msg.split(" ")[1]); } catch (Exception ignored) {}
                        job.phasesJson = scanPhases(5,"active",0,"pending",0,"pending",0,"pending",0,"pending");
                    } else if (msg.startsWith("Running dependency:tree")) {
                        scanDone[0]++;
                        job.phasesJson = scanPhases(treeProgressPercent(scanDone[0], scanMods[0]),"active",0,"pending",0,"pending",0,"pending",0,"pending");
                    }
                };
                ScanInput input = new MavenProjectScanner().scan(projectRoot, scanProg, job::appendLine);

                job.phasesJson = scanPhases(100,"done",0,"active",0,"pending",0,"pending",0,"pending");
                Consumer<String> buildProg = msg -> {
                    Integer versionPct = stepProgressPercent(msg, "Version ");
                    Integer vulnPct = stepProgressPercent(msg, "Vulnerability ");
                    if (versionPct != null) {
                        job.phasesJson = scanPhases(100,"done",versionPct,"active",0,"pending",0,"pending",0,"pending");
                    } else if (vulnPct != null) {
                        job.phasesJson = scanPhases(100,"done",100,"done",vulnPct,"active",0,"pending",0,"pending");
                    } else if ("Updates".equals(msg)) {
                        job.phasesJson = scanPhases(100,"done",100,"done",100,"done",0,"active",0,"pending");
                    }
                };
                ScanReport report = store.ingest(input, buildProg);

                job.phasesJson = scanPhases(100,"done",100,"done",100,"done",100,"done",0,"active");
                analysis.runEnforcerCheck(projectRoot, report.scanId(), msg -> {
                    if (msg.startsWith("Dependency management ")) {
                        try {
                            int pct = Integer.parseInt(msg.substring("Dependency management ".length()).trim());
                            job.phasesJson = scanPhases(100,"done",100,"done",100,"done",100,"done",pct,"active");
                        } catch (Exception ignored) {}
                    }
                }, job::appendLine);
                job.phasesJson = scanPhases(100,"done",100,"done",100,"done",100,"done",100,"done");

                job.scanId = report.scanId();
                job.status = ScanJob.Status.DONE;
            } catch (Throwable e) {
                job.errorMessage = causeChain(e);
                job.status = ScanJob.Status.ERROR;
            }
        }, "redkite-scan-" + jobId).start();
    }

    void handleApiEnforcerResults(HttpExchange exchange) throws IOException {
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

    /** Dependency-tree phase progress: 10% on discovering the modules, the next 80% spread over
     *  them, capped at 95% until the phase is really done; 20% while the module count is unknown. */
    static int treeProgressPercent(int modulesDone, int modules) {
        return modules > 0 ? Math.min(10 + modulesDone * 80 / modules, 95) : 20;
    }

    /** Percent complete for a "{@code <prefix>n/total}" progress message, or {@code null} if
     *  {@code msg} isn't one (wrong prefix or unparsable counts). */
    static Integer stepProgressPercent(String msg, String prefix) {
        if (!msg.startsWith(prefix)) return null;
        String[] parts = msg.substring(prefix.length()).split("/");
        try {
            int n = Integer.parseInt(parts[0].trim());
            int total = Integer.parseInt(parts[1].trim());
            return total > 0 ? n * 100 / total : 0;
        } catch (RuntimeException e) {
            return null;
        }
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

    void handleApiScanStatus(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        String jobId = queryParam(exchange.getRequestURI().getQuery(), "jobId");
        if (jobId == null) { sendText(exchange, 400, "Missing jobId"); return; }
        ScanJob job = scanJobs.get(jobId);
        if (job == null) { sendText(exchange, 404, "Job not found"); return; }
        switch (job.status) {
            case RUNNING -> sendJson(exchange, 200, "{\"status\":\"running\",\"phases\":" + job.phasesJson
                    + ",\"log\":" + jsonStrArray(job.recentLinesSnapshot()) + "}");
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

    void handleApiMetadataClear(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed");
            return;
        }
        store.versionProvider.clearAll();
        store.clearVersionCache();
        store.vulnerabilityProvider.clearAll();
        store.licenses.clearLicenseCache();
        sendJson(exchange, 200, "{\"cleared\":true}");
    }

    void handleApiProjects(HttpExchange exchange) throws IOException {
        String[] parts = exchange.getRequestURI().getPath().split("/");
        if (parts.length == 4 && "DELETE".equalsIgnoreCase(exchange.getRequestMethod())) {
            String projectId = parts[3];
            store.deleteProject(projectId);
            sendJson(exchange, 200, "{\"deleted\":true}");
            return;
        }
        sendText(exchange, 405, "Method not allowed");
    }

    void handleApiScanPom(HttpExchange exchange) throws IOException {
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
                Map<String, String> patchedFiles = pomChanges.generatePomPatches(
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

    void handleApiScanPomWrite(HttpExchange exchange) throws IOException {
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
}
