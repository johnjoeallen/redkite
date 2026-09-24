package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.maven.RemediationApplier;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.core.service.CandidateUpdateResolver;
import com.redkite.core.service.UpdatePlanBuilder;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import static com.redkite.server.Http.*;
import static com.redkite.server.Json.*;
import static com.redkite.server.PomXml.*;

/** Applying remediations: single fixes, validated batch applies (with revert on failure), and read-only resolve/plan queries. */
final class RemediationHandlers {
    private static final Logger LOGGER = Logger.getLogger(RemediationHandlers.class.getName());
    private final ConcurrentHashMap<String, ApplyJob> applyJobs = new ConcurrentHashMap<>();
    private final Store store;
    private final PomChanges pomChanges;

    RemediationHandlers(Store store, PomChanges pomChanges) {
        this.store = store;
        this.pomChanges = pomChanges;
    }

    void handleApiRemediationApply(HttpExchange exchange) throws IOException {
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
            pomChanges.refreshPinSummaryComments(applier, scanId, projectRoot, modified, null);
            for (Map.Entry<Path, String> entry : modified.entrySet()) {
                Files.writeString(entry.getKey(), entry.getValue(), StandardCharsets.UTF_8);
            }

            sendJson(exchange, 200, "{\"status\":\"ok\"}");
        } catch (Exception e) {
            LOGGER.warning(() -> "Remediation apply failed: " + e.getMessage());
            sendText(exchange, 500, "Apply failed: " + e.getMessage());
        }
    }

    void handleApiRemediationApplyBatch(HttpExchange exchange) throws IOException {
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
            com.redkite.maven.ProjectConfigFile.ProjectConfig projectConfig = com.redkite.maven.ProjectConfigFile.load(projectRoot);
            com.redkite.maven.ValidationRunner.ValidationOptions validationOptions = new com.redkite.maven.ValidationRunner.ValidationOptions(
                    projectConfig.toBuildArgs(), projectConfig.env(), projectConfig.mode(), projectConfig.springBootArgs(),
                    projectConfig.enableTests(), projectConfig.fullLogs(), projectConfig.startedPattern());

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

                    pomChanges.refreshPinSummaryComments(applier, scanId, projectRoot, modified, originals);

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
                            runner.validateWithStartup(projectRoot, rootPom, 180, validationOptions, job::appendLine);
                    job.baselinePassed = pre.passed();
                    if (!pre.passed()) {
                        LOGGER.info(() -> "Pre-apply validation failed (baseline broken) — continuing with apply: " + pre.failureSignature());
                    }

                    // --- APPLYING ---
                    job.phase = ApplyJob.Phase.APPLYING;

                    // Back up what's about to be overwritten before touching any real project file.
                    savePristineCopies(projectRoot, originals);

                    // Write all changes to disk.
                    for (Map.Entry<Path, String> entry : modified.entrySet()) {
                        Files.writeString(entry.getKey(), entry.getValue(), StandardCharsets.UTF_8);
                    }

                    // --- POST-VALIDATE ---
                    job.phase = ApplyJob.Phase.POST_VALIDATE;
                    com.redkite.maven.ValidationRunner.ValidationResult post =
                            runner.validateWithStartup(projectRoot, rootPom, 180, validationOptions, job::appendLine);
                    if (!post.passed()) {
                        // Preserve every file as it stood when validation failed, BEFORE reverting
                        // any of them — ValidationRunner already snapshots the root POM to
                        // .redkite/work/pom.xml, but an apply can touch other files too (submodule
                        // POMs, pomPatches), and those need to survive the revert just as much.
                        saveFailedCopies(projectRoot, modified);
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
                        job.failureCommand = post.command() != null ? String.join(" ", post.command()) : null;
                        job.failureLogPath = com.redkite.maven.ValidationRunner.redkiteWorkDir(projectRoot).resolve("build.log").toString();
                        job.status = ApplyJob.Status.FAILED;
                        return;
                    }

                    cleanupWorkDir(projectRoot);
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
    void handleApiRemediationResolve(HttpExchange exchange) throws IOException {
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
    void handleApiRemediationPlan(HttpExchange exchange) throws IOException {
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

    void handleApiRemediationApplyStatus(HttpExchange exchange) throws IOException {
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
                sendJson(exchange, 200, "{\"status\":\"running\",\"phase\":" + jsonStr(phase)
                        + ",\"log\":" + jsonStrArray(job.recentLinesSnapshot()) + "}");
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
                if (job.failureCommand != null) sb.append(",\"command\":").append(jsonStr(job.failureCommand));
                if (job.failureLogPath != null) sb.append(",\"logPath\":").append(jsonStr(job.failureLogPath));
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

    /**
     * Backs up every file an apply job is about to overwrite to
     * {@code .redkite/work/pristine/<relative path>}, mirroring the project's own directory layout,
     * before any real project file is touched. A safety net beyond the in-memory {@code originals}
     * map the apply job already reverts from on a failed validation — if the server dies mid-apply
     * (between writing changes and reverting them), these are what's left to restore from by hand.
     * Best-effort: a failure to back up a file is logged, never thrown.
     */
    private static void savePristineCopies(Path projectRoot, Map<Path, String> originals) {
        Path pristineDir = com.redkite.maven.ValidationRunner.redkiteWorkDir(projectRoot).resolve("pristine");
        for (Map.Entry<Path, String> entry : originals.entrySet()) {
            Path relative = projectRoot.relativize(entry.getKey());
            Path dest = pristineDir.resolve(relative);
            try {
                Files.createDirectories(dest.getParent());
                Files.writeString(dest, entry.getValue(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                LOGGER.warning(() -> "Could not save pristine copy of " + entry.getKey() + " to " + dest + ": " + e.getMessage());
            }
        }
    }

    /**
     * Preserves every file an apply job touched exactly as it stood when post-apply validation
     * failed, mirrored to {@code .redkite/work/<relative path>} — called before the in-memory
     * revert writes the originals back over them. Complements {@code ValidationRunner}'s own
     * {@code .redkite/work/pom.xml} snapshot (which only ever covers the one POM path a build was
     * actually invoked against): an apply can touch several files at once (submodule POMs,
     * pomPatches), and every one of them needs to survive the revert for diagnosis, not just the
     * root. Best-effort: a failure to save a file is logged, never thrown.
     */
    private static void saveFailedCopies(Path projectRoot, Map<Path, String> modified) {
        Path workDir = com.redkite.maven.ValidationRunner.redkiteWorkDir(projectRoot);
        for (Map.Entry<Path, String> entry : modified.entrySet()) {
            Path relative = projectRoot.relativize(entry.getKey());
            Path dest = workDir.resolve(relative);
            try {
                Files.createDirectories(dest.getParent());
                Files.writeString(dest, entry.getValue(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                LOGGER.warning(() -> "Could not save failed copy of " + entry.getKey() + " to " + dest + ": " + e.getMessage());
            }
        }
    }

    /**
     * Clears everything in {@code .redkite/work/} that only matters while an apply might still need
     * to recover — pristine pre-apply backups and any failed-file snapshots — once an apply job
     * finishes successfully; a failed apply leaves them in place for inspection instead of calling
     * this. {@code build.log} is deliberately left alone: it always reflects the most recent
     * validation run regardless of outcome (see {@code ValidationRunner.saveLog}), so it survives
     * every cleanup, and so does the {@code work/} directory itself. Best-effort: a failure to clean
     * up is logged, never thrown.
     */
    private static void cleanupWorkDir(Path projectRoot) {
        Path workDir = com.redkite.maven.ValidationRunner.redkiteWorkDir(projectRoot);
        if (!Files.exists(workDir)) return;
        Path buildLog = workDir.resolve("build.log");
        try (var walk = Files.walk(workDir)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                if (p.equals(workDir) || p.equals(buildLog)) return;
                try {
                    if (Files.isDirectory(p)) {
                        try (var children = Files.list(p)) {
                            if (children.findAny().isPresent()) return; // not empty (holds build.log or similar) — keep
                        }
                    }
                    Files.delete(p);
                } catch (IOException e) {
                    LOGGER.warning(() -> "Could not delete " + p + ": " + e.getMessage());
                }
            });
        } catch (IOException e) {
            LOGGER.warning(() -> "Could not clean up " + workDir + ": " + e.getMessage());
        }
    }
}
