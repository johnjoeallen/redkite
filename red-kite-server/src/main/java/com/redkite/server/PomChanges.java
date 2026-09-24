package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.maven.RemediationApplier;
import com.redkite.core.service.VersionControllerResolver;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.redkite.server.PomXml.*;
import static com.redkite.server.PomPatcher.*;
import static com.redkite.server.Versions.*;

/** Turns version selections and pin toggles into patched POM files, and keeps the pin-summary comments current. */
final class PomChanges {
    private final Store store;
    private final EnforcerAnalysis analysis;

    PomChanges(Store store, EnforcerAnalysis analysis) {
        this.store = store;
        this.analysis = analysis;
    }

    Map<String, String> generatePomPatches(ScanReport report, Map<String, String> sourcePoms, String workingTreePath, Map<String, String> rawUpdates, Map<String, List<TransitiveConflictFinding>> conflictsByKey) throws Exception {
        return generatePomPatches(report, sourcePoms, workingTreePath, rawUpdates, conflictsByKey, Set.of(), Set.of());
    }

    Map<String, String> generatePomPatches(ScanReport report, Map<String, String> sourcePoms, String workingTreePath, Map<String, String> rawUpdates, Map<String, List<TransitiveConflictFinding>> conflictsByKey, Set<Long> pinnedIds, Set<Long> unpinnedIds) throws Exception {
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

        // Every property name the scan's own provenance resolution found actually controlling a
        // component's version — whether declared locally or by a parent/imported BOM (Spring
        // Boot's BOM managing logback-classic via its own ${logback-classic.version}, say). Used
        // below to tell a genuinely orphaned RedKite-created property (nothing anywhere claims it)
        // apart from a project-authored override of a property an inherited BOM controls, which
        // never appears as a literal ${...} reference in this project's own POM text at all.
        Set<String> activeProperties = new LinkedHashSet<>();
        for (ScanComponent c : report.components()) {
            VersionController vc = VersionControllerResolver.resolve(c);
            String propertyName = null;
            if (vc instanceof VersionController.LocalProperty lp) propertyName = lp.propertyName();
            else if (vc instanceof VersionController.ImportedBom ib) propertyName = ib.propertyName();
            else if (vc instanceof VersionController.ParentDependencyManagement pdm) propertyName = pdm.propertyName();
            else if (vc instanceof VersionController.ParentProperty pp) propertyName = pp.propertyName();
            if (propertyName != null) activeProperties.add(propertyName);
        }

        // Property names already owned by the project's parent chain / imported BOMs — checked so
        // normalising a literal version into a new property (below) never shadows one an ancestor
        // relies on for its own, unrelated dependency management (see
        // resolveProjectDeclaredPropertyNames).
        String rootPomKey = selectRootPomKey(sourcePoms, workingTreePath);
        Set<String> reservedPropertyNames = rootPomKey != null && sourcePoms.get(rootPomKey) != null
                ? analysis.resolveProjectDeclaredPropertyNames(Path.of(workingTreePath), Path.of(workingTreePath).resolve(rootPomKey), sourcePoms.get(rootPomKey))
                : Set.of();

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
            result.put(entry.getKey(), patchPomXml(content, fileUpdates, pinnedCoords, unpinnedCoords, activeProperties, reservedPropertyNames));
        }

        // Sync the root POM's declared version properties to match any direct dep upgrades so
        // project-owned version declarations stay aligned across modules.
        RemediationApplier applier = new RemediationApplier();
        if (rootPomKey != null && (!allDirectUpdates.isEmpty() || !pinnedCoords.isEmpty() || !unpinnedCoords.isEmpty())) {
            String rootContent = result.containsKey(rootPomKey) ? result.get(rootPomKey) : sourcePoms.get(rootPomKey);
            if (rootContent != null) {
                String updated = patchPomXml(rootContent, allDirectUpdates, pinnedCoords, unpinnedCoords, activeProperties, reservedPropertyNames);
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
    void refreshPinSummaryComments(RemediationApplier applier, String scanId, Path projectRoot,
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
}
