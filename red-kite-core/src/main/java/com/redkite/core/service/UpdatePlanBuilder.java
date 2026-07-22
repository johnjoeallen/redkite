package com.redkite.core.service;

import com.redkite.core.domain.CandidateUpdate;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyFinding;
import com.redkite.core.domain.ProposedChangeSet;
import com.redkite.core.domain.RecommendationConfidence;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.UpdateAction;
import com.redkite.core.domain.UpdatePlan;
import com.redkite.core.domain.VersionController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds an {@link UpdatePlan} — alternative strategies for fixing the finding(s) on one
 * coordinate, so a caller can compare them rather than only ever seeing the first computable fix.
 *
 * <p>Only strategies genuinely constructible from what RedKite already knows are produced:
 * <ul>
 *   <li>the "natural" fix — whatever {@link CandidateUpdateResolver} would normally propose,
 *       which may be a shared property change affecting sibling dependencies too;
 *   <li>a local-override-only alternative — always available, and unlike the natural fix, never
 *       touches a shared control set (skipped when it would just duplicate the natural fix, i.e.
 *       when that fix is already a single-coordinate override);
 *   <li>pin/ignore — always available, a zero-risk "accept current risk and revisit later".
 * </ul>
 * Deliberately missing: "update the parent to a newer release" and "import a newer BOM" — real
 * alternatives from the design brief, but determining whether some newer parent/BOM version would
 * actually fix a finding means cross-referencing external version metadata for that parent/BOM
 * coordinate itself and re-resolving what it would manage, which isn't wired up here.
 */
public final class UpdatePlanBuilder {
    private UpdatePlanBuilder() {
    }

    public static UpdatePlan buildForCoordinate(
            List<ScanComponent> allComponents,
            ComponentCoordinate coordinate,
            String targetVersion,
            List<DependencyFinding> findings,
            Set<ComponentCoordinate> userPinnedCoordinates) {

        Map<ComponentCoordinate, String> selection = Map.of(coordinate, targetVersion);
        Map<ComponentCoordinate, List<DependencyFinding>> findingsByCoordinate = Map.of(coordinate, findings);

        List<CandidateUpdate> candidates = new ArrayList<>();
        List<CandidateUpdate> natural = CandidateUpdateResolver.resolve(
                allComponents, selection, findingsByCoordinate, userPinnedCoordinates);
        candidates.addAll(natural);

        boolean naturalIsAlreadyASingleCoordinateOverride = natural.size() == 1
                && natural.get(0).action() == UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE
                && natural.get(0).resultingChanges().movements().size() == 1;
        if (!naturalIsAlreadyASingleCoordinateOverride) {
            overrideOnlyCandidate(allComponents, coordinate, targetVersion, findings, userPinnedCoordinates)
                    .ifPresent(candidates::add);
        }

        candidates.add(pinTemporarilyCandidate(allComponents, coordinate, findings));

        return new UpdatePlan(List.copyOf(findings), List.copyOf(candidates));
    }

    private static Map<ComponentCoordinate, ScanComponent> indexByCoordinate(List<ScanComponent> allComponents) {
        Map<ComponentCoordinate, ScanComponent> byCoordinate = new LinkedHashMap<>();
        for (ScanComponent c : allComponents) {
            byCoordinate.putIfAbsent(c.coordinate(), c);
        }
        return byCoordinate;
    }

    private static java.util.Optional<CandidateUpdate> overrideOnlyCandidate(
            List<ScanComponent> allComponents, ComponentCoordinate coordinate, String targetVersion,
            List<DependencyFinding> findings, Set<ComponentCoordinate> userPinnedCoordinates) {
        ScanComponent current = indexByCoordinate(allComponents).get(coordinate);
        if (current == null) return java.util.Optional.empty();
        String oldValue = current.version();
        VersionController controller = VersionControllerResolver.resolve(current);
        boolean overridesPlatform = controller instanceof VersionController.ParentDependencyManagement
                || controller instanceof VersionController.ImportedBom;
        boolean introducesDowngrade = CandidateUpdateResolver.compareVersions(targetVersion, oldValue) < 0;
        String reason = findings.isEmpty() ? "Requested version change" : reasonFrom(findings);
        return java.util.Optional.of(new CandidateUpdate(
                UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE,
                coordinate.groupId() + ":" + coordinate.artifactId() + " dependencyManagement override",
                oldValue,
                targetVersion,
                reason + " (local override — leaves any shared property/declaration untouched)",
                List.copyOf(findings),
                new ProposedChangeSet(List.of(new ProposedChangeSet.DependencyMovement(coordinate, oldValue, targetVersion))),
                RecommendationConfidence.HIGH,
                true,
                userPinnedCoordinates.contains(coordinate),
                introducesDowngrade,
                overridesPlatform));
    }

    private static CandidateUpdate pinTemporarilyCandidate(
            List<ScanComponent> allComponents, ComponentCoordinate coordinate, List<DependencyFinding> findings) {
        ScanComponent current = indexByCoordinate(allComponents).get(coordinate);
        String currentVersion = current != null ? current.version() : "unknown";
        return new CandidateUpdate(
                UpdateAction.PIN_TEMPORARILY,
                coordinate.groupId() + ":" + coordinate.artifactId(),
                currentVersion,
                currentVersion,
                "Accept current risk for now and revisit later — no version changes",
                List.copyOf(findings),
                new ProposedChangeSet(List.of()),
                RecommendationConfidence.HIGH,
                true,
                false,
                false,
                false);
    }

    private static String reasonFrom(List<DependencyFinding> findings) {
        java.util.LinkedHashSet<String> reasons = new java.util.LinkedHashSet<>();
        for (DependencyFinding f : findings) reasons.add(f.reason().name());
        return String.join(", ", reasons);
    }
}
