package com.redkite.core.service;

import com.redkite.core.domain.CandidateUpdate;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.ControlSet;
import com.redkite.core.domain.DependencyFinding;
import com.redkite.core.domain.ProposedChangeSet;
import com.redkite.core.domain.RecommendationConfidence;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.UpdateAction;
import com.redkite.core.domain.VersionController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Resolves a set of user-selected "change this coordinate to this version" requests into
 * {@link CandidateUpdate}s — collapsing selections that share a {@link ControlSet} into one
 * proposed edit instead of one independent edit per component. Matches the design brief's worked
 * example directly: selecting a CVE fix for both {@code logback-core} and {@code logback-classic}
 * (which share the {@code logback.version} property, whether or not each is locally declared)
 * must resolve to one "change the property" update, not two separate dependency edits.
 *
 * <p>Where a shared control set's selections request different target versions, the highest
 * requested version wins — the property can only hold one value, and a higher version is treated
 * as a superset of whatever a lower one was fixing. This mirrors the existing UI's own
 * sibling-version-sync behavior for property-linked dependencies.
 */
public final class CandidateUpdateResolver {
    private CandidateUpdateResolver() {
    }

    /**
     * @param allComponents             every component from the scan — needed to compute control
     *                                  sets and to know each coordinate's current version.
     * @param selectedTargetVersions    coordinates the user selected, each mapped to the version
     *                                  they want it changed to.
     * @param findingsByCoordinate      findings driving each selection, for {@code reason}/
     *                                  {@code findingsAddressed} — may omit or leave empty for a
     *                                  coordinate with no associated finding (a plain manual pick).
     */
    public static List<CandidateUpdate> resolve(
            List<ScanComponent> allComponents,
            Map<ComponentCoordinate, String> selectedTargetVersions,
            Map<ComponentCoordinate, List<DependencyFinding>> findingsByCoordinate) {

        Map<ComponentCoordinate, ScanComponent> currentByCoordinate = new LinkedHashMap<>();
        for (ScanComponent c : allComponents) {
            currentByCoordinate.putIfAbsent(c.coordinate(), c);
        }

        Map<ComponentCoordinate, ControlSet> controlSetByCoordinate = new LinkedHashMap<>();
        for (ControlSet set : ControlSetAnalyzer.analyze(allComponents).controlSets()) {
            for (ComponentCoordinate member : set.members()) {
                controlSetByCoordinate.put(member, set);
            }
        }

        // Group selections: those sharing a control set collapse into one group (keyed by the
        // ControlSet itself — a record, so equal sets from the same analysis pass compare equal);
        // everything else is its own singleton group.
        Map<Object, List<ComponentCoordinate>> groups = new LinkedHashMap<>();
        for (ComponentCoordinate coordinate : selectedTargetVersions.keySet()) {
            ControlSet set = controlSetByCoordinate.get(coordinate);
            Object groupKey = set != null ? set : coordinate;
            groups.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(coordinate);
        }

        List<CandidateUpdate> results = new ArrayList<>();
        for (Map.Entry<Object, List<ComponentCoordinate>> entry : groups.entrySet()) {
            List<ComponentCoordinate> selectedInGroup = entry.getValue();
            ControlSet set = entry.getKey() instanceof ControlSet cs ? cs : null;

            String proposedVersion = selectedInGroup.stream()
                    .map(selectedTargetVersions::get)
                    .max(CandidateUpdateResolver::compareVersions)
                    .orElseThrow();

            List<ComponentCoordinate> affected = set != null ? set.members() : selectedInGroup;
            List<ProposedChangeSet.DependencyMovement> movements = new ArrayList<>();
            for (ComponentCoordinate coordinate : affected) {
                ScanComponent current = currentByCoordinate.get(coordinate);
                String from = current != null ? current.version() : "unknown";
                if (!proposedVersion.equals(from)) {
                    movements.add(new ProposedChangeSet.DependencyMovement(coordinate, from, proposedVersion));
                }
            }

            ScanComponent representative = currentByCoordinate.get(selectedInGroup.get(0));
            VersionController controller = representative != null ? VersionControllerResolver.resolve(representative) : null;
            String oldValue = representative != null ? representative.version() : "unknown";

            List<DependencyFinding> findings = new ArrayList<>();
            for (ComponentCoordinate coordinate : selectedInGroup) {
                findings.addAll(findingsByCoordinate.getOrDefault(coordinate, List.of()));
            }

            results.add(new CandidateUpdate(
                    actionFor(controller, movements),
                    set != null ? set.controllerDescription() : describeController(controller),
                    oldValue,
                    proposedVersion,
                    reasonFor(findings),
                    List.copyOf(findings),
                    new ProposedChangeSet(List.copyOf(movements)),
                    RecommendationConfidence.HIGH,
                    true));
        }
        return results;
    }

    private static UpdateAction actionFor(VersionController controller, List<ProposedChangeSet.DependencyMovement> movements) {
        if (controller instanceof VersionController.LocalProperty) {
            return UpdateAction.CHANGE_PROPERTY;
        }
        if (controller instanceof VersionController.ParentDependencyManagement p && p.propertyName() != null) {
            return UpdateAction.CHANGE_PROPERTY;
        }
        if (controller instanceof VersionController.ImportedBom b && b.propertyName() != null) {
            return UpdateAction.CHANGE_PROPERTY;
        }
        boolean anyDowngrade = movements.stream().anyMatch(m -> compareVersions(m.toVersion(), m.fromVersion()) < 0);
        if (controller instanceof VersionController.LocalDependencyManagement || controller instanceof VersionController.DirectLiteral) {
            return anyDowngrade ? UpdateAction.DOWNGRADE : UpdateAction.UPGRADE;
        }
        // Parent/BOM literal entry, mediation, or unmanaged: nothing local to edit yet — the only
        // available action is adding a fresh local dependencyManagement override.
        return UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE;
    }

    private static String describeController(VersionController controller) {
        if (controller instanceof VersionController.DirectLiteral) return "direct version";
        if (controller instanceof VersionController.LocalProperty p) return "property " + p.propertyName();
        if (controller instanceof VersionController.LocalDependencyManagement d) return "local dependencyManagement (" + d.declaringFile() + ")";
        if (controller instanceof VersionController.ImportedBom b) return "imported BOM " + b.bomCoordinate();
        if (controller instanceof VersionController.ParentDependencyManagement p) return "parent " + p.parentCoordinate();
        if (controller instanceof VersionController.DependencyMediation) return "dependency mediation (unmanaged)";
        return "unmanaged";
    }

    private static String reasonFor(List<DependencyFinding> findings) {
        if (findings.isEmpty()) return "Requested version change";
        Set<String> reasons = new LinkedHashSet<>();
        for (DependencyFinding f : findings) {
            reasons.add(f.reason().name());
        }
        return String.join(", ", reasons);
    }

    // ---- minimal version comparison (kept local — red-kite-core has no dependency on a shared one) ----

    private static final Pattern SEPARATOR = Pattern.compile("[.\\-]");

    private static int compareVersions(String left, String right) {
        if (left.equals(right)) return 0;
        String[] leftParts = SEPARATOR.split(left);
        String[] rightParts = SEPARATOR.split(right);
        int max = Math.max(leftParts.length, rightParts.length);
        for (int i = 0; i < max; i++) {
            String l = i < leftParts.length ? leftParts[i] : "0";
            String r = i < rightParts.length ? rightParts[i] : "0";
            int cmp = compareToken(l, r);
            if (cmp != 0) return cmp;
        }
        return 0;
    }

    private static int compareToken(String left, String right) {
        boolean leftNumeric = left.chars().allMatch(Character::isDigit) && !left.isEmpty();
        boolean rightNumeric = right.chars().allMatch(Character::isDigit) && !right.isEmpty();
        if (leftNumeric && rightNumeric) {
            return Long.compare(Long.parseLong(left), Long.parseLong(right));
        }
        if (leftNumeric != rightNumeric) {
            return leftNumeric ? 1 : -1;
        }
        return left.compareToIgnoreCase(right);
    }
}
