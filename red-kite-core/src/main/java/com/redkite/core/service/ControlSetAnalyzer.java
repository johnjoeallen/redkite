package com.redkite.core.service;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.ControlSet;
import com.redkite.core.domain.DependencyFinding;
import com.redkite.core.domain.DependencyFindingReason;
import com.redkite.core.domain.ReleaseFamily;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Groups dependencies by the single local declaration that controls their version — a Maven
 * property or a local {@code dependencyManagement} entry — into {@link ControlSet}s.
 *
 * <p>A control set is only ever proof that changing its controller moves every member together;
 * it is never treated as proof the members are genuinely related upstream (see
 * {@link ReleaseFamilyRegistry}). Where a control set's members resolve, via the curated release-
 * family registry, to two or more distinct upstream families, this also raises a
 * {@link DependencyFindingReason#MULTI_FAMILY_PROPERTY} finding — the property may be binding
 * unrelated release families together and could produce an unavailable or incompatible
 * combination if changed as one unit.
 */
public final class ControlSetAnalyzer {
    private ControlSetAnalyzer() {
    }

    public record Result(List<ControlSet> controlSets, List<DependencyFinding> multiFamilyWarnings) {
    }

    public static Result analyze(List<ScanComponent> components) {
        Map<String, List<ScanComponent>> byController = new LinkedHashMap<>();
        for (ScanComponent component : components) {
            VersionController controller = VersionControllerResolver.resolve(component);
            if (!(controller instanceof VersionController.LocalProperty)
                    && !(controller instanceof VersionController.LocalDependencyManagement)) {
                continue;
            }
            String key = component.owningVersionControlPoint();
            if (key == null) continue;
            byController.computeIfAbsent(key, k -> new ArrayList<>()).add(component);
        }

        List<ControlSet> controlSets = new ArrayList<>();
        List<DependencyFinding> warnings = new ArrayList<>();
        for (Map.Entry<String, List<ScanComponent>> entry : byController.entrySet()) {
            List<ScanComponent> members = entry.getValue();
            Set<ComponentCoordinate> coordinates = new LinkedHashSet<>();
            for (ScanComponent m : members) {
                coordinates.add(m.coordinate());
            }
            // A control set is only interesting once it actually controls more than one
            // declaration — a property or dependencyManagement entry referenced by exactly one
            // dependency doesn't create a coordinated-change relationship worth surfacing.
            if (coordinates.size() < 2) continue;

            controlSets.add(new ControlSet(entry.getKey(), List.copyOf(coordinates)));

            Set<String> familyNames = new LinkedHashSet<>();
            for (ComponentCoordinate coordinate : coordinates) {
                ReleaseFamilyRegistry.familyOf(coordinate).map(ReleaseFamily::name).ifPresent(familyNames::add);
            }
            if (familyNames.size() >= 2) {
                String description = "Property or managed declaration '" + entry.getKey()
                        + "' controls artifacts from multiple upstream release families ("
                        + String.join(", ", familyNames) + "). Changing it may produce an "
                        + "unavailable or incompatible version combination.";
                for (ScanComponent member : members) {
                    warnings.add(new DependencyFinding(member.id(), DependencyFindingReason.MULTI_FAMILY_PROPERTY, description));
                }
            }
        }
        return new Result(controlSets, warnings);
    }
}
