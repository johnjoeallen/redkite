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
 * Groups dependencies by the single local, editable declaration that controls their version into
 * {@link ControlSet}s: a Maven property (whether a dependency references it directly, or a
 * parent/BOM's own managed entry happens to be written as that same property — either way,
 * editing one property line moves both), a local {@code dependencyManagement} entry, or a
 * literal-versioned parent/BOM entry (which, having no property, cannot be shared with anything
 * else and never forms a group of its own).
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
            String key = groupingKey(controller, component.owningVersionControlPoint());
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

            String label = displayLabel(entry.getKey());
            controlSets.add(new ControlSet(label, List.copyOf(coordinates)));

            Set<String> familyNames = new LinkedHashSet<>();
            for (ComponentCoordinate coordinate : coordinates) {
                ReleaseFamilyRegistry.familyOf(coordinate).map(ReleaseFamily::name).ifPresent(familyNames::add);
            }
            if (familyNames.size() >= 2) {
                String description = "Property or managed declaration '" + label
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

    /** Human-readable form of an internal grouping key, for {@link ControlSet#controllerDescription()}
     *  and warning text — a bare property name rather than the internal {@code "property:"} prefix. */
    private static String displayLabel(String key) {
        if (key.startsWith("property:")) return "property " + key.substring("property:".length());
        if (key.startsWith("localDepMgmt:")) return key.substring("localDepMgmt:".length());
        return key;
    }

    /** The grouping key for one component's controller, or {@code null} if it can't share a
     *  control set with anything. A property name is used as the key on its own — deliberately
     *  ignoring which file/coordinate declares it — since a {@link VersionController.LocalProperty}
     *  override and a parent/BOM's own property-backed managed entry of the same name are, once
     *  Maven resolves the property, the exact same editable value; grouping only by the raw
     *  {@code owningVersionControlPoint} string would miss that they're the same declaration. A
     *  literal-versioned {@link VersionController.ParentDependencyManagement}/{@link VersionController.ImportedBom}
     *  entry has no property to share, so it never groups with anything else. */
    private static String groupingKey(VersionController controller, String owningVersionControlPoint) {
        if (controller instanceof VersionController.LocalProperty p) {
            return "property:" + p.propertyName();
        }
        if (controller instanceof VersionController.LocalDependencyManagement) {
            return "localDepMgmt:" + owningVersionControlPoint;
        }
        if (controller instanceof VersionController.ParentDependencyManagement p && p.propertyName() != null) {
            return "property:" + p.propertyName();
        }
        if (controller instanceof VersionController.ImportedBom b && b.propertyName() != null) {
            return "property:" + b.propertyName();
        }
        return null;
    }
}
