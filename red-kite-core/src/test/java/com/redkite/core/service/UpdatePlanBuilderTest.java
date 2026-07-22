package com.redkite.core.service;

import com.redkite.core.domain.CandidateUpdate;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyFinding;
import com.redkite.core.domain.DependencyFindingReason;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.UpdateAction;
import com.redkite.core.domain.UpdatePlan;
import com.redkite.core.domain.VersionSource;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UpdatePlanBuilderTest {

    private static long nextId = 1;

    private static ScanComponent propertyBacked(String groupId, String artifactId, String version, String propertyName) {
        return new ScanComponent(nextId++, new ComponentCoordinate(groupId, artifactId), version,
                DependencyScope.COMPILE, true, VersionSource.PROPERTY, "pom.xml",
                "/project/dependencies/dependency[" + groupId + ":" + artifactId + "]",
                Map.of(), false, "pom.xml#" + propertyName, "pom.xml");
    }

    private static ScanComponent parentManaged(String groupId, String artifactId, String version, String propertyName) {
        return new ScanComponent(nextId++, new ComponentCoordinate(groupId, artifactId), version,
                DependencyScope.COMPILE, false, VersionSource.PARENT_MANAGED, "pom.xml",
                "/project/dependency-tree/dependency[" + groupId + ":" + artifactId + "]",
                Map.of(), false, "org.example:parent-pom:1.0.0#" + propertyName, "pom.xml");
    }

    private static ScanComponent mediated(String groupId, String artifactId, String version) {
        return new ScanComponent(nextId++, new ComponentCoordinate(groupId, artifactId), version,
                DependencyScope.COMPILE, false, VersionSource.UNKNOWN, "pom.xml",
                "/project/dependency-tree/dependency[" + groupId + ":" + artifactId + "]",
                Map.of(), false, "pom.xml#dependencyTree", "pom.xml");
    }

    private static List<DependencyFinding> cve(long componentId) {
        return List.of(new DependencyFinding(componentId, DependencyFindingReason.CVE, "CVE"));
    }

    @Test
    void sharedControlSetOffersNaturalPropertyChangeOverrideOnlyAndPinAlternatives() {
        ScanComponent core = propertyBacked("ch.qos.logback", "logback-core", "1.5.18", "logback.version");
        ScanComponent classic = parentManaged("ch.qos.logback", "logback-classic", "1.5.18", "logback.version");
        List<ScanComponent> all = List.of(core, classic);

        UpdatePlan plan = UpdatePlanBuilder.buildForCoordinate(
                all, core.coordinate(), "1.5.25", cve(core.id()), Set.of());

        assertEquals(3, plan.candidates().size(), "natural (property change) + override-only + pin");

        CandidateUpdate natural = findByAction(plan, UpdateAction.CHANGE_PROPERTY);
        assertEquals(2, natural.resultingChanges().movements().size(), "shared property affects both dependencies");

        CandidateUpdate override = findByAction(plan, UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE);
        assertEquals(1, override.resultingChanges().movements().size(), "override-only must not touch the sibling");
        assertEquals(core.coordinate(), override.resultingChanges().movements().get(0).coordinate());

        assertNotNull(findByAction(plan, UpdateAction.PIN_TEMPORARILY));
    }

    @Test
    void overrideAlternativeIsSkippedWhenNaturalFixIsAlreadyASingleCoordinateOverride() {
        ScanComponent lib = mediated("com.example", "lib", "1.0.0");
        UpdatePlan plan = UpdatePlanBuilder.buildForCoordinate(
                List.of(lib), lib.coordinate(), "2.0.0", cve(lib.id()), Set.of());

        assertEquals(2, plan.candidates().size(), "natural override + pin, no duplicate override alternative");
        assertEquals(1, plan.candidates().stream().filter(c -> c.action() == UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE).count());
    }

    @Test
    void overrideAlternativeOnAParentManagedCoordinateFlagsThatItOverridesThePlatform() {
        ScanComponent classic = parentManaged("ch.qos.logback", "logback-classic", "1.5.18", "logback.version");
        UpdatePlan plan = UpdatePlanBuilder.buildForCoordinate(
                List.of(classic), classic.coordinate(), "1.5.25", cve(classic.id()), Set.of());

        CandidateUpdate override = findByAction(plan, UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE);
        assertTrue(override.overridesPlatform());
    }

    @Test
    void userPinnedCoordinateIsFlaggedAsConflicting() {
        ScanComponent lib = mediated("com.example", "lib", "1.0.0");
        UpdatePlan plan = UpdatePlanBuilder.buildForCoordinate(
                List.of(lib), lib.coordinate(), "2.0.0", cve(lib.id()), Set.of(lib.coordinate()));

        CandidateUpdate override = findByAction(plan, UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE);
        assertTrue(override.conflictsWithUserPin());
    }

    @Test
    void pinTemporarilyNeverChangesAnyVersion() {
        ScanComponent lib = mediated("com.example", "lib", "1.0.0");
        UpdatePlan plan = UpdatePlanBuilder.buildForCoordinate(
                List.of(lib), lib.coordinate(), "2.0.0", cve(lib.id()), Set.of());

        CandidateUpdate pin = findByAction(plan, UpdateAction.PIN_TEMPORARILY);
        assertTrue(pin.resultingChanges().movements().isEmpty());
        assertEquals(pin.oldValue(), pin.proposedValue());
    }

    private static CandidateUpdate findByAction(UpdatePlan plan, UpdateAction action) {
        return plan.candidates().stream().filter(c -> c.action() == action).findFirst()
                .orElseThrow(() -> new AssertionError("No candidate with action " + action));
    }
}
