package com.redkite.core.service;

import com.redkite.core.domain.CandidateUpdate;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyFinding;
import com.redkite.core.domain.DependencyFindingReason;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ProposedChangeSet;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.UpdateAction;
import com.redkite.core.domain.VersionSource;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CandidateUpdateResolverTest {

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

    private static ScanComponent literal(String groupId, String artifactId, String version) {
        return new ScanComponent(nextId++, new ComponentCoordinate(groupId, artifactId), version,
                DependencyScope.COMPILE, true, VersionSource.LITERAL, "pom.xml",
                "/project/dependencies/dependency[" + groupId + ":" + artifactId + "]",
                Map.of(), false, "pom.xml#dependency", "pom.xml");
    }

    private static DependencyFinding cve(long componentId, String description) {
        return new DependencyFinding(componentId, DependencyFindingReason.CVE, description);
    }

    @Test
    void twoCveFindingsSharingAControlSetResolveToOneChangePropertyUpdate() {
        // The brief's worked example: CVEs on logback-core (local property) and logback-classic
        // (resolved through a parent's BOM, same property name) must collapse into one property
        // change, not two independent dependency edits.
        ScanComponent core = propertyBacked("ch.qos.logback", "logback-core", "1.5.18", "logback.version");
        ScanComponent classic = parentManaged("ch.qos.logback", "logback-classic", "1.5.18", "logback.version");
        List<ScanComponent> all = List.of(core, classic);

        Map<ComponentCoordinate, String> selected = new LinkedHashMap<>();
        selected.put(core.coordinate(), "1.5.25");
        selected.put(classic.coordinate(), "1.5.25");
        Map<ComponentCoordinate, List<DependencyFinding>> findings = Map.of(
                core.coordinate(), List.of(cve(core.id(), "CVE in logback-core")),
                classic.coordinate(), List.of(cve(classic.id(), "CVE in logback-classic")));

        List<CandidateUpdate> results = CandidateUpdateResolver.resolve(all, selected, findings);

        assertEquals(1, results.size(), "Must not create two independent dependency edits");
        CandidateUpdate update = results.get(0);
        assertEquals(UpdateAction.CHANGE_PROPERTY, update.action());
        assertEquals("property logback.version", update.editableDeclaration());
        assertEquals("1.5.18", update.oldValue());
        assertEquals("1.5.25", update.proposedValue());
        assertEquals(2, update.findingsAddressed().size());
        assertTrue(update.reason().contains("CVE"));

        List<ProposedChangeSet.DependencyMovement> movements = update.resultingChanges().movements();
        assertEquals(2, movements.size());
        assertTrue(movements.stream().anyMatch(m -> m.coordinate().equals(core.coordinate())
                && m.fromVersion().equals("1.5.18") && m.toVersion().equals("1.5.25")));
        assertTrue(movements.stream().anyMatch(m -> m.coordinate().equals(classic.coordinate())
                && m.fromVersion().equals("1.5.18") && m.toVersion().equals("1.5.25")));
    }

    @Test
    void controlSetMemberNotExplicitlySelectedStillAppearsAsACollateralMovement() {
        ScanComponent core = propertyBacked("ch.qos.logback", "logback-core", "1.5.18", "logback.version");
        ScanComponent classic = parentManaged("ch.qos.logback", "logback-classic", "1.5.18", "logback.version");
        List<ScanComponent> all = List.of(core, classic);

        // Only logback-core is explicitly selected — logback-classic must still show up as an
        // affected dependency in the resulting change set, since the property change affects it too.
        Map<ComponentCoordinate, String> selected = Map.of(core.coordinate(), "1.5.25");
        List<CandidateUpdate> results = CandidateUpdateResolver.resolve(all, selected, Map.of());

        assertEquals(1, results.size());
        List<ProposedChangeSet.DependencyMovement> movements = results.get(0).resultingChanges().movements();
        assertTrue(movements.stream().anyMatch(m -> m.coordinate().equals(classic.coordinate())),
                "logback-classic shares the property, so it must appear as a collateral movement");
    }

    @Test
    void highestRequestedVersionWinsWhenSelectionsInOneGroupDisagree() {
        ScanComponent core = propertyBacked("ch.qos.logback", "logback-core", "1.5.18", "logback.version");
        ScanComponent classic = parentManaged("ch.qos.logback", "logback-classic", "1.5.18", "logback.version");
        List<ScanComponent> all = List.of(core, classic);

        Map<ComponentCoordinate, String> selected = new LinkedHashMap<>();
        selected.put(core.coordinate(), "1.5.20");
        selected.put(classic.coordinate(), "1.5.25");

        List<CandidateUpdate> results = CandidateUpdateResolver.resolve(all, selected, Map.of());
        assertEquals(1, results.size());
        assertEquals("1.5.25", results.get(0).proposedValue());
    }

    @Test
    void ungroupedSelectionOnLiteralDirectDependencyIsItsOwnUpgrade() {
        ScanComponent lib = literal("com.example", "lib", "1.0.0");
        List<CandidateUpdate> results = CandidateUpdateResolver.resolve(
                List.of(lib), Map.of(lib.coordinate(), "2.0.0"), Map.of());

        assertEquals(1, results.size());
        CandidateUpdate update = results.get(0);
        assertEquals(UpdateAction.UPGRADE, update.action());
        assertEquals("direct version", update.editableDeclaration());
        assertEquals(1, update.resultingChanges().movements().size());
    }

    @Test
    void downgradeTargetIsClassifiedAsDowngradeAction() {
        ScanComponent lib = literal("com.example", "lib", "2.0.0");
        List<CandidateUpdate> results = CandidateUpdateResolver.resolve(
                List.of(lib), Map.of(lib.coordinate(), "1.0.0"), Map.of());

        assertEquals(UpdateAction.DOWNGRADE, results.get(0).action());
    }

    // --- one selection per controller type ---

    private static ScanComponent sourced(String artifactId, String version, VersionSource source, boolean direct, String owning) {
        return new ScanComponent(nextId++, new ComponentCoordinate("g", artifactId), version,
                DependencyScope.COMPILE, direct, source, "pom.xml", null, Map.of(), false, owning, "pom.xml");
    }

    private static CandidateUpdate single(ScanComponent component, String target) {
        List<CandidateUpdate> results = CandidateUpdateResolver.resolve(List.of(component), Map.of(component.coordinate(), target), Map.of());
        assertEquals(1, results.size());
        return results.get(0);
    }

    @Test
    void eachControllerTypeGetsItsOwnActionAndDescription() {
        CandidateUpdate literal = single(sourced("a", "1.0", VersionSource.LITERAL, true, "pom.xml#dependency"), "1.1");
        assertEquals(UpdateAction.UPGRADE, literal.action());
        assertEquals("direct version", literal.editableDeclaration());

        CandidateUpdate property = single(sourced("a", "1.0", VersionSource.PROPERTY, true, "pom.xml#a.version"), "1.1");
        assertEquals(UpdateAction.CHANGE_PROPERTY, property.action());
        assertEquals("property a.version", property.editableDeclaration());

        CandidateUpdate localDm = single(sourced("a", "1.0", VersionSource.BOM_MANAGED, true, "sub/pom.xml"), "0.9");
        assertEquals(UpdateAction.DOWNGRADE, localDm.action());
        assertEquals("local dependencyManagement (sub/pom.xml)", localDm.editableDeclaration());
        assertTrue(localDm.introducesDowngrade());
        assertFalse(localDm.overridesPlatform());

        CandidateUpdate parentLiteral = single(sourced("a", "1.0", VersionSource.PARENT_MANAGED, false, "org:parent:1#literal"), "1.1");
        assertEquals(UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE, parentLiteral.action());
        assertEquals("parent org:parent:1", parentLiteral.editableDeclaration());
        assertTrue(parentLiteral.overridesPlatform());

        CandidateUpdate parentProperty = single(sourced("a", "1.0", VersionSource.PARENT_MANAGED, false, "org:parent:1#a.version"), "1.1");
        assertEquals(UpdateAction.CHANGE_PROPERTY, parentProperty.action());
        assertFalse(parentProperty.overridesPlatform());

        CandidateUpdate bomLiteral = single(sourced("a", "1.0", VersionSource.PLATFORM_MANAGED, false, "org:bom:1#literal"), "1.1");
        assertEquals(UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE, bomLiteral.action());
        assertEquals("imported BOM org:bom:1", bomLiteral.editableDeclaration());
        assertTrue(bomLiteral.overridesPlatform());

        CandidateUpdate bomProperty = single(sourced("a", "1.0", VersionSource.PLATFORM_MANAGED, false, "org:bom:1#a.version"), "1.1");
        assertEquals(UpdateAction.CHANGE_PROPERTY, bomProperty.action());
        assertFalse(bomProperty.overridesPlatform());

        CandidateUpdate mediated = single(sourced("a", "1.0", VersionSource.UNKNOWN, false, null), "1.1");
        assertEquals(UpdateAction.ADD_DEPENDENCY_MANAGEMENT_OVERRIDE, mediated.action());
        assertEquals("dependency mediation (unmanaged)", mediated.editableDeclaration());
        assertFalse(mediated.overridesPlatform());

        assertEquals("unmanaged", single(sourced("a", "1.0", VersionSource.UNKNOWN, true, null), "1.1").editableDeclaration());
    }

    @Test
    void selectionForAnUnscannedCoordinateMovesFromUnknown() {
        ComponentCoordinate ghost = new ComponentCoordinate("g", "ghost");
        CandidateUpdate update = CandidateUpdateResolver.resolve(List.of(), Map.of(ghost, "1.0"), Map.of()).get(0);
        assertEquals("unmanaged", update.editableDeclaration());
        assertEquals("unknown", update.oldValue());
        assertEquals(List.of(new ProposedChangeSet.DependencyMovement(ghost, "unknown", "1.0")), update.resultingChanges().movements());
        assertEquals("Requested version change", update.reason());
    }

    @Test
    void equivalentVersionSpellingIsNeitherADowngradeNorANoOp() {
        CandidateUpdate update = single(sourced("a", "1.0", VersionSource.LITERAL, true, "pom.xml#dependency"), "1.0.0");
        assertEquals(UpdateAction.UPGRADE, update.action());
        assertFalse(update.introducesDowngrade());
        assertEquals(1, update.resultingChanges().movements().size());
        assertTrue(single(sourced("a", "1.0", VersionSource.LITERAL, true, "pom.xml#dependency"), "1.0").resultingChanges().movements().isEmpty());
    }

    @Test
    void reasonListsEachDistinctFindingReasonOnce() {
        ScanComponent component = literal("g", "r", "1.0");
        List<DependencyFinding> findings = List.of(cve(component.id(), "a"), cve(component.id(), "b"),
                new DependencyFinding(component.id(), DependencyFindingReason.OUTDATED, "c"));
        CandidateUpdate update = CandidateUpdateResolver.resolve(List.of(component),
                Map.of(component.coordinate(), "2.0"), Map.of(component.coordinate(), findings)).get(0);
        assertEquals("CVE, OUTDATED", update.reason());
    }

    @Test
    void versionComparisonHandlesLengthsQualifiersAndCase() {
        assertTrue(CandidateUpdateResolver.compareVersions("1.10", "1.9") > 0);
        assertTrue(CandidateUpdateResolver.compareVersions("1", "1.1") < 0);
        assertTrue(CandidateUpdateResolver.compareVersions("1.1", "1") > 0);
        assertEquals(0, CandidateUpdateResolver.compareVersions("1", "1.0"));
        assertEquals(0, CandidateUpdateResolver.compareVersions("1.0", "1"));
        assertTrue(CandidateUpdateResolver.compareVersions("1.0-alpha", "1.0-beta") < 0);
        assertTrue(CandidateUpdateResolver.compareVersions("1.0.1", "1.0-rc") > 0);
        assertTrue(CandidateUpdateResolver.compareVersions("1.0-rc", "1.0.1") < 0);
        assertEquals(0, CandidateUpdateResolver.compareVersions("1.0-RC", "1.0-rc"));
    }
}
