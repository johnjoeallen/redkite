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
}
