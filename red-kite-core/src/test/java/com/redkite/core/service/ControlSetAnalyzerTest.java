package com.redkite.core.service;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.ControlSet;
import com.redkite.core.domain.DependencyFinding;
import com.redkite.core.domain.DependencyFindingReason;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionSource;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ControlSetAnalyzerTest {

    private static long nextId = 1;

    private static ScanComponent propertyBacked(String groupId, String artifactId, String version,
                                                 String propertyFile, String propertyName) {
        return new ScanComponent(nextId++, new ComponentCoordinate(groupId, artifactId), version,
                DependencyScope.COMPILE, true, VersionSource.PROPERTY, propertyFile,
                "/project/dependencies/dependency[" + groupId + ":" + artifactId + "]",
                Map.of(), false, propertyFile + "#" + propertyName, propertyFile);
    }

    private static ScanComponent literal(String groupId, String artifactId, String version) {
        return new ScanComponent(nextId++, new ComponentCoordinate(groupId, artifactId), version,
                DependencyScope.COMPILE, true, VersionSource.LITERAL, "pom.xml",
                "/project/dependencies/dependency[" + groupId + ":" + artifactId + "]",
                Map.of(), false, "pom.xml#dependency", "pom.xml");
    }

    @Test
    void sharedPropertyCreatesControlSetWithoutInferringReleaseFamily() {
        // Two artifacts unknown to ReleaseFamilyRegistry, sharing one property. RedKite may
        // conclude "changing shared.version affects both" (a control set) but must not conclude
        // they belong to one upstream release family.
        ScanComponent one = propertyBacked("example.one", "lib-one", "1.0.0", "pom.xml", "shared.version");
        ScanComponent two = propertyBacked("example.two", "lib-two", "1.0.0", "pom.xml", "shared.version");

        ControlSetAnalyzer.Result result = ControlSetAnalyzer.analyze(List.of(one, two));

        assertEquals(1, result.controlSets().size());
        ControlSet set = result.controlSets().get(0);
        assertEquals("property shared.version", set.controllerDescription());
        assertEquals(setOf(one.coordinate(), two.coordinate()), setOf(set.members()));

        assertTrue(result.multiFamilyWarnings().isEmpty(),
                "Neither artifact is a known release family, so there's nothing to flag as multi-family");
        assertTrue(ReleaseFamilyRegistry.familyOf(one.coordinate()).isEmpty());
        assertTrue(ReleaseFamilyRegistry.familyOf(two.coordinate()).isEmpty());
    }

    @Test
    void propertySpanningTwoKnownReleaseFamiliesIsFlaggedForSplitting() {
        ScanComponent logbackCore = propertyBacked("ch.qos.logback", "logback-core", "1.5.18", "pom.xml", "shared.version");
        ScanComponent jacksonDatabind = propertyBacked("com.fasterxml.jackson.core", "jackson-databind", "2.18.3", "pom.xml", "shared.version");

        ControlSetAnalyzer.Result result = ControlSetAnalyzer.analyze(List.of(logbackCore, jacksonDatabind));

        assertEquals(1, result.controlSets().size());
        assertEquals(2, result.multiFamilyWarnings().size());
        for (DependencyFinding warning : result.multiFamilyWarnings()) {
            assertEquals(DependencyFindingReason.MULTI_FAMILY_PROPERTY, warning.reason());
            assertTrue(warning.description().contains("Logback"));
            assertTrue(warning.description().contains("Jackson core"));
        }
    }

    @Test
    void localPropertyAndParentManagedEntryOfSameNameShareOneControlSet() {
        // The worked example from the design brief: logback-core is directly declared against a
        // local ${logback.version} override; logback-classic isn't declared anywhere locally at
        // all — it's controlled by Spring Boot's own BOM entry, which happens to be written as
        // that exact same property name. Editing one line (the local property) moves both, so
        // they must land in the same control set even though their VersionController kinds differ.
        ScanComponent logbackCore = new ScanComponent(nextId++,
                new ComponentCoordinate("ch.qos.logback", "logback-core"), "1.5.25",
                DependencyScope.COMPILE, true, VersionSource.PROPERTY, "pom.xml",
                "/project/dependencies/dependency[ch.qos.logback:logback-core]",
                Map.of(), false, "pom.xml#logback.version", "pom.xml");
        ScanComponent logbackClassic = new ScanComponent(nextId++,
                new ComponentCoordinate("ch.qos.logback", "logback-classic"), "1.5.25",
                DependencyScope.COMPILE, false, VersionSource.PARENT_MANAGED, "pom.xml",
                "/project/dependency-tree/dependency[ch.qos.logback:logback-classic]",
                Map.of(), false, "org.springframework.boot:spring-boot-dependencies:3.5.16#logback.version", "pom.xml");

        ControlSetAnalyzer.Result result = ControlSetAnalyzer.analyze(List.of(logbackCore, logbackClassic));

        assertEquals(1, result.controlSets().size());
        ControlSet set = result.controlSets().get(0);
        assertEquals("property logback.version", set.controllerDescription());
        assertEquals(setOf(logbackCore.coordinate(), logbackClassic.coordinate()), setOf(set.members()));
    }

    @Test
    void logbackFamilyIsRecognizedIndependentlyOfAnySharedProperty() {
        // No shared property at all — each declares its own literal version — yet the curated
        // registry still recognizes the upstream release-family relationship.
        ScanComponent core = literal("ch.qos.logback", "logback-core", "1.5.18");
        ScanComponent classic = literal("ch.qos.logback", "logback-classic", "1.5.18");

        ControlSetAnalyzer.Result result = ControlSetAnalyzer.analyze(List.of(core, classic));
        assertTrue(result.controlSets().isEmpty(), "No shared local declaration controls these — no control set");

        assertEquals("Logback", ReleaseFamilyRegistry.familyOf(core.coordinate()).orElseThrow().name());
        assertEquals("Logback", ReleaseFamilyRegistry.familyOf(classic.coordinate()).orElseThrow().name());
    }

    private static java.util.Set<ComponentCoordinate> setOf(ComponentCoordinate... items) {
        return java.util.Set.of(items);
    }

    private static java.util.Set<ComponentCoordinate> setOf(List<ComponentCoordinate> items) {
        return java.util.Set.copyOf(items);
    }
}
