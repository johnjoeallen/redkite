package com.redkite.maven;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionSource;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class FamilyVersionAlignerTest {

    private static final String JACKSON_GROUP_ID = "com.fasterxml.jackson";
    private static final String JACKSON_BOM_ARTIFACT = "jackson-bom";

    private static ManagedVersionResolver.ManagedVersion bomManaged(String version, String controllerCoordinate) {
        return new ManagedVersionResolver.ManagedVersion(version, controllerCoordinate, "jackson.version", true);
    }

    private static ScanComponent component(long id, String groupId, String artifactId, String version, boolean direct) {
        return new ScanComponent(id, new ComponentCoordinate(groupId, artifactId), version,
                DependencyScope.COMPILE, direct, VersionSource.BOM_MANAGED, "pom.xml", null,
                Map.of(), false, null, null);
    }

    /** A probe reflecting the real Jackson 2.22.1 BOM's shape: core/databind at 2.22.1,
     *  annotations at 2.22 (no patch digit) — verified live against Maven Central during planning. */
    private static FamilyVersionAligner.BomMemberProbe realJackson2_22_1Probe(String controller) {
        return (bomGroupId, bomArtifactId, version) -> {
            assertEquals(JACKSON_GROUP_ID, bomGroupId);
            assertEquals(JACKSON_BOM_ARTIFACT, bomArtifactId);
            assertEquals("2.22.1", version, "Only the family's own target version should ever be probed");
            return Map.of(
                    "com.fasterxml.jackson.core:jackson-core", bomManaged("2.22.1", controller),
                    "com.fasterxml.jackson.core:jackson-databind", bomManaged("2.22.1", controller),
                    "com.fasterxml.jackson.core:jackson-annotations", bomManaged("2.22", controller));
        };
    }

    // --- Scenario 1 & 3: governed members keep independent versions, never broadcast ---

    @Test
    void bomGovernedMembersKeepIndependentVersionsNeverBroadcast() {
        // pins holds the computed convergence winners (what each artifact NEEDS to become);
        // projectManaged reflects the CURRENT state (the older BOM release presently imported).
        Map<String, String> pins = new LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-core", "2.22.1",
                "com.fasterxml.jackson.core:jackson-databind", "2.22.1",
                "com.fasterxml.jackson.core:jackson-annotations", "2.22"));
        String controller = JACKSON_GROUP_ID + ":" + JACKSON_BOM_ARTIFACT + ":2.21.4";
        Map<String, ManagedVersionResolver.ManagedVersion> projectManaged = Map.of(
                "com.fasterxml.jackson.core:jackson-core", bomManaged("2.21.5", controller),
                "com.fasterxml.jackson.core:jackson-databind", bomManaged("2.21.5", controller),
                "com.fasterxml.jackson.core:jackson-annotations", bomManaged("2.21", controller));

        Map<String, String> result = new FamilyVersionAligner(realJackson2_22_1Probe(controller))
                .align(pins, List.of(), projectManaged);

        assertEquals("2.22.1", result.get("com.fasterxml.jackson:jackson-bom"),
                "core+databind share the BOM's own version and are already imported through it — collapsed into one pin");
        assertNull(result.get("com.fasterxml.jackson.core:jackson-core"));
        assertNull(result.get("com.fasterxml.jackson.core:jackson-databind"));
        assertEquals("2.22", result.get("com.fasterxml.jackson.core:jackson-annotations"),
                "annotations must never be forced to 2.22.1 just because its siblings landed there");
    }

    @Test
    void identicalBomManagedVersionsNeedNoPin() {
        String controller = JACKSON_GROUP_ID + ":" + JACKSON_BOM_ARTIFACT + ":2.22.1";
        Map<String, String> pins = new LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-databind", "2.22.1"));
        Map<String, ManagedVersionResolver.ManagedVersion> projectManaged = Map.of(
                "com.fasterxml.jackson.core:jackson-databind", bomManaged("2.22.1", controller));

        Map<String, String> result = new FamilyVersionAligner(null).align(pins, List.of(), projectManaged);

        assertTrue(result.isEmpty(), "Already matches what the BOM manages — nothing to pin");
    }

    // --- Scenario 6: an explicit project override is recognised, never silently replaced ---

    @Test
    void projectOverrideBelowComputedWinnerIsKeptNotSilentlyReplaced() {
        // The project deliberately pins jackson-databind to 2.20.5 (a direct entry, no controlling
        // BOM/parent). A convergence finding's raw winner (2.19.0) is BELOW that — the override
        // must win outright, exactly like it did before this artifact belonged to any family logic.
        Map<String, String> pins = new LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-databind", "2.19.0"));
        Map<String, ManagedVersionResolver.ManagedVersion> projectManaged = Map.of(
                "com.fasterxml.jackson.core:jackson-databind",
                new ManagedVersionResolver.ManagedVersion("2.20.5", null, null, false));

        Map<String, String> result = new FamilyVersionAligner(null).align(pins, List.of(), projectManaged);

        assertTrue(result.isEmpty(), "The declared override already covers the winner — nothing to change, and it must not be replaced");
    }

    @Test
    void projectOverrideRaisedWithinItsOwnReleaseLineIsKeptAsItsOwnPin() {
        Map<String, String> pins = new LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-databind", "2.20.9"));
        Map<String, ManagedVersionResolver.ManagedVersion> projectManaged = Map.of(
                "com.fasterxml.jackson.core:jackson-databind",
                new ManagedVersionResolver.ManagedVersion("2.20.5", null, null, false));

        Map<String, String> result = new FamilyVersionAligner(null).align(pins, List.of(), projectManaged);

        assertEquals("2.20.9", result.get("com.fasterxml.jackson.core:jackson-databind"),
                "A same-release-line raise over the project's own override is a legitimate, minimal fix — kept as its own pin");
    }

    // --- Scenario 10: the Jackson 2.22.1 regression, reproduced without any project-declared BOM
    // import at all (the project manages Jackson artifacts individually) — this is the shape of
    // the updated convergence-fixture: nothing in projectManaged, purely a raise-only-floor family
    // target, resolved against the family's well-known BOM coordinate as a fallback. ---

    @Test
    void jacksonBomRegression_noProjectImport_probedAgainstTheFamiliesKnownBom() {
        Map<String, String> pins = new LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-core", "2.22.1",
                "com.fasterxml.jackson.core:jackson-databind", "2.22.1",
                "com.fasterxml.jackson.core:jackson-annotations", "2.22"));

        Map<String, String> result = new FamilyVersionAligner(realJackson2_22_1Probe(null))
                .align(pins, List.of(), Map.of());

        assertEquals("2.22.1", result.get("com.fasterxml.jackson.core:jackson-core"));
        assertEquals("2.22.1", result.get("com.fasterxml.jackson.core:jackson-databind"));
        assertEquals("2.22", result.get("com.fasterxml.jackson.core:jackson-annotations"),
                "jackson-annotations must never be pinned to 2.22.1 — that artifact does not exist");
        assertNull(result.get("com.fasterxml.jackson:jackson-bom"),
                "Nothing to collapse into — the project doesn't import this BOM today, so there's no property to bump");
    }

    @Test
    void collapseIsSkippedWhenProbeCannotVerifyEveryMember() {
        Map<String, String> pins = new LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-core", "2.22.1",
                "com.fasterxml.jackson.core:jackson-databind", "2.22.1"));
        String controller = JACKSON_GROUP_ID + ":" + JACKSON_BOM_ARTIFACT + ":2.21.4";
        Map<String, ManagedVersionResolver.ManagedVersion> projectManaged = Map.of(
                "com.fasterxml.jackson.core:jackson-core", bomManaged("2.21.5", controller),
                "com.fasterxml.jackson.core:jackson-databind", bomManaged("2.21.5", controller));

        // Probe "succeeds" but doesn't actually confirm jackson-databind at the target version —
        // the collapse must not go through on a partial/unverifiable result.
        FamilyVersionAligner.BomMemberProbe probe = (g, a, v) -> Map.of(
                "com.fasterxml.jackson.core:jackson-core", bomManaged("2.22.1", controller));

        Map<String, String> result = new FamilyVersionAligner(probe).align(pins, List.of(), projectManaged);

        assertEquals("2.22.1", result.get("com.fasterxml.jackson.core:jackson-core"));
        assertEquals("2.22.1", result.get("com.fasterxml.jackson.core:jackson-databind"),
                "Falls back to the plain target when the probe has no data for this member");
        assertNull(result.get("com.fasterxml.jackson:jackson-bom"), "Never collapse on an unverified probe result");
    }

    @Test
    void noProbeConfiguredFallsBackToTheOriginalBroadcastBehaviorRatherThanThrowing() {
        // Disabling the probe (null) means there's no way to learn each member's real version for
        // the target release, so this documents an explicit, known limitation: without a probe,
        // RedKite is no better than before (annotations DOES get broadcast to core's version here)
        // — production wiring (step 7) always supplies a real probe backed by PomFetcher, so this
        // path only matters for callers that deliberately disable it. The point of this test is
        // that doing so degrades safely (no exception, no worse than the pre-fix behavior) rather
        // than that the degraded output is desirable.
        Map<String, String> pins = new LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-core", "2.22.1",
                "com.fasterxml.jackson.core:jackson-annotations", "2.21"));
        String controller = JACKSON_GROUP_ID + ":" + JACKSON_BOM_ARTIFACT + ":2.21.4";
        Map<String, ManagedVersionResolver.ManagedVersion> projectManaged = Map.of(
                "com.fasterxml.jackson.core:jackson-core", bomManaged("2.21.5", controller),
                "com.fasterxml.jackson.core:jackson-annotations", bomManaged("2.21", controller));

        Map<String, String> result = new FamilyVersionAligner(null).align(pins, List.of(), projectManaged);

        assertEquals("2.22.1", result.get("com.fasterxml.jackson.core:jackson-core"));
        assertEquals("2.22.1", result.get("com.fasterxml.jackson.core:jackson-annotations"));
        assertNull(result.get("com.fasterxml.jackson:jackson-bom"), "Never collapses without a probe to verify against");
    }

    // --- Regression safety net: ungoverned release-train families (no BOM at all) keep the
    // pre-existing broadcast behavior, which is correct for them (every module of a Netty release
    // really does share one literal version). ---

    @Test
    void ungovernedFamilyWithNoProjectDeclarationRaisesEveryMemberToTheHighestObserved() {
        Map<String, String> pins = new LinkedHashMap<>(Map.of(
                "io.netty:netty-buffer", "4.1.130.Final",
                "io.netty:netty-handler", "4.1.135.Final"));

        Map<String, String> result = new FamilyVersionAligner(null).align(pins, List.of(), Map.of());

        assertEquals("4.1.135.Final", result.get("io.netty:netty-buffer"));
        assertEquals("4.1.135.Final", result.get("io.netty:netty-handler"));
    }

    @Test
    void ungovernedFamilyWithADirectDeclaredDependencyWinsWithinItsReleaseLine() {
        Map<String, String> pins = new LinkedHashMap<>(Map.of("io.netty:netty-buffer", "4.2.16.Final"));
        List<ScanComponent> components = List.of(component(1L, "io.netty", "netty-common", "4.1.135.Final", true));

        Map<String, String> result = new FamilyVersionAligner(null).align(pins, components, Map.of());

        assertEquals("4.1.135.Final", result.get("io.netty:netty-buffer"),
                "A transitively-observed higher version on a different release line must not drag the family across the line the project declared");
    }
}
