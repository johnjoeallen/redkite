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

    // --- family matching, target selection and fallbacks (Netty: no allowlist, no known BOM) ---

    private static ScanComponent netty(long id, String artifactId, String version, boolean direct, boolean snapshot) {
        return new ScanComponent(id, new ComponentCoordinate("io.netty", artifactId), version,
                DependencyScope.COMPILE, direct, VersionSource.LITERAL, "pom.xml", null, Map.of(), snapshot, null, null);
    }

    private static Map<String, String> nettyPins() {
        Map<String, String> pins = new LinkedHashMap<>();
        pins.put("io.netty:netty-handler", "4.1.100");
        pins.put("io.netty:netty-codec", "4.1.90");
        pins.put("nocolon", "1");
        pins.put(":blank-group", "2");
        return pins;
    }

    @Test
    void familyMatchingUsesGroupPrefixesAndAllowlists() {
        FamilyVersionAligner.FamilyGroup cucumber = FamilyVersionAligner.COORDINATED_FAMILIES.get(0);
        assertTrue(cucumber.matches("io.cucumber", "cucumber-core"));
        assertFalse(cucumber.matches("io.cucumber", "unrelated"));
        assertFalse(cucumber.matches("io.cucumberx", "cucumber-core"));
        FamilyVersionAligner.FamilyGroup plain = new FamilyVersionAligner.FamilyGroup("x", "org.x", null);
        assertTrue(plain.matches("org.x.sub", "anything"));
        assertFalse(plain.hasKnownBom());
        assertFalse(new FamilyVersionAligner.FamilyGroup("x", "org.x", null, "org.x", null).hasKnownBom());
    }

    @Test
    void declaredDirectDependencyIsRaisedOnlyWithinItsReleaseLine() {
        List<ScanComponent> components = List.of(
                netty(1, "netty-buffer", "4.1.95", true, false),
                netty(2, "netty-common", "4.2.0-SNAPSHOT", true, true),
                netty(3, "netty-transport", "${netty.version}", true, false),
                netty(4, "netty-resolver", " ", true, false),
                netty(5, "netty-resolver-dns", null, true, false),
                netty(6, "netty-codec-http", "5.0.0", false, false));
        Map<String, String> result = new FamilyVersionAligner(null).align(nettyPins(), components, Map.of());
        assertEquals("4.1.100", result.get("io.netty:netty-handler"));
        assertEquals("4.1.100", result.get("io.netty:netty-codec"));
        assertEquals("1", result.get("nocolon"));
        assertEquals("2", result.get(":blank-group"));

        Map<String, String> olderLine = new FamilyVersionAligner(null).align(nettyPins(),
                List.of(netty(1, "netty-buffer", "4.0.5", true, false)), Map.of());
        assertEquals("4.0.5", olderLine.get("io.netty:netty-handler"), "a project on an older line is not dragged across it");
        assertEquals("4.0.5", olderLine.get("io.netty:netty-codec"));
    }

    @Test
    void withoutADeclarationTheHighestObservedVersionWins() {
        List<ScanComponent> components = List.of(
                netty(1, "netty-buffer", "4.1.120", false, false),
                netty(2, "netty-common", "4.2.0-SNAPSHOT", false, true),
                netty(3, "netty-transport", null, false, false),
                netty(4, "netty-resolver", "4.1.1", false, false));
        Map<String, String> result = new FamilyVersionAligner(null).align(nettyPins(), components, Map.of());
        assertEquals("4.1.120", result.get("io.netty:netty-handler"));
        assertEquals("4.1.120", result.get("io.netty:netty-codec"));
    }

    @Test
    void projectOwnOverridesAreReconciledPerArtifact() {
        Map<String, ManagedVersionResolver.ManagedVersion> own = Map.of(
                "io.netty:netty-codec", new ManagedVersionResolver.ManagedVersion("4.1.80", null, null, false),
                // BOM-governed entries are not a deliberate ceiling
                "io.netty:netty-buffer", new ManagedVersionResolver.ManagedVersion("9.9.9", "org.x:bom:1", null, true),
                "unrelated", new ManagedVersionResolver.ManagedVersion("1", null, null, false));
        Map<String, String> raised = new FamilyVersionAligner(null).align(nettyPins(), List.of(), own);
        assertEquals("4.1.90", raised.get("io.netty:netty-codec"), "a raise within the override's release line is kept");
        assertEquals("4.1.100", raised.get("io.netty:netty-handler"));

        Map<String, String> pins = nettyPins();
        pins.put("io.netty:netty-codec", "4.2.0");
        Map<String, String> otherLine = new FamilyVersionAligner(null).align(pins, List.of(), own);
        assertFalse(otherLine.containsKey("io.netty:netty-codec"), "crossing the override's release line keeps the override: no pin");

        Map<String, ManagedVersionResolver.ManagedVersion> blank = Map.of(
                "io.netty:netty-codec", new ManagedVersionResolver.ManagedVersion(" ", null, null, false));
        assertEquals("4.1.90", new FamilyVersionAligner(null).align(nettyPins(), List.of(), blank).get("io.netty:netty-codec"));
    }

    @Test
    void anImportedBomIsProbedAndItsMembersCollapseIntoOnePin() {
        String controller = "io.netty:netty-bom:4.1.90";
        Map<String, ManagedVersionResolver.ManagedVersion> imported = Map.of(
                "io.netty:netty-handler", new ManagedVersionResolver.ManagedVersion("4.1.90", controller, "netty.version", true),
                "io.netty:netty-codec", new ManagedVersionResolver.ManagedVersion("4.1.90", controller, "netty.version", true));
        List<String> probes = new java.util.ArrayList<>();
        FamilyVersionAligner.BomMemberProbe probe = (g, a, v) -> {
            probes.add(g + ":" + a + ":" + v);
            return Map.of(
                    "io.netty:netty-handler", new ManagedVersionResolver.ManagedVersion(v, "io.netty:netty-bom:" + v, null, true),
                    "io.netty:netty-codec", new ManagedVersionResolver.ManagedVersion(v, "io.netty:netty-bom:" + v, null, true));
        };
        Map<String, String> result = new FamilyVersionAligner(probe).align(nettyPins(), List.of(), imported);
        assertEquals(List.of("io.netty:netty-bom:4.1.100"), probes);
        assertEquals("4.1.100", result.get("io.netty:netty-bom"));
        assertFalse(result.containsKey("io.netty:netty-handler"));
        assertFalse(result.containsKey("io.netty:netty-codec"));
    }

    @Test
    void anUnusableProbeFallsBackToBroadcasting() {
        String controller = "io.netty:netty-bom:4.1.90";
        Map<String, ManagedVersionResolver.ManagedVersion> imported = Map.of(
                "io.netty:netty-handler", new ManagedVersionResolver.ManagedVersion("4.1.90", controller, null, true),
                "io.netty:netty-codec", new ManagedVersionResolver.ManagedVersion("4.1.90", controller, null, true));
        for (FamilyVersionAligner.BomMemberProbe probe : List.<FamilyVersionAligner.BomMemberProbe>of(
                (g, a, v) -> { throw new IllegalStateException("offline"); },
                (g, a, v) -> Map.of(),
                (g, a, v) -> null)) {
            Map<String, String> result = new FamilyVersionAligner(probe).align(nettyPins(), List.of(), imported);
            assertEquals("4.1.100", result.get("io.netty:netty-handler"));
            assertEquals("4.1.100", result.get("io.netty:netty-codec"));
            assertFalse(result.containsKey("io.netty:netty-bom"));
        }

        // A controller coordinate that isn't g:a[:v] can't be probed at all.
        Map<String, ManagedVersionResolver.ManagedVersion> odd = Map.of(
                "io.netty:netty-handler", new ManagedVersionResolver.ManagedVersion("4.1.90", "single", null, true));
        Map<String, String> result = new FamilyVersionAligner((g, a, v) -> { throw new AssertionError("not probed"); })
                .align(nettyPins(), List.of(), odd);
        assertEquals("4.1.100", result.get("io.netty:netty-handler"));
    }

    @Test
    void theHighestDeliberateOverrideSetsTheTarget() {
        Map<String, ManagedVersionResolver.ManagedVersion> own = new LinkedHashMap<>();
        own.put("io.netty:netty-codec", new ManagedVersionResolver.ManagedVersion("4.1.80", null, null, false));
        own.put("io.netty:netty-handler", new ManagedVersionResolver.ManagedVersion("4.1.85", null, null, false));
        own.put("io.netty:netty-common", new ManagedVersionResolver.ManagedVersion("4.1.70", null, null, false));
        Map<String, String> pins = new LinkedHashMap<>(Map.of("io.netty:netty-buffer", "4.1.10"));
        assertEquals("4.1.85", new FamilyVersionAligner(null).align(pins, List.of(), own).get("io.netty:netty-buffer"));
    }

    @Test
    void equalVersionsSpelledDifferentlyNeverReplaceTheFirst() {
        Map<String, ManagedVersionResolver.ManagedVersion> own = Map.of(
                "io.netty:netty-handler", new ManagedVersionResolver.ManagedVersion("4.1.85", null, null, false));
        // A declared direct dependency and a pin that equal the declared version keep its spelling.
        Map<String, String> pins = new LinkedHashMap<>();
        pins.put("io.netty:netty-buffer", "4.1.10");
        pins.put("io.netty:netty-codec", "4.1.85.0");
        Map<String, String> result = new FamilyVersionAligner(null).align(pins,
                List.of(netty(1, "netty-transport", "4.1.85.0", true, false)), own);
        assertEquals("4.1.85", result.get("io.netty:netty-buffer"));

        // Without a declaration, the first of two equal observed versions is the floor.
        Map<String, String> floorPins = new LinkedHashMap<>();
        floorPins.put("io.netty:netty-buffer", "4.1.90");
        floorPins.put("io.netty:netty-codec", "4.1.90.0");
        assertEquals("4.1.90", new FamilyVersionAligner(null).align(floorPins, List.of(), Map.of()).get("io.netty:netty-codec"));

        // A pin equal to the project's own override is not a raise: the override stands and the pin goes.
        Map<String, String> overridePins = new LinkedHashMap<>(Map.of("io.netty:netty-handler", "4.1.85.0"));
        assertFalse(new FamilyVersionAligner(null).align(overridePins, List.of(), own).containsKey("io.netty:netty-handler"));
    }

    @Test
    void allowlistedFamiliesOnlyAlignTheirListedArtifacts() {
        Map<String, String> pins = new LinkedHashMap<>();
        pins.put("io.cucumber:cucumber-core", "7.1.0");
        pins.put("io.cucumber:cucumber-java", "7.2.0");
        pins.put("io.cucumber:tag-expressions", "5.0.0");
        Map<String, String> result = new FamilyVersionAligner(null).align(pins, List.of(), Map.of());
        assertEquals("7.2.0", result.get("io.cucumber:cucumber-core"));
        assertEquals("7.2.0", result.get("io.cucumber:cucumber-java"));
        assertEquals("5.0.0", result.get("io.cucumber:tag-expressions"));
    }

    @Test
    void aBomControllerWithoutAVersionStillCollapses() {
        String controller = "io.netty:netty-bom";
        Map<String, ManagedVersionResolver.ManagedVersion> imported = Map.of(
                "io.netty:netty-handler", new ManagedVersionResolver.ManagedVersion("4.1.90", controller, null, true),
                "io.netty:netty-codec", new ManagedVersionResolver.ManagedVersion("4.1.90", controller, null, true));
        FamilyVersionAligner.BomMemberProbe probe = (g, a, v) -> Map.of(
                "io.netty:netty-handler", new ManagedVersionResolver.ManagedVersion(v, controller, null, true),
                "io.netty:netty-codec", new ManagedVersionResolver.ManagedVersion(v, controller, null, true));
        Map<String, String> result = new FamilyVersionAligner(probe).align(nettyPins(), List.of(), imported);
        assertEquals("4.1.100", result.get("io.netty:netty-bom"));
    }
}
