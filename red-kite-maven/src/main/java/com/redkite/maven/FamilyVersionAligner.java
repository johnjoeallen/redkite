package com.redkite.maven;

import com.redkite.core.domain.ScanComponent;
import com.redkite.core.service.SemanticVersionComparator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Aligns computed convergence-fix pins for members of a coordinated dependency family — replacing
 * the historical approach of broadcasting one literal version onto every family member, which is
 * wrong whenever a real BOM manages different members at different literal versions (e.g. the
 * Jackson 2.22.1 BOM manages {@code jackson-core}/{@code jackson-databind} at {@code 2.22.1} but
 * {@code jackson-annotations} at {@code 2.22} — broadcasting the family's own version string would
 * pin {@code jackson-annotations} to an artifact that doesn't exist).
 *
 * <p>The target release for the family is still chosen the same way as before (the project's own
 * declared version for the family, raised only within its release line by observed conflicts; or,
 * failing that, the highest version observed anywhere for the family). What changes is what gets
 * written for each member once that target is known:
 * <ul>
 *   <li>A member the project explicitly overrides itself (a direct dependencyManagement entry,
 *       not something a BOM/parent contributes) keeps that override — reconciled against the
 *       computed winner per artifact, never touched by the family-wide target.</li>
 *   <li>Otherwise, if the family's controlling BOM coordinate is knowable — either because the
 *       project already imports it, or because it's one of the small set of coordinated families
 *       with a well-known BOM ({@link FamilyGroup#bomGroupId()}) — that BOM is probed at the
 *       target version via {@link BomMemberProbe}, and each member gets ITS OWN version from that
 *       probe, not the broadcast target string.</li>
 *   <li>A member the probe has no data for (or when no BOM is knowable at all) falls back to the
 *       target string directly — the original, safe behavior for genuine release trains (Netty,
 *       Cucumber, JUnit, etc.) that really do share one literal version and have no BOM to ask.</li>
 * </ul>
 * When two or more members land on the target version through a BOM they're already imported via,
 * their pins collapse into one pin keyed at the BOM's own coordinate — letting
 * {@code RemediationApplier} bump the driving property in place instead of adding N literal pins.
 */
public final class FamilyVersionAligner {

    @FunctionalInterface
    public interface BomMemberProbe {
        /** What importing {@code bomGroupId:bomArtifactId:bomVersion} as a BOM would manage, per
         *  member artifact. See {@link BomVersionResolver#resolveBomMembers}. */
        Map<String, ManagedVersionResolver.ManagedVersion> resolveMembers(String bomGroupId, String bomArtifactId, String bomVersion);
    }

    /** @param bomGroupId @param bomArtifactId the family's well-known BOM coordinate, when one
     *      exists — probed as a fallback when the project doesn't already import a BOM for this
     *      family itself. {@code null} for families with no single canonical BOM (most of them);
     *      this is curated configuration data, not a special implementation path — the resolution
     *      itself is entirely generic. */
    public record FamilyGroup(String id, String groupIdPrefix, Set<String> artifactAllowlist,
                               String bomGroupId, String bomArtifactId) {
        public FamilyGroup(String id, String groupIdPrefix, Set<String> artifactAllowlist) {
            this(id, groupIdPrefix, artifactAllowlist, null, null);
        }

        public boolean matches(String groupId, String artifactId) {
            boolean groupMatches = groupId.equals(groupIdPrefix) || groupId.startsWith(groupIdPrefix + ".");
            if (!groupMatches) return false;
            return artifactAllowlist == null || artifactAllowlist.contains(artifactId);
        }

        boolean hasKnownBom() {
            return bomGroupId != null && bomArtifactId != null;
        }
    }

    public static final List<FamilyGroup> COORDINATED_FAMILIES = List.of(
            new FamilyGroup("cucumber", "io.cucumber", Set.of(
                    "cucumber-core", "cucumber-gherkin", "cucumber-gherkin-messages", "cucumber-plugin",
                    "datatable", "docstring", "cucumber-java", "cucumber-spring", "cucumber-junit-platform-engine")),
            new FamilyGroup("netty", "io.netty", null),
            new FamilyGroup("aws-sdk", "software.amazon.awssdk", null),
            new FamilyGroup("brave", "io.zipkin.brave", null),
            new FamilyGroup("jetty", "org.eclipse.jetty", null),
            new FamilyGroup("bytebuddy", "net.bytebuddy", null),
            new FamilyGroup("opentelemetry", "io.opentelemetry", null),
            new FamilyGroup("logback", "ch.qos.logback", null),
            // JUnit Jupiter (5.x) and Platform (1.x) are released together but on different
            // version schemes — they must be aligned within themselves, never with each other.
            new FamilyGroup("junit-jupiter", "org.junit.jupiter", null),
            new FamilyGroup("junit-platform", "org.junit.platform", null),
            // Micrometer core (1.1x.y) and tracing (1.x.y) version independently despite the
            // shared groupId, and context-propagation is independent of both.
            new FamilyGroup("micrometer-core", "io.micrometer", Set.of(
                    "micrometer-commons", "micrometer-core", "micrometer-jakarta9", "micrometer-observation",
                    "micrometer-registry-prometheus")),
            new FamilyGroup("micrometer-tracing", "io.micrometer", Set.of(
                    "micrometer-tracing", "micrometer-tracing-bridge-brave", "micrometer-tracing-bridge-otel")),
            new FamilyGroup("jackson", "com.fasterxml.jackson", null,
                    "com.fasterxml.jackson", "jackson-bom"));

    private final BomMemberProbe bomMemberProbe;

    /** @param bomMemberProbe verifies a candidate BOM-coordinate pin before collapsing several
     *      per-member pins into one, and supplies each member's own version for the target release
     *      — pass {@code null} to disable BOM probing entirely (falls back fully to the original
     *      broadcast behavior for every family). */
    public FamilyVersionAligner(BomMemberProbe bomMemberProbe) {
        this.bomMemberProbe = bomMemberProbe;
    }

    /** Pure — no I/O. Returns a new map; does not mutate {@code pins}. */
    public Map<String, String> align(Map<String, String> pins, List<ScanComponent> components,
                                      Map<String, ManagedVersionResolver.ManagedVersion> projectManaged) {
        Map<String, String> result = new LinkedHashMap<>(pins);
        for (FamilyGroup family : COORDINATED_FAMILIES) {
            alignOneFamily(family, result, components, projectManaged);
        }
        return result;
    }

    private void alignOneFamily(FamilyGroup family, Map<String, String> pins, List<ScanComponent> components,
                                 Map<String, ManagedVersionResolver.ManagedVersion> projectManaged) {
        List<String> keys = familyKeys(family, pins.keySet());
        if (keys.isEmpty()) return;

        String target = computeFamilyTarget(family, keys, pins, components, projectManaged);
        if (target == null) return;

        String bomGroupId = null, bomArtifactId = null;
        String discovered = discoverImportedBomController(family, projectManaged);
        if (discovered != null) {
            String[] parts = discovered.split(":", 3);
            if (parts.length >= 2) { bomGroupId = parts[0]; bomArtifactId = parts[1]; }
        } else if (family.hasKnownBom()) {
            bomGroupId = family.bomGroupId();
            bomArtifactId = family.bomArtifactId();
        }

        Map<String, ManagedVersionResolver.ManagedVersion> probedMembers = null;
        if (bomMemberProbe != null && bomGroupId != null) {
            try {
                Map<String, ManagedVersionResolver.ManagedVersion> probed = bomMemberProbe.resolveMembers(bomGroupId, bomArtifactId, target);
                if (probed != null && !probed.isEmpty()) probedMembers = probed;
            } catch (Exception ignored) {
                // Unverifiable — every member falls back to the plain broadcast target below.
            }
        }

        List<String> collapsible = new ArrayList<>();
        for (String key : keys) {
            ManagedVersionResolver.ManagedVersion current = projectManaged.get(key);
            if (current != null && !current.bomImport() && current.controllerCoordinate() == null) {
                // The project's OWN direct declaration for this exact artifact — a deliberate
                // choice, reconciled independently and never touched by the family-wide target.
                applyOwnOverride(pins, key, current.version());
                continue;
            }

            ManagedVersionResolver.ManagedVersion probed = probedMembers != null ? probedMembers.get(key) : null;
            String memberTarget = probed != null ? probed.version() : target;
            if (current != null && memberTarget.equals(current.version())) {
                pins.remove(key); // already correctly managed — nothing to change
                continue;
            }
            pins.put(key, memberTarget);

            boolean collapsibleHere = bomGroupId != null && memberTarget.equals(target)
                    && current != null && bomImportMatches(current, bomGroupId, bomArtifactId);
            if (collapsibleHere) collapsible.add(key);
        }

        if (bomGroupId != null && collapsible.size() >= 2 && probedMembers != null) {
            Map<String, ManagedVersionResolver.ManagedVersion> finalProbed = probedMembers;
            String finalTarget = target;
            boolean allVerified = collapsible.stream()
                    .allMatch(key -> finalProbed.containsKey(key) && finalTarget.equals(finalProbed.get(key).version()));
            if (allVerified) {
                for (String key : collapsible) pins.remove(key);
                pins.put(bomGroupId + ":" + bomArtifactId, target);
            }
        }
    }

    private static void applyOwnOverride(Map<String, String> pins, String key, String managedVersion) {
        String reconciled = reconcile(pins.get(key), managedVersion);
        if (reconciled.equals(managedVersion)) {
            pins.remove(key);
        } else {
            pins.put(key, reconciled);
        }
    }

    /** A BOM the project already imports for one of this family's members, if any — preferred over
     *  the family's curated fallback BOM so an existing property gets bumped rather than a new,
     *  unrelated-looking pin appearing for a BOM the project doesn't actually use. */
    private static String discoverImportedBomController(FamilyGroup family,
            Map<String, ManagedVersionResolver.ManagedVersion> projectManaged) {
        for (Map.Entry<String, ManagedVersionResolver.ManagedVersion> e : projectManaged.entrySet()) {
            String[] ga = e.getKey().split(":", 2);
            if (ga.length != 2 || !family.matches(ga[0], ga[1])) continue;
            ManagedVersionResolver.ManagedVersion mv = e.getValue();
            if (mv.bomImport() && mv.controllerCoordinate() != null) return mv.controllerCoordinate();
        }
        return null;
    }

    private static boolean bomImportMatches(ManagedVersionResolver.ManagedVersion mv, String bomGroupId, String bomArtifactId) {
        if (!mv.bomImport() || mv.controllerCoordinate() == null) return false;
        String[] parts = mv.controllerCoordinate().split(":", 3);
        return parts.length >= 2 && parts[0].equals(bomGroupId) && parts[1].equals(bomArtifactId);
    }

    /** The release to move the family to: the project's own declared version for the family
     *  (raised only within its release line by observed conflicts — a project deliberately on an
     *  older line must not get dragged across it), or, failing that, the highest version observed
     *  anywhere for the family.
     *
     *  <p>Only a DELIBERATE project override (a direct dependencyManagement entry — {@code
     *  controllerCoordinate() == null}) counts as a declared ceiling here. A BOM/parent-governed
     *  entry merely reflects whatever happens to be currently imported, not a deliberate choice to
     *  stay below some line — treating it as a hard ceiling would make it impossible to ever raise
     *  a BOM-governed family across a minor release boundary, which is the normal, common case a
     *  real convergence fix needs to do. */
    private static String computeFamilyTarget(FamilyGroup family, List<String> keys, Map<String, String> pins,
            List<ScanComponent> components, Map<String, ManagedVersionResolver.ManagedVersion> projectManaged) {
        String declaredTarget = null;
        for (Map.Entry<String, ManagedVersionResolver.ManagedVersion> e : projectManaged.entrySet()) {
            String[] ga = e.getKey().split(":", 2);
            if (ga.length != 2 || !family.matches(ga[0], ga[1])) continue;
            if (e.getValue().controllerCoordinate() != null) continue; // BOM/parent-governed — not a deliberate ceiling
            if (declaredTarget == null || SemanticVersionComparator.compare(e.getValue().version(), declaredTarget) > 0) {
                declaredTarget = e.getValue().version();
            }
        }
        for (ScanComponent c : components) {
            String g = c.coordinate().groupId(), a = c.coordinate().artifactId();
            if (c.direct() && family.matches(g, a) && c.version() != null && !c.version().isBlank()
                    && !c.version().contains("${") && !c.snapshot()
                    && (declaredTarget == null || SemanticVersionComparator.compare(c.version(), declaredTarget) > 0)) {
                declaredTarget = c.version();
            }
        }

        if (declaredTarget != null) {
            String target = declaredTarget;
            for (String key : keys) {
                String v = pins.get(key);
                if (SemanticVersionComparator.sameReleaseLine(v, declaredTarget) && SemanticVersionComparator.compare(v, target) > 0) {
                    target = v;
                }
            }
            return target;
        }

        String floor = null;
        for (String key : keys) {
            String v = pins.get(key);
            if (floor == null || SemanticVersionComparator.compare(v, floor) > 0) floor = v;
        }
        for (ScanComponent c : components) {
            String g = c.coordinate().groupId(), a = c.coordinate().artifactId();
            if (family.matches(g, a) && c.version() != null && !c.snapshot()
                    && (floor == null || SemanticVersionComparator.compare(c.version(), floor) > 0)) {
                floor = c.version();
            }
        }
        return floor;
    }

    private static List<String> familyKeys(FamilyGroup family, Set<String> keys) {
        List<String> matches = new ArrayList<>();
        for (String key : keys) {
            int idx = key.indexOf(':');
            if (idx <= 0) continue;
            if (family.matches(key.substring(0, idx), key.substring(idx + 1))) matches.add(key);
        }
        return matches;
    }

    /** Mirrors the pre-existing {@code reconcileWithDeclared} semantics, per artifact: the
     *  project's own declared version is authoritative by default; a computed winner overrides it
     *  only when it's a raise WITHIN the same release line. */
    private static String reconcile(String computed, String managedVersion) {
        if (managedVersion == null || managedVersion.isBlank()) return computed;
        if (computed == null || computed.isBlank()) return managedVersion;
        if (SemanticVersionComparator.sameReleaseLine(computed, managedVersion)
                && SemanticVersionComparator.compare(computed, managedVersion) > 0) {
            return computed;
        }
        return managedVersion;
    }
}
