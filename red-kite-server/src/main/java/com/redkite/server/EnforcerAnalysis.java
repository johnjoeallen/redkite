package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.maven.BomVersionResolver;
import com.redkite.maven.ConflictOutputParser;
import com.redkite.maven.EnforcerRunner;
import com.redkite.maven.FamilyVersionAligner;
import com.redkite.maven.ManagedVersionResolver;
import com.redkite.maven.PomAvailabilityChecker;
import com.redkite.maven.PomFetcher;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.logging.Logger;

import static com.redkite.server.PomXml.*;
import static com.redkite.server.Versions.*;

/** Runs the enforcer for an analysis, verifies a computed dependency-management auto-fix (phase 2) and plans those pins. */
final class EnforcerAnalysis {
    private static final Logger LOGGER = Logger.getLogger(EnforcerAnalysis.class.getName());
    private final PomAvailabilityChecker pomAvailabilityChecker = new PomAvailabilityChecker();

    /**
     * Phase 2: applies computed dep-management pins to a temp copy of all project POMs
     * (with all existing dep management and RedKite remediations stripped) and re-runs the
     * enforcer to verify whether the auto-fix resolves all violations.
     *
     * Returns the remaining findings, an empty list if all resolved, or null if Phase 2 could not run.
     */
    private record Phase2Result(List<TransitiveConflictFinding> remainingFindings, List<String> appliedPins) {}

    private final Store store;

    EnforcerAnalysis(Store store) {
        this.store = store;
    }

    void runEnforcerCheck(Path projectRoot, String scanId, Consumer<String> progress, Consumer<String> onLine) {
        try {
            Path pomPath = projectRoot.resolve("pom.xml");
            com.redkite.maven.TempPomAnalyzer analyzer = new com.redkite.maven.TempPomAnalyzer();
            progress.accept("Dependency management 5");

            // Scan POM files for dep-management entries and RedKite exclusion metadata.
            // This is a pure file read — no Maven invocation needed.
            com.redkite.maven.TempPomAnalyzer.PomMetadata meta = analyzer.scanPomMetadata(projectRoot);
            progress.accept("Dependency management 20");

            // Run the enforcer against the original project (not a temp directory) so that
            // parent-POM resolution and source-file lookup always work correctly.
            // If a previous run established that rules are lifecycle-bound (enforcer:enforce
            // reports no rules), the project flag is set and we skip straight to verify.
            ScanEntry scanEntry = store.getScan(scanId);
            String projectId = scanEntry.projectId();
            List<ScanComponent> components = scanEntry.report().components();
            boolean skipDirectEnforce = store.getProjectEnforcerUseVerify(projectId);
            EnforcerRunner.EnforcerRunResult enfResult = new EnforcerRunner().run(projectRoot, pomPath, skipDirectEnforce, onLine);
            if (enfResult.usedVerifyFallback() && !skipDirectEnforce) {
                store.setProjectEnforcerUseVerify(projectId);
            }
            progress.accept("Dependency management 50");

            String rawOutput = enfResult.rawOutput();
            EnforcerStatus status;
            List<TransitiveConflictFinding> findings = List.of();
            if (enfResult.errorDetail() != null) {
                status = EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE;
                LOGGER.warning(() -> "Enforcer could not start for scan " + scanId + ": " + enfResult.errorDetail());
            } else if (enfResult.passed()) {
                status = EnforcerStatus.ENFORCER_RUN_PASSED;
            } else {
                findings = new ConflictOutputParser().parse(rawOutput);
                if (findings.isEmpty()) {
                    status = EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE;
                    String tail = rawOutput.length() > 2000 ? rawOutput.substring(rawOutput.length() - 2000) : rawOutput;
                    LOGGER.warning(() -> "Enforcer ran but produced no parseable conflict findings for scan "
                            + scanId + ". Raw output (last 2000 chars):\n" + tail);
                } else {
                    status = EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS;
                }
            }

            // Phase 2: verify auto-fix with computed dep-management pins
            progress.accept("Dependency management 60");
            List<TransitiveConflictFinding> phase2Findings = null;
            List<String> phase2Pins = List.of();
            if (status == EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS) {
                Phase2Result p2 = runPhase2Validation(projectRoot, pomPath, findings, skipDirectEnforce, components, onLine);
                if (p2 != null) {
                    phase2Findings = p2.remainingFindings();
                    phase2Pins = p2.appliedPins();
                }
            }
            progress.accept("Dependency management 80");

            // Stale exclusion detection
            Set<String> conflictKeys = findings.stream()
                    .map(f -> f.groupId() + ":" + f.artifactId())
                    .collect(java.util.stream.Collectors.toSet());
            List<String> staleExclusions = meta.allRedkiteExclusions().stream()
                    .filter(ga -> !conflictKeys.contains(ga))
                    .distinct().toList();

            progress.accept("Dependency management 95");
            store.saveEnforcerResult(scanId, status, rawOutput, findings, staleExclusions, phase2Findings,
                    meta.exclusionsStripped(), meta.depMgmtEntries(), phase2Pins);
        } catch (Exception e) {
            LOGGER.log(java.util.logging.Level.WARNING,
                    "Enforcer check failed for scan " + scanId, e);
            store.saveEnforcerResult(scanId, EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE, "",
                    List.of(), List.of(), null, 0, List.of(), List.of());
        }
    }

    private Phase2Result runPhase2Validation(
            Path projectRoot, Path pomPath, List<TransitiveConflictFinding> findings,
            boolean skipDirectEnforce, List<ScanComponent> components, Consumer<String> onLine) {
        try {
            // The project's own (non-RedKite) dep-management entries are deliberate choices —
            // pristine analysis strips them, which resurfaces conflicts the project has already
            // resolved. Respect the project's version for those artifacts instead of re-deriving
            // a winner from the stripped tree (which max-picks and can cross a release line the
            // project deliberately avoided, e.g. Netty 4.1 -> 4.2).
            Map<String, ManagedVersionResolver.ManagedVersion> declared =
                    resolveProjectManagedVersions(projectRoot, pomPath, readFileQuietly(pomPath));
            Map<String, String> rawPins = new LinkedHashMap<>();
            for (TransitiveConflictFinding f : findings) {
                String key = f.groupId() + ":" + f.artifactId();
                ManagedVersionResolver.ManagedVersion managed = declared.get(key);
                String winner = reconcileWithDeclared(computeWinnerVersion(f), managed != null ? managed.version() : null);
                if (winner != null && !winner.isBlank()) {
                    rawPins.put(key, winner);
                }
            }
            Map<String, String> aligned = alignFamilies(rawPins, components, declared, projectRoot);

            // Never recommend/apply a candidate coordinate that doesn't actually exist — a pin
            // that only comes from a broadcast/probe fallback (not directly observed anywhere in
            // the tree) is exactly the case that needs verifying.
            PomFetcher pomFetcher = new PomFetcher(projectRoot);
            Map<String, String> pins = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : aligned.entrySet()) {
                String[] ga = e.getKey().split(":", 2);
                if (ga.length != 2) continue;
                PomAvailabilityChecker.CheckResult check = pomAvailabilityChecker.check(pomFetcher, ga[0], ga[1], e.getValue());
                if (check.status() == PomAvailabilityChecker.Availability.AVAILABLE) {
                    pins.put(e.getKey(), e.getValue());
                } else {
                    String detail = check.detail();
                    LOGGER.warning(() -> "Phase 2: dropping unavailable candidate pin " + e.getKey() + ":" + e.getValue() + " — " + detail);
                }
            }

            List<String> pinsList = pins.entrySet().stream()
                    .map(e -> e.getKey() + ":" + e.getValue())
                    .toList();
            LOGGER.info(() -> "Phase 2: running enforcer with " + pins.size() + " computed dep-management pin(s)");
            EnforcerRunner.EnforcerRunResult r =
                    new com.redkite.maven.TempPomAnalyzer().runWithPins(projectRoot, pomPath, pins, skipDirectEnforce, onLine);
            if (r.passed()) {
                LOGGER.info("Phase 2: all conflicts resolved by auto-fix");
                return new Phase2Result(List.of(), pinsList);
            }
            if (r.errorDetail() != null) return new Phase2Result(null, pinsList);
            List<TransitiveConflictFinding> remaining = new ConflictOutputParser().parse(r.rawOutput());
            LOGGER.info(() -> "Phase 2: " + remaining.size() + " conflict(s) remain after auto-fix");
            return new Phase2Result(remaining, pinsList);
        } catch (Exception e) {
            LOGGER.warning(() -> "Phase 2 validation failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Resolves the project's root POM's own dependency management — including everything reachable
     * through its parent chain and imported BOMs, per member artifact — via
     * {@link BomVersionResolver}. Replaces the old flat, BOM-import-blind parsing: that version
     * folded a BOM import's own coordinate in as if it were a real managed artifact, which is part
     * of how family alignment used to corrupt BOM-governed members (see {@link FamilyVersionAligner}).
     */
    Map<String, ManagedVersionResolver.ManagedVersion> resolveProjectManagedVersions(
            Path projectRoot, Path pomPath, String rootPomXml) {
        try {
            return new BomVersionResolver(new PomFetcher(projectRoot)).resolveProjectDeclared(pomPath, rootPomXml);
        } catch (Exception e) {
            LOGGER.warning(() -> "Could not resolve project dependency management: " + e.getMessage());
            return Map.of();
        }
    }

    /** Every property name declared anywhere across the project's parent chain and imported BOMs
     *  — see {@link BomVersionResolver#resolveProjectDeclaredPropertyNames}. Used by
     *  {@link PomPatcher#patchPomXml} so a newly-introduced property from normalising a literal version never
     *  shadows one an ancestor (e.g. a Spring Boot parent) already owns. */
    Set<String> resolveProjectDeclaredPropertyNames(Path projectRoot, Path pomPath, String rootPomXml) {
        try {
            return new BomVersionResolver(new PomFetcher(projectRoot)).resolveProjectDeclaredPropertyNames(pomPath, rootPomXml);
        } catch (Exception e) {
            LOGGER.warning(() -> "Could not resolve ancestor property names: " + e.getMessage());
            return Set.of();
        }
    }

    /**
     * Computes planned dep-management pins for a set of findings, family-aligned. Used both by
     * {@link #runPhase2Validation} and by display-only fallback paths that recompute pins live
     * when a scan's stored {@code phase2Pins} is empty (e.g. cached data from before Phase 2 ran).
     */
    List<String> computePlannedPins(List<TransitiveConflictFinding> findings, List<ScanComponent> components,
                                            Path projectRoot, Map<String, ManagedVersionResolver.ManagedVersion> projectManaged) {
        Map<String, String> pins = new LinkedHashMap<>();
        for (TransitiveConflictFinding f : findings) {
            String key = f.groupId() + ":" + f.artifactId();
            ManagedVersionResolver.ManagedVersion managed = projectManaged.get(key);
            String winner = reconcileWithDeclared(computeWinnerVersion(f), managed != null ? managed.version() : null);
            if (winner != null && !winner.isBlank()) {
                pins.put(key, winner);
            }
        }
        Map<String, String> aligned = alignFamilies(pins, components, projectManaged, projectRoot);
        return aligned.entrySet().stream().map(e -> e.getKey() + ":" + e.getValue()).toList();
    }

    /**
     * Re-runs family alignment over a stored "G:A:V" pin list. Stored {@code phase2Pins} may
     * predate the family-alignment logic (or fixes to it), so the display/Apply paths must not
     * trust them verbatim — realignment converges the list to the same result a fresh computation
     * would give, and is a no-op on already-aligned pins.
     */
    List<String> realignStoredPins(List<String> storedPins, List<ScanComponent> components,
                                           Path projectRoot, Map<String, ManagedVersionResolver.ManagedVersion> projectManaged) {
        Map<String, String> pins = new LinkedHashMap<>();
        for (String gav : storedPins) {
            int last = gav.lastIndexOf(':');
            if (last <= 0) continue;
            pins.put(gav.substring(0, last), gav.substring(last + 1));
        }
        // A stored pin for an artifact the project itself manages must be reconciled with the
        // project's declared version, same as a fresh computation would be.
        for (Map.Entry<String, String> e : pins.entrySet()) {
            ManagedVersionResolver.ManagedVersion managed = projectManaged.get(e.getKey());
            e.setValue(reconcileWithDeclared(e.getValue(), managed != null ? managed.version() : null));
        }
        Map<String, String> aligned = alignFamilies(pins, components, projectManaged, projectRoot);
        return aligned.entrySet().stream().map(e -> e.getKey() + ":" + e.getValue()).toList();
    }

    /** Wires {@link FamilyVersionAligner} up with a live {@link BomVersionResolver} (backed by a
     *  {@link PomFetcher} rooted at this project) so it can probe a coordinated family's known BOM
     *  before ever broadcasting one version to every member — see {@link FamilyVersionAligner} for
     *  the actual alignment logic and rationale; nothing family-specific lives here anymore. */
    private Map<String, String> alignFamilies(Map<String, String> pins, List<ScanComponent> components,
            Map<String, ManagedVersionResolver.ManagedVersion> projectManaged, Path projectRoot) {
        BomVersionResolver bomResolver = new BomVersionResolver(new PomFetcher(projectRoot));
        return new FamilyVersionAligner(bomResolver::resolveBomMembers).align(pins, components, projectManaged);
    }

    /**
     * Reconciles a computed winner with the version the project itself declares for the same
     * artifact. The declared version is the project's deliberate choice and wins by default; the
     * computed winner overrides it only when it is a raise WITHIN the declared release line
     * (same major.minor — e.g. logback 1.5.25 declared, 1.5.38 required → 1.5.38). A computed
     * winner on a different line (Netty 4.1.135 declared, 4.2.16 observed transitively) must not
     * displace the declared version.
     */
    private String reconcileWithDeclared(String computed, String declaredVersion) {
        if (declaredVersion == null || declaredVersion.isBlank()) return computed;
        if (computed == null || computed.isBlank()) return declaredVersion;
        if (sameReleaseLine(computed, declaredVersion) && compareVersionsSemantic(computed, declaredVersion) > 0) {
            return computed;
        }
        return declaredVersion;
    }

    /** The version to pin for a conflict finding: the highest of its resolved and conflicting versions. */
    private String computeWinnerVersion(TransitiveConflictFinding f) {
        String winner = f.resolvedVersion() != null ? f.resolvedVersion() : "";
        for (String v : f.conflictingVersions()) {
            if (compareVersionsSemantic(v, winner) > 0) winner = v;
        }
        return winner.isBlank() ? null : winner;
    }
}
