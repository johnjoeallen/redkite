package com.redkite.server;

import com.redkite.core.domain.TransitiveConflictFinding;
import com.redkite.maven.ManagedVersionResolver.ManagedVersion;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Planning dependency-management pins from enforcer findings, reconciled with the project's own declarations. */
class EnforcerAnalysisTest {
    @TempDir
    Path project;

    // Pin planning never touches the store; none of these coordinates belong to a BOM-probed family.
    private final EnforcerAnalysis analysis = new EnforcerAnalysis(null);

    private static TransitiveConflictFinding conflict(String artifactId, String resolved, String... conflicting) {
        return new TransitiveConflictFinding("g", artifactId, resolved, List.of(conflicting), List.of(),
                "dependencyConvergence", null, List.of());
    }

    private static ManagedVersion declared(String version) {
        return new ManagedVersion(version, null, null, false);
    }

    @Test
    void plannedPinsTakeTheHighestVersionUnlessTheProjectDeclaresAnotherLine() {
        List<TransitiveConflictFinding> findings = List.of(
                conflict("plain", "1.0", "1.2", "0.9"),
                conflict("raised", "1.5.25", "1.5.38"),
                conflict("other-line", "4.1.135", "4.2.16"),
                conflict("blank-declared", "2.0", "2.1"),
                conflict("no-versions", null),
                conflict("only-conflicting", null, "3.0"));
        Map<String, ManagedVersion> projectManaged = Map.of(
                "g:raised", declared("1.5.25"),
                "g:other-line", declared("4.1.135"),
                "g:blank-declared", declared(" "),
                "g:no-versions", declared("7.0"));
        assertEquals(List.of("g:plain:1.2", "g:raised:1.5.38", "g:other-line:4.1.135", "g:blank-declared:2.1",
                        "g:no-versions:7.0", "g:only-conflicting:3.0"),
                analysis.computePlannedPins(findings, List.of(), project, projectManaged));
        assertEquals(List.of(), analysis.computePlannedPins(List.of(conflict("none", null)), List.of(), project, Map.of()));
    }

    @Test
    void storedPinsAreReconciledTheSameWay() {
        assertEquals(List.of("g:plain:1.2", "g:raised:1.5.38", "g:other-line:4.1.135"),
                analysis.realignStoredPins(List.of("g:plain:1.2", "g:raised:1.5.38", "g:other-line:4.2.16", "nocolon", ":x"),
                        List.of(), project, Map.of("g:raised", declared("1.5.25"), "g:other-line", declared("4.1.135"))));
    }
}
