package com.redkite.maven;

import com.redkite.core.domain.ConflictCandidateAction;
import com.redkite.core.domain.TransitiveConflictFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConflictOutputParserTest {

    private final ConflictOutputParser parser = new ConflictOutputParser();

    static final String CONVERGENCE_OUTPUT = """
            [INFO] --- enforcer:3.4.1:enforce (default) @ my-app ---
            [WARNING] Rule 0: org.apache.maven.plugins.enforcer.DependencyConvergence failed with message:
            Failed while enforcing releasability the error(s) are [
            Dependency convergence error for com.google.guava:guava:32.1.2-jre paths to dependency are:
            +-com.example:my-app:1.0.0-SNAPSHOT
              +-com.example:service-a:1.0.0
                +-com.google.guava:guava:32.1.2-jre
            +-com.example:my-app:1.0.0-SNAPSHOT
              +-com.example:service-b:2.0.0
                +-com.google.guava:guava:31.1-jre
            ]
            [INFO] BUILD FAILURE
            """;

    static final String UPPER_BOUND_OUTPUT = """
            [INFO] --- enforcer:3.4.1:enforce (default) @ my-app ---
            [WARNING] Rule 0: org.apache.maven.plugins.enforcer.RequireUpperBoundDeps failed with message:
            Failed while enforcing RequireUpperBoundDeps. The error(s) are [
            Require upper bound dependencies error for org.slf4j:slf4j-api:1.7.36 paths to dependency are:
            +-com.example:my-app:1.0.0-SNAPSHOT
              +-org.slf4j:slf4j-api:1.7.25
            +-com.example:my-app:1.0.0-SNAPSHOT
              +-com.example:service-a:1.0.0
                +-org.slf4j:slf4j-api:1.7.36
            ]
            [INFO] BUILD FAILURE
            """;

    @Test
    void parsesEmptyOutputToEmptyList() {
        assertTrue(parser.parse("").isEmpty());
        assertTrue(parser.parse(null).isEmpty());
        assertTrue(parser.parse("[INFO] BUILD SUCCESS").isEmpty());
    }

    @Test
    void parsesDependencyConvergenceFinding() {
        List<TransitiveConflictFinding> findings = parser.parse(CONVERGENCE_OUTPUT);
        assertEquals(1, findings.size());
        TransitiveConflictFinding f = findings.get(0);
        assertEquals("com.google.guava", f.groupId());
        assertEquals("guava", f.artifactId());
        assertEquals("32.1.2-jre", f.resolvedVersion());
        assertEquals("dependencyConvergence", f.ruleName());
        assertTrue(f.conflictingVersions().contains("31.1-jre"),
                "Expected conflicting version 31.1-jre in " + f.conflictingVersions());
        assertFalse(f.conflictingVersions().contains("32.1.2-jre"),
                "Resolved version should not be in conflicting versions");
    }

    @Test
    void parsesRequireUpperBoundDepsFinding() {
        List<TransitiveConflictFinding> findings = parser.parse(UPPER_BOUND_OUTPUT);
        assertEquals(1, findings.size());
        TransitiveConflictFinding f = findings.get(0);
        assertEquals("org.slf4j", f.groupId());
        assertEquals("slf4j-api", f.artifactId());
        assertEquals("1.7.36", f.resolvedVersion());
        assertEquals("requireUpperBoundDeps", f.ruleName());
        assertTrue(f.conflictingVersions().contains("1.7.25"),
                "Expected 1.7.25 as conflicting version");
    }

    @Test
    void generatesAddDependencyManagementAction() {
        List<TransitiveConflictFinding> findings = parser.parse(CONVERGENCE_OUTPUT);
        assertFalse(findings.isEmpty());
        TransitiveConflictFinding f = findings.get(0);
        assertTrue(f.candidateActions().stream()
                .anyMatch(a -> a.type() == ConflictCandidateAction.ActionType.ADD_DEPENDENCY_MANAGEMENT
                        && "com.google.guava".equals(a.groupId())
                        && "guava".equals(a.artifactId())
                        && "32.1.2-jre".equals(a.version())),
                "Expected ADD_DEPENDENCY_MANAGEMENT action for guava:32.1.2-jre");
    }

    @Test
    void generatesAddExclusionActionsForConflictingPaths() {
        List<TransitiveConflictFinding> findings = parser.parse(CONVERGENCE_OUTPUT);
        assertFalse(findings.isEmpty());
        TransitiveConflictFinding f = findings.get(0);
        boolean hasExclusion = f.candidateActions().stream()
                .anyMatch(a -> a.type() == ConflictCandidateAction.ActionType.ADD_EXCLUSION
                        && "com.google.guava".equals(a.groupId())
                        && "guava".equals(a.artifactId()));
        assertTrue(hasExclusion, "Expected ADD_EXCLUSION action for guava");
    }

    @Test
    void parsesMultipleFindings() {
        String combined = CONVERGENCE_OUTPUT + "\n" + UPPER_BOUND_OUTPUT;
        List<TransitiveConflictFinding> findings = parser.parse(combined);
        assertEquals(2, findings.size());
    }
}
