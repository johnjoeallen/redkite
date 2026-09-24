package com.redkite.maven;

import com.redkite.core.domain.ConflictCandidateAction;
import com.redkite.core.domain.ConflictCandidateAction.ActionType;
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

    @Test
    void readsEveryPathVersionFormAndOffersOneExclusionPerParent() {
        String output = """
                Dependency convergence error for com.google.guava:guava:32.1.2-jre paths to dependency are:
                +-com.example:my-app:1.0.0-SNAPSHOT
                  +-com.example:service-a
                    +-com.google.guava:guava:jar:32.1.2-jre:compile
                +-com.example:my-app:1.0.0-SNAPSHOT
                  +-com.example:service-b:2.0.0
                    +-com.google.guava:guava:pom:31.1-jre
                +-com.example:my-app:1.0.0-SNAPSHOT
                  +-com.example:service-c:2.0.0
                    +-com.google.guava:guava:30.0-jre:compile
                +-com.example:my-app:1.0.0-SNAPSHOT
                  +-com.example:service-b:2.0.0
                    +-com.google.guava:guava:29.0-jre
                ]
                """;
        TransitiveConflictFinding f = parser.parse(output).get(0);

        assertEquals(List.of(
                "+-com.example:my-app:1.0.0-SNAPSHOT\n  +-com.example:service-a\n    +-com.google.guava:guava:jar:32.1.2-jre:compile",
                "+-com.example:my-app:1.0.0-SNAPSHOT\n  +-com.example:service-b:2.0.0\n    +-com.google.guava:guava:pom:31.1-jre",
                "+-com.example:my-app:1.0.0-SNAPSHOT\n  +-com.example:service-c:2.0.0\n    +-com.google.guava:guava:30.0-jre:compile",
                "+-com.example:my-app:1.0.0-SNAPSHOT\n  +-com.example:service-b:2.0.0\n    +-com.google.guava:guava:29.0-jre"),
                f.dependencyPaths());
        assertEquals(List.of("31.1-jre", "30.0-jre", "29.0-jre"), f.conflictingVersions());
        assertEquals(List.of(
                new ConflictCandidateAction(ActionType.ADD_DEPENDENCY_MANAGEMENT, "com.google.guava", "guava", "32.1.2-jre", null, null),
                new ConflictCandidateAction(ActionType.ADD_EXCLUSION, "com.google.guava", "guava", "32.1.2-jre", "com.example", "service-a"),
                new ConflictCandidateAction(ActionType.ADD_EXCLUSION, "com.google.guava", "guava", "31.1-jre", "com.example", "service-b"),
                new ConflictCandidateAction(ActionType.ADD_EXCLUSION, "com.google.guava", "guava", "30.0-jre", "com.example", "service-c")),
                f.candidateActions());
    }

    @Test
    void upperBoundPathsUseTheRequiredVersionAfterTheArrow() {
        // No closing "]": the block runs to the end of the output.
        String output = """
                [ERROR] Rule 1: org.apache.maven.enforcer.rules.dependency.RequireUpperBoundDeps failed with message:
                Require upper bound dependencies error for org.slf4j:slf4j-api:jar:1.7.36. Paths to dependency are:
                com.example:my-app:jar:1.0
                  +-org.slf4j:slf4j-api:1.7.25 (managed) <-- org.slf4j:slf4j-api:1.7.30
                com.example:my-app:jar:1.0
                  +-org.slf4j:jcl-over-slf4j:1.7.36
                    +-org.slf4j:slf4j-api:1.7.25 (managed) <-- org.slf4j:slf4j-api:jar:1.7.31:compile
                com.example:my-app:jar:1.0
                  +-com.acme:client:2.0
                    +-org.slf4j:slf4j-api:1.7.25 (managed) <-- org.slf4j:slf4j-api:1.7.32:compile
                com.example:my-app:jar:1.0
                  +-com.acme:other:2.0
                    +-org.slf4j:slf4j-api:1.7.25 (managed) <-- org.slf4j:slf4j-api:pom:1.7.33 (scope)
                com.example:my-app:jar:1.0
                  +-org.slf4j:slf4j-api:1.7.34 <-- org.slf4j:other:1.0
                com.example:my-app:jar:1.0
                  +-org.slf4j:slf4j-api:1.7.35 <-- com.other:slf4j-api:1.0
                com.example:my-app:jar:1.0
                  +-org.slf4j:slf4j-api:1.7.37 <-- nothing""";
        TransitiveConflictFinding f = parser.parse(output).get(0);

        assertEquals("1.7.36", f.resolvedVersion());
        assertEquals(7, f.dependencyPaths().size());
        assertEquals("com.example:my-app:jar:1.0\n  +-org.slf4j:slf4j-api:1.7.25 (managed) <-- org.slf4j:slf4j-api:1.7.30",
                f.dependencyPaths().get(0));
        assertEquals(List.of("1.7.30", "1.7.31", "1.7.32", "1.7.33", "1.7.34", "1.7.35", "1.7.37"),
                f.conflictingVersions());
        assertEquals(List.of(
                new ConflictCandidateAction(ActionType.ADD_DEPENDENCY_MANAGEMENT, "org.slf4j", "slf4j-api", "1.7.36", null, null),
                new ConflictCandidateAction(ActionType.ADD_EXCLUSION, "org.slf4j", "slf4j-api", "1.7.31", "org.slf4j", "jcl-over-slf4j"),
                new ConflictCandidateAction(ActionType.ADD_EXCLUSION, "org.slf4j", "slf4j-api", "1.7.32", "com.acme", "client"),
                new ConflictCandidateAction(ActionType.ADD_EXCLUSION, "org.slf4j", "slf4j-api", "1.7.33", "com.acme", "other")),
                f.candidateActions());
    }

    @Test
    void headerVersionsLoseTheirPackagingPrefixAndTrailingPeriod() {
        String output = """
                [ERROR] Rule 0: DependencyConvergence failed with message:
                Dependency convergence error for g:a:jar:1.0. paths to dependency are:

                Dependency convergence error for g:a:POM:2.0 paths to dependency are:

                Dependency convergence error for g:a:war:3.0 paths to dependency are:

                Dependency convergence error for g:a:ear:4.0 paths to dependency are:

                Dependency convergence error for g:a:test-jar:5.0 paths to dependency are:

                [ERROR] Rule 1: RequireUpperBoundDeps failed with message:
                Require upper bound dependencies error for g:a:bundle:6.0 paths to dependency are:

                Require upper bound dependencies error for g:a:aar:7.0 paths to dependency are:

                Require upper bound dependencies error for g:a:zip:8.0 paths to dependency are:
                """;
        List<TransitiveConflictFinding> findings = parser.parse(output);

        assertEquals(List.of("1.0", "2.0", "3.0", "4.0", "5.0", "6.0", "7.0", "zip:8.0"),
                findings.stream().map(TransitiveConflictFinding::resolvedVersion).toList());
        assertTrue(findings.stream().allMatch(f -> f.dependencyPaths().isEmpty()));
    }
}
