package com.redkite.maven;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RemediationApplierTest {

    private final RemediationApplier applier = new RemediationApplier();

    static final String POM_WITH_DEPENDENCIES = """
            <project>
              <dependencies>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>service-b</artifactId>
                  <version>2.0.0</version>
                </dependency>
              </dependencies>
            </project>
            """;

    static final String POM_WITH_DEP_MGMT = """
            <project>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.slf4j</groupId>
                    <artifactId>slf4j-api</artifactId>
                    <version>1.7.30</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </project>
            """;

    @Test
    void addsExclusionToMatchingDependency() {
        String result = applier.applyExclusion(POM_WITH_DEPENDENCIES,
                "com.example", "service-b",
                "com.google.guava", "guava",
                "Convergence fix");
        assertTrue(result.contains("<exclusion>"), "Should contain <exclusion>");
        assertTrue(result.contains("<groupId>com.google.guava</groupId>"));
        assertTrue(result.contains("<artifactId>guava</artifactId>"));
        assertTrue(result.contains("redkite:exclusion"), "Should have redkite comment");
    }

    @Test
    void doesNotAddExclusionToNonMatchingDependency() {
        String result = applier.applyExclusion(POM_WITH_DEPENDENCIES,
                "com.example", "service-a", // doesn't exist in POM
                "com.google.guava", "guava",
                "Convergence fix");
        assertFalse(result.contains("guava"), "Should not add exclusion for non-matching dep");
    }

    @Test
    void doesNotDuplicateExistingRedkiteExclusion() {
        String withExclusion = applier.applyExclusion(POM_WITH_DEPENDENCIES,
                "com.example", "service-b",
                "com.google.guava", "guava",
                "Convergence fix");
        String twice = applier.applyExclusion(withExclusion,
                "com.example", "service-b",
                "com.google.guava", "guava",
                "Convergence fix");
        // Should only appear once
        int count = countOccurrences(twice, "redkite:exclusion");
        assertEquals(1, count, "Should not duplicate existing redkite exclusion");
    }

    @Test
    void addsDependencyManagementPinWhenNoneExists() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String result = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "Convergence fix");
        assertTrue(result.contains("<dependencyManagement>"));
        assertTrue(result.contains("<version>32.1.2-jre</version>"));
        assertTrue(result.contains("redkite:dependency-management"));
    }

    @Test
    void pinCommentUsesHardcodedVersionAndRemovalNote() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String result = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "Convergence fix");
        assertTrue(result.contains("redkite:dependency-management pin"),
                "Marker should be renamed to include 'pin'");
        assertTrue(result.contains("remove this comment to prevent RedKite managing this dependency"),
                "Comment should note how to opt a dependency out of RedKite management");
        // The <version> must be the literal value, never a ${...} property reference.
        assertTrue(result.contains("<version>32.1.2-jre</version>"));
        assertFalse(result.contains("${"), "Dependency management pins must never use property references");
    }

    @Test
    void injectsIntExistingDependencyManagement() {
        String result = applier.applyDependencyManagementPin(POM_WITH_DEP_MGMT,
                "com.google.guava", "guava", "32.1.2-jre", "Convergence fix");
        assertTrue(result.contains("<version>32.1.2-jre</version>"),
                "Should add guava version in existing depMgmt");
        assertTrue(result.contains("slf4j-api"),
                "Should preserve existing dep mgmt entries");
    }

    @Test
    void updatesVersionOfExistingRedkitePin() {
        String pom = applier.applyDependencyManagementPin("<project><dependencies/></project>",
                "com.google.guava", "guava", "31.0-jre", "Initial fix");
        String updated = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "Updated fix");
        assertTrue(updated.contains("32.1.2-jre"), "Should update to new version");
        assertFalse(updated.contains("31.0-jre"), "Should not keep old version");
    }

    @Test
    void updatesLegacyPreRenameCommentInPlaceInsteadOfDuplicating() {
        // Simulates a pin written by an older RedKite version, before the marker was renamed
        // from "redkite:dependency-management" to "redkite:dependency-management pin".
        String pom = """
                <project>
                  <dependencyManagement>
                    <dependencies>
                      <!-- redkite:dependency-management groupId="org.springframework.boot" artifactId="spring-boot-starter-amqp" version="3.5.15" reason="Convergence fix" -->
                      <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-amqp</artifactId>
                        <version>3.5.15</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String updated = applier.applyDependencyManagementPin(pom,
                "org.springframework.boot", "spring-boot-starter-amqp", "3.5.16", "CVE fix");
        int occurrences = countOccurrences(updated, "spring-boot-starter-amqp");
        assertEquals(2, occurrences,
                "Should update the legacy pin in place (once in the comment, once in <artifactId>), not duplicate it");
        assertTrue(updated.contains("3.5.16"), "Should update to the new version");
        assertFalse(updated.contains("3.5.15"), "Should not keep the old version behind as a duplicate entry");
    }

    @Test
    void stripsRedkiteExclusionsFromPom() {
        String withExclusion = applier.applyExclusion(POM_WITH_DEPENDENCIES,
                "com.example", "service-b",
                "com.google.guava", "guava", "Fix");
        String stripped = applier.stripRedkiteRemediations(withExclusion);
        assertFalse(stripped.contains("redkite:exclusion"), "Should remove redkite comment");
        assertFalse(stripped.contains("<exclusion>"), "Should remove exclusion block");
    }

    @Test
    void stripsRedkiteDepMgmtPinFromPom() {
        String pom = "<project><dependencies/></project>";
        String withPin = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "Fix");
        String stripped = applier.stripRedkiteRemediations(withPin);
        assertFalse(stripped.contains("redkite:dependency-management"), "Should remove redkite comment");
        assertFalse(stripped.contains("guava"), "Should remove the dependency entry");
    }

    private static int countOccurrences(String text, String pattern) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(pattern, idx)) != -1) {
            count++;
            idx += pattern.length();
        }
        return count;
    }
}
