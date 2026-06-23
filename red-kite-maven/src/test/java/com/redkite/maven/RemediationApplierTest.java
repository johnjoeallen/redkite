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
