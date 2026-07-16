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
    void reusesExistingExclusionsBlockInsteadOfAddingASecondOne() {
        // Maven's schema allows at most one <exclusions> element per dependency. A dependency
        // that already has its own exclusions must get the RedKite exclusion appended into the
        // existing block, not a second <exclusions> sibling (which is invalid).
        String pom = """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>service-b</artifactId>
                      <version>2.0.0</version>
                      <exclusions>
                        <exclusion>
                          <groupId>commons-io</groupId>
                          <artifactId>commons-io</artifactId>
                        </exclusion>
                      </exclusions>
                    </dependency>
                  </dependencies>
                </project>
                """;
        String result = applier.applyExclusion(pom,
                "com.example", "service-b",
                "com.google.guava", "guava",
                "Convergence fix");
        assertEquals(1, countOccurrences(result, "<exclusions>"),
                "Must reuse the existing <exclusions> block, not add a second one");
        assertTrue(result.contains("<artifactId>guava</artifactId>"), "New exclusion added");
        assertTrue(result.contains("<artifactId>commons-io</artifactId>"), "Existing exclusion preserved");
    }

    @Test
    void producesWellFormedXmlOutput() throws Exception {
        String result = applier.applyDependencyManagementPin(POM_WITH_DEP_MGMT,
                "com.google.guava", "guava", "32.1.2-jre", "Convergence fix");
        // Must re-parse cleanly
        javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new java.io.ByteArrayInputStream(result.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    @Test
    void updatesVersionPropertyWhenProjectEntryUsesOne() {
        // A project entry managed through a version property (typically shared by sibling
        // modules, e.g. ${logback.version} driving logback-core AND logback-classic) must have
        // the PROPERTY updated — hardcoding the single entry would silently detach it from its
        // family and allow the family to split across versions.
        String pom = """
                <project>
                  <properties>
                    <logback.version>1.5.25</logback.version>
                  </properties>
                  <dependencyManagement>
                    <dependencies>
                      <!-- CVE-2026-1225: force logback-core to patched version -->
                      <dependency>
                        <groupId>ch.qos.logback</groupId>
                        <artifactId>logback-core</artifactId>
                        <version>${logback.version}</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String updated = applier.applyDependencyManagementPin(pom,
                "ch.qos.logback", "logback-core", "1.5.38", "Enforcer dependency convergence fix by RedKite");

        assertEquals(1, countOccurrences(updated, "<artifactId>logback-core</artifactId>"),
                "Should not add a duplicate entry");
        assertTrue(updated.contains("<logback.version>1.5.38</logback.version>"),
                "Should update the property value");
        assertTrue(updated.contains("<version>${logback.version}</version>"),
                "The entry must keep its property reference");
        assertFalse(updated.contains("redkite:dependency-management"),
                "Property updates must not convert the entry into a RedKite-managed pin");
    }

    @Test
    void leavesEntryUntouchedWhenItsPropertyIsNotDefinedInThisPom() {
        // If the property comes from somewhere this POM can't see (e.g. an external parent),
        // converting the entry into a standalone hardcoded pin is worse than not applying.
        String pom = """
                <project>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>ch.qos.logback</groupId>
                        <artifactId>logback-core</artifactId>
                        <version>${logback.version}</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String updated = applier.applyDependencyManagementPin(pom,
                "ch.qos.logback", "logback-core", "1.5.38", "Fix");
        assertEquals(pom, updated, "Must not modify the POM when the property can't be located");
    }

    @Test
    void takesOverExistingLiteralDepMgmtEntryInsteadOfDuplicating() {
        // A project entry with a literal version (no property) is taken over in place rather
        // than duplicated, which Maven rejects with "must be unique".
        String pom = """
                <project>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>ch.qos.logback</groupId>
                        <artifactId>logback-core</artifactId>
                        <version>1.5.25</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String updated = applier.applyDependencyManagementPin(pom,
                "ch.qos.logback", "logback-core", "1.5.38", "Fix");
        assertEquals(1, countOccurrences(updated, "<artifactId>logback-core</artifactId>"),
                "Should take over the existing entry, not add a duplicate");
        assertTrue(updated.contains("<version>1.5.38</version>"), "Should update the version in place");
        assertFalse(updated.contains("1.5.25"), "Old version should be gone");
        assertTrue(updated.contains("redkite:dependency-management pin"),
                "Should mark the taken-over entry as RedKite-managed");
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

    @Test
    void userPinUsesDistinctTagFromComputedPin() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String result = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "User pinned via RedKite", true);
        assertTrue(result.contains("redkite:user-pin"), "Should use the user-pin marker");
        assertFalse(result.contains("redkite:dependency-management"),
                "Should not also carry the computed-pin marker");
        assertEquals(java.util.Set.of("com.google.guava:guava"), applier.findUserPinnedCoordinates(result));
    }

    @Test
    void removeUserPinStripsMarkerButKeepsHardcodedVersion() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String pinned = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "User pinned via RedKite", true);
        String unpinned = applier.removeUserPin(pinned, "com.google.guava", "guava");
        assertFalse(unpinned.contains("redkite:user-pin"), "Marker should be gone");
        assertTrue(unpinned.contains("<version>32.1.2-jre</version>"), "Version entry should remain");
        assertTrue(applier.findUserPinnedCoordinates(unpinned).isEmpty());
    }

    @Test
    void userPinOnPropertyManagedFamilyProtectsEverySharingDependency() {
        // Two dependencies sharing a version property (a "family") get pinned together, since
        // they can't have independent versions.
        String pom = """
                <project>
                  <properties>
                    <logback.version>1.5.25</logback.version>
                  </properties>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>ch.qos.logback</groupId>
                        <artifactId>logback-core</artifactId>
                        <version>${logback.version}</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>ch.qos.logback</groupId>
                      <artifactId>logback-classic</artifactId>
                      <version>${logback.version}</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        String pinned = applier.applyDependencyManagementPin(pom,
                "ch.qos.logback", "logback-core", "1.5.25", "User pinned via RedKite", true);
        assertTrue(pinned.contains("redkite:user-pin"));
        assertEquals(java.util.Set.of("ch.qos.logback:logback-core", "ch.qos.logback:logback-classic"),
                applier.findUserPinnedCoordinates(pinned),
                "Both family members sharing the property should be reported as pinned");

        String unpinned = applier.removeUserPin(pinned, "ch.qos.logback", "logback-core");
        assertFalse(unpinned.contains("redkite:user-pin"));
        assertTrue(unpinned.contains("<logback.version>1.5.25</logback.version>"),
                "Property value should be preserved after un-pinning");
        assertTrue(applier.findUserPinnedCoordinates(unpinned).isEmpty());
    }

    @Test
    void countPinsDistinguishesComputedFromUserPins() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String withComputed = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "Convergence fix");
        String withBoth = applier.applyDependencyManagementPin(withComputed,
                "org.slf4j", "slf4j-api", "2.0.16", "User pinned via RedKite", true);

        RemediationApplier.PinCounts counts = applier.countPins(withBoth);
        assertEquals(2, counts.total());
        assertEquals(1, counts.userPinned());
    }

    @Test
    void countPinsIgnoresExclusionsAndSummaryComment() {
        String withExclusion = applier.applyExclusion(POM_WITH_DEPENDENCIES,
                "com.example", "service-b", "com.google.guava", "guava", "Fix");
        String withSummary = applier.applyPinSummaryComment(withExclusion,
                new RemediationApplier.PinCounts(0, 0), null);
        assertEquals(0, applier.countPins(withSummary).total());
    }

    @Test
    void pinSummaryCommentIsFirstChildAndReplacesOnReapply() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String withSummary = applier.applyPinSummaryComment(pom,
                new RemediationApplier.PinCounts(3, 1), new RemediationApplier.PinCounts(5, 2));
        assertTrue(withSummary.contains("redkite:pin-summary"));
        assertTrue(withSummary.contains("project: 5 redkite pin(s) (2 user pinned)"));
        assertTrue(withSummary.contains("this file: 3 redkite pin(s) (1 user pinned)"));
        int commentIdx = withSummary.indexOf("<!--");
        int firstTagIdx = withSummary.indexOf("<project");
        assertTrue(commentIdx > firstTagIdx && commentIdx < withSummary.indexOf("<dependencies"),
                "Summary comment should be the first child of <project>");

        String updated = applier.applyPinSummaryComment(withSummary,
                new RemediationApplier.PinCounts(4, 1), new RemediationApplier.PinCounts(6, 2));
        assertEquals(1, countOccurrences(updated, "redkite:pin-summary"), "Should replace, not duplicate");
        assertTrue(updated.contains("project: 6 redkite pin(s) (2 user pinned)"));
        assertTrue(updated.contains("this file: 4 redkite pin(s) (1 user pinned)"));
    }

    @Test
    void pinSummaryOmitsProjectTotalsWhenNull() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String withSummary = applier.applyPinSummaryComment(pom,
                new RemediationApplier.PinCounts(2, 0), null);
        assertFalse(withSummary.contains("project:"), "Single-pom projects shouldn't show a redundant project total");
        assertTrue(withSummary.contains("2 redkite pin(s) (0 user pinned)"));
    }

    @Test
    void stripRedkiteRemediationsRemovesPinSummaryComment() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String withSummary = applier.applyPinSummaryComment(pom,
                new RemediationApplier.PinCounts(1, 0), null);
        String stripped = applier.stripRedkiteRemediations(withSummary);
        assertFalse(stripped.contains("redkite:pin-summary"));
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
