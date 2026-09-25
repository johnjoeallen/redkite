package com.redkite.maven;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

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
    void collapsesAStrayPlainDuplicateWhenTakingOverTheFirstEntry() {
        // Two plain (non-RedKite) dependencyManagement entries for the same coordinate is already
        // an invalid POM ("must be unique") — but if one slips in (bad merge, hand edit), taking
        // over just the first one and leaving the second in place still leaves an unbuildable POM.
        String pom = """
                <project>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>ch.qos.logback</groupId>
                        <artifactId>logback-core</artifactId>
                        <version>1.5.20</version>
                      </dependency>
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
                "Both plain entries must collapse into the single one RedKite took over");
        assertTrue(updated.contains("<version>1.5.38</version>"));
        assertFalse(updated.contains("1.5.20"));
        assertFalse(updated.contains("1.5.25"));
    }

    @Test
    void collapsesAStrayDuplicateLeftAlongsideAnEarlierRedkitePin() {
        // If RedKite's own marked entry already exists but a second, unrelated entry for the same
        // coordinate was independently added later (manual edit, merge), updating only the marked
        // entry (what step 1 alone would do) leaves the stray behind and the build still fails.
        String pom = """
                <project>
                  <dependencyManagement>
                    <dependencies>
                      <!-- redkite:dependency-management pin groupId="ch.qos.logback" artifactId="logback-core" version="1.5.25" reason="Fix" — remove this comment to prevent RedKite managing this dependency -->
                      <dependency>
                        <groupId>ch.qos.logback</groupId>
                        <artifactId>logback-core</artifactId>
                        <version>1.5.25</version>
                      </dependency>
                      <dependency>
                        <groupId>ch.qos.logback</groupId>
                        <artifactId>logback-core</artifactId>
                        <version>1.5.30</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String updated = applier.applyDependencyManagementPin(pom,
                "ch.qos.logback", "logback-core", "1.5.38", "Fix");
        assertEquals(1, countOccurrences(updated, "<artifactId>logback-core</artifactId>"),
                "The stray unrelated entry must be removed, leaving only RedKite's updated pin");
        assertTrue(updated.contains("<version>1.5.38</version>"));
        assertFalse(updated.contains("1.5.30"));
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
                "com.google.guava", "guava", "32.1.2-jre", "User pinned via RedKite", RemediationApplier.PinKind.USER);
        assertTrue(result.contains("redkite:user-pin"), "Should use the user-pin marker");
        assertFalse(result.contains("redkite:dependency-management"),
                "Should not also carry the computed-pin marker");
        assertEquals(java.util.Set.of("com.google.guava:guava"), applier.findUserPinnedCoordinates(result));
    }

    @Test
    void removeUserPinStripsMarkerButKeepsHardcodedVersion() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String pinned = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "User pinned via RedKite", RemediationApplier.PinKind.USER);
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
                "ch.qos.logback", "logback-core", "1.5.25", "User pinned via RedKite", RemediationApplier.PinKind.USER);
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
                "org.slf4j", "slf4j-api", "2.0.16", "User pinned via RedKite", RemediationApplier.PinKind.USER);

        RemediationApplier.PinCounts counts = applier.countPins(withBoth);
        assertEquals(2, counts.total());
        assertEquals(1, counts.userPinned());
    }

    // RedKite no longer writes "unmanaged" markers — leaving a no-CVE/no-conflict transitive
    // alone is now purely the UI's default display state, never persisted to the POM. These tests
    // cover the remaining backward-compat surface: a marker left behind by an older RedKite
    // version (current bare-comment form, or the pre-rename "redkite:ignore" with a full
    // hardcoded <dependency>) must still be recognized and converted into a real pin the moment a
    // fix needs to force a version, and cleaned up by stripRedkiteRemediations.

    @Test
    void applyingAPinOverAnUnmanagedMarkerCreatesTheMissingDependency() {
        // A component marked unmanaged by an older RedKite can later develop a CVE with a fix —
        // applying it must convert the bare comment straight into a real, enforced pin rather than
        // just rewriting the comment text and leaving nothing to actually force the version.
        String marked = """
                <project>
                  <dependencyManagement>
                    <dependencies>
                      <!-- redkite:unmanaged groupId="org.example" artifactId="vuln-lib" reason="x" — no CVE/conflict — unmanaged by RedKite; pick a version to override -->
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String upgraded = applier.applyDependencyManagementPin(marked,
                "org.example", "vuln-lib", "9.9.9", "CVE fix by RedKite");
        assertTrue(upgraded.contains("<dependency>"), "Must create the dependency the rewritten comment claims to pin");
        assertTrue(upgraded.contains("<version>9.9.9</version>"));
        assertFalse(upgraded.contains("redkite:unmanaged"));
        assertEquals(1, applier.countPins(upgraded).total());
    }

    @Test
    void findsAndConvertsLegacyIgnoreMarkerAndItsDependencyEntry() {
        // Pre-rename RedKite versions wrote "redkite:ignore" above a full hardcoded <dependency>.
        // Applying a pin over it must recognize the legacy tag too, updating the existing
        // <dependency> in place rather than leaving the stale marker and duplicating the entry.
        String legacy = """
                <project>
                  <dependencyManagement>
                    <dependencies>
                      <!-- redkite:ignore groupId="com.google.guava" artifactId="guava" version="32.1.2-jre" reason="x" — no CVE/conflict — RedKite leaves this alone; pick a version to override -->
                      <dependency>
                        <groupId>com.google.guava</groupId>
                        <artifactId>guava</artifactId>
                        <version>32.1.2-jre</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String upgraded = applier.applyDependencyManagementPin(legacy,
                "com.google.guava", "guava", "33.0.0-jre", "CVE fix by RedKite");
        assertFalse(upgraded.contains("redkite:ignore"));
        assertTrue(upgraded.contains("<version>33.0.0-jre</version>"));
        assertEquals(1, applier.countPins(upgraded).total());

        String stripped = applier.stripRedkiteRemediations(legacy);
        assertFalse(stripped.contains("redkite:ignore"));
        assertFalse(stripped.contains("<dependency>"), "stripRedkiteRemediations must drop the legacy entry too");
    }

    @Test
    void countPinsDoesNotCountUnmanagedMarkerAsAPin() {
        String pom = "<project>\n  <dependencies/>\n</project>";
        String withPin = applier.applyDependencyManagementPin(pom,
                "com.google.guava", "guava", "32.1.2-jre", "Convergence fix");
        String withBoth = withPin.replace("</dependencyManagement>",
                "<!-- redkite:unmanaged groupId=\"org.slf4j\" artifactId=\"slf4j-api\" reason=\"x\" -->\n  </dependencyManagement>");

        RemediationApplier.PinCounts counts = applier.countPins(withBoth);
        assertEquals(1, counts.total(), "Unmanaged marker must not count as a pin");
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

    // ---------------------------------------------------------------- marker bookkeeping

    private static final String POM_WITH_MARKERS = """
            <project>
              <!-- redkite:pin-summary 3 redkite pin(s) (2 user pinned) -->
              <properties>
                <!-- redkite:user-pin version="1.0" — user pinned -->
                <shared.version>1.0</shared.version>
                <free.version>2.0</free.version>
              </properties>
              <dependencyManagement>
                <dependencies>
                  <!-- redkite:dependency-management pin groupId="g" artifactId="managed" version="3.0" reason="r" -->
                  <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>3.0</version></dependency>
                  <!-- redkite:dependency-management groupId="g" artifactId="legacy" version="4.0" -->
                  <dependency><groupId>g</groupId><artifactId>legacy</artifactId><version>4.0</version></dependency>
                  <!-- redkite:user-pin groupId="g" artifactId="userpinned" version="5.0" -->
                  <dependency><groupId>g</groupId><artifactId>userpinned</artifactId><version>5.0</version></dependency>
                  <!-- redkite:ignore groupId="g" artifactId="ignored" -->
                  <dependency><groupId>g</groupId><artifactId>ignored</artifactId><version>6.0</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>plain</artifactId><version>7.0</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>noversion</artifactId></dependency>
                </dependencies>
              </dependencyManagement>
              <dependencies>
                <dependency>
                  <groupId>g</groupId><artifactId>shared-a</artifactId><version>${shared.version}</version>
                  <exclusions>
                    <!-- redkite:exclusion groupId="x" artifactId="y" reason="r" -->
                    <exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion>
                  </exclusions>
                </dependency>
                <dependency>
                  <groupId>g</groupId><artifactId>free</artifactId><version>${free.version}</version>
                  <exclusions>
                    <!-- redkite:exclusion groupId="x" artifactId="z" reason="r" -->
                    <exclusion><groupId>x</groupId><artifactId>z</artifactId></exclusion>
                    <exclusion><groupId>keep</groupId><artifactId>me</artifactId></exclusion>
                  </exclusions>
                </dependency>
                <dependency><groupId>g</groupId><artifactId>literal</artifactId><version>1.0</version></dependency>
                <!-- redkite:exclusion groupId="dangling" artifactId="marker" -->
              </dependencies>
              <build><plugins>
                <plugin><artifactId>maven-shared-plugin</artifactId><version>${shared.version}</version></plugin>
                <plugin><groupId>org.example</groupId><artifactId>other-plugin</artifactId><version>${shared.version}</version></plugin>
                <plugin><artifactId>unversioned-plugin</artifactId></plugin>
              </plugins></build>
            </project>
            """;

    @Test
    void userPinnedCoordinatesIncludeEverythingSharingAPinnedProperty() {
        assertEquals(Set.of("g:userpinned", "g:shared-a", "org.apache.maven.plugins:maven-shared-plugin", "org.example:other-plugin"),
                applier.findUserPinnedCoordinates(POM_WITH_MARKERS));
    }

    @Test
    void removingAPropertyLevelUserPinKeepsTheValue() {
        String result = applier.removeUserPin(POM_WITH_MARKERS, "g", "shared-a");
        assertFalse(result.contains("redkite:user-pin version="), result);
        assertTrue(result.contains("<shared.version>1.0</shared.version>"), result);
        assertTrue(result.contains("redkite:user-pin groupId=\"g\" artifactId=\"userpinned\""), "other pins stay");

        assertSame(POM_WITH_MARKERS, applier.removeUserPin(POM_WITH_MARKERS, "g", "literal"), "a literal version has no property pin");
        assertSame(POM_WITH_MARKERS, applier.removeUserPin(POM_WITH_MARKERS, "g", "free"), "an unpinned property is left alone");
        assertSame(POM_WITH_MARKERS, applier.removeUserPin(POM_WITH_MARKERS, "g", "absent"));
    }

    @Test
    void stripRemovesEveryRedkiteMarkerButKeepsProjectContent() {
        String stripped = applier.stripRedkiteRemediations(POM_WITH_MARKERS);
        assertFalse(stripped.contains("redkite:"), stripped);
        for (String gone : List.of("managed", "legacy", "userpinned", "ignored"))
            assertFalse(stripped.contains("<artifactId>" + gone + "</artifactId>"), gone + " should be gone: " + stripped);
        assertTrue(stripped.contains("<artifactId>plain</artifactId>"), stripped);
        assertTrue(stripped.contains("<shared.version>1.0</shared.version>"), stripped);
        assertFalse(stripped.contains("<artifactId>y</artifactId>"), stripped);
        assertTrue(stripped.contains("<artifactId>me</artifactId>"), "a hand-written exclusion stays: " + stripped);
        assertEquals(1, stripped.split("<exclusions>", -1).length - 1, "the emptied <exclusions> wrapper is removed: " + stripped);
    }

    @Test
    void dependencyManagementCanBeListedAndStripped() {
        assertEquals(List.of("g:managed:3.0", "g:legacy:4.0", "g:userpinned:5.0", "g:ignored:6.0", "g:plain:7.0"),
                applier.extractDepMgmtEntries(POM_WITH_MARKERS));
        String stripped = applier.stripAllDepManagement(POM_WITH_MARKERS);
        assertFalse(stripped.contains("dependencyManagement"), stripped);
        assertTrue(stripped.contains("<artifactId>shared-a</artifactId>"), stripped);
    }

    @Test
    void exclusionAndPinCounts() {
        assertEquals(3, applier.countRedkiteExclusions(POM_WITH_MARKERS));
        assertEquals(0, applier.countRedkiteExclusions("<project/>"));
        assertEquals(List.of("x:y", "x:z", "dangling:marker"), applier.parseRedkiteExclusions(POM_WITH_MARKERS));
        assertEquals(List.of(), applier.parseRedkiteExclusions("<!-- redkite:exclusion groupId=\"only\" -->"));
        // managed + legacy computed pins, one dependency user pin, one property user pin; "ignore" is not a pin.
        assertEquals(new RemediationApplier.PinCounts(4, 2), applier.countPins(POM_WITH_MARKERS));
    }

    @Test
    void pinSummaryIsReplacedRatherThanDuplicated() {
        String once = applier.applyPinSummaryComment(POM_WITH_MARKERS, new RemediationApplier.PinCounts(4, 2), null);
        assertTrue(once.contains("<!-- redkite:pin-summary 4 redkite pin(s) (2 user pinned) -->"), once);
        assertEquals(1, once.split("redkite:pin-summary", -1).length - 1, once);

        String project = applier.applyPinSummaryComment(once, new RemediationApplier.PinCounts(4, 2), new RemediationApplier.PinCounts(9, 3));
        assertTrue(project.contains("<!-- redkite:pin-summary project: 9 redkite pin(s) (3 user pinned) — this file: 4 redkite pin(s) (2 user pinned) -->"), project);
        assertEquals(1, project.split("redkite:pin-summary", -1).length - 1, project);

        assertTrue(applier.applyPinSummaryComment("<project/>", new RemediationApplier.PinCounts(0, 0), null)
                .contains("<project>\n  <!-- redkite:pin-summary 0 redkite pin(s) (0 user pinned) -->"));
    }

    @Test
    void pinReasonIsEscapedInsideTheMarker() {
        String result = applier.applyDependencyManagementPin(POM_WITH_DEPENDENCIES, "g", "new", "1.0", "a \"quoted\" & <odd> reason");
        assertTrue(result.contains("reason=\"a &quot;quoted&quot; &amp; &lt;odd> reason\""), result);
    }

    @Test
    void treeAnnotationsAreStrippedFromVersions() {
        assertEquals("1.0", RemediationApplier.sanitizeVersion("1.0 (managed) <-- 0.9"));
        assertEquals("1.0", RemediationApplier.sanitizeVersion("1.0"));
        assertEquals("", RemediationApplier.sanitizeVersion(null));
        assertEquals(" 1.0", RemediationApplier.sanitizeVersion(" 1.0"));
    }

    private static final String POM_WITH_ODD_MARKERS = """
            <project>
              <!-- an ordinary comment -->
              <properties>
                <used.version>1.0</used.version>
                <!-- redkite:user-pin version="1.0" — dangling, nothing follows it -->
              </properties>
              <dependencyManagement><dependencies>
                <!-- redkite:dependency-management pin groupId="g" artifactId="x" -->
                <exclusion/>
                <dependency><artifactId>no-group</artifactId><version>1</version></dependency>
                <dependency><groupId>g</groupId><version>1</version></dependency>
              </dependencies></dependencyManagement>
              <dependencies>
                <dependency><artifactId>no-group</artifactId><version>${used.version}</version></dependency>
                <dependency><groupId>g</groupId><artifactId>no-version</artifactId></dependency>
                <dependency><groupId>g</groupId><artifactId>undeclared</artifactId><version>${missing.version}</version></dependency>
                <dependency><groupId>g</groupId><artifactId>d</artifactId><version>1</version>
                  <exclusions>
                    <!-- redkite:exclusion groupId="x" artifactId="" -->
                    <dependency/>
                  </exclusions>
                </dependency>
              </dependencies>
              <build><plugins>
                <plugin><artifactId>versionless</artifactId></plugin>
                <plugin><groupId> </groupId><artifactId>blank-group</artifactId><version>${used.version}</version></plugin>
                <plugin><groupId>g</groupId><version>${used.version}</version></plugin>
              </plugins></build>
            </project>
            """;

    @Test
    void oddlyShapedMarkersAndDeclarationsAreTolerated() {
        assertEquals(Set.of(), applier.findUserPinnedCoordinates(POM_WITH_ODD_MARKERS), "a pin marker with nothing after it pins nothing");
        assertSame(POM_WITH_ODD_MARKERS, applier.removeUserPin(POM_WITH_ODD_MARKERS, "g", "no-version"));
        assertSame(POM_WITH_ODD_MARKERS, applier.removeUserPin(POM_WITH_ODD_MARKERS, "g", "undeclared"));
        assertEquals(List.of(), applier.extractDepMgmtEntries(POM_WITH_ODD_MARKERS));
        assertEquals(List.of(), applier.parseRedkiteExclusions(POM_WITH_ODD_MARKERS), "an empty artifactId is not a coordinate");

        String stripped = applier.stripRedkiteRemediations(POM_WITH_ODD_MARKERS);
        assertFalse(stripped.contains("redkite:"), stripped);
        assertTrue(stripped.contains("<exclusion/>"), "a marker above the wrong element only loses the marker: " + stripped);
        assertTrue(stripped.contains("<exclusions>"), stripped);
        assertTrue(stripped.contains("<!-- an ordinary comment -->"), stripped);

        String summary = applier.applyPinSummaryComment(POM_WITH_ODD_MARKERS, new RemediationApplier.PinCounts(1, 1), null);
        assertTrue(summary.contains("<project>\n  <!-- redkite:pin-summary 1 redkite pin(s) (1 user pinned) -->\n  <!-- an ordinary comment -->"), summary);
    }

    @Test
    void userPinOnAPropertyManagedEntryMarksAndUpdatesTheProperty() {
        String pom = "<project><properties><p.version>1</p.version></properties><dependencyManagement><dependencies>"
                + "<dependency><groupId>g</groupId><artifactId>a</artifactId><version>${p.version}</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        String pinned = applier.applyDependencyManagementPin(pom, "g", "a", "2", null, RemediationApplier.PinKind.USER);
        assertTrue(pinned.contains("redkite:user-pin version=\"2\""), pinned);
        assertTrue(pinned.contains("<p.version>2</p.version>"), pinned);

        String repinned = applier.applyDependencyManagementPin(pinned, "g", "a", "3", "again", RemediationApplier.PinKind.USER);
        assertTrue(repinned.contains("redkite:user-pin version=\"3\""), repinned);
        assertEquals(1, repinned.split("redkite:user-pin", -1).length - 1, repinned);

        String same = applier.applyDependencyManagementPin(repinned, "g", "a", "3", null, RemediationApplier.PinKind.USER);
        assertTrue(same.contains("<p.version>3</p.version>"), same);

        String inherited = pom.replace("<properties><p.version>1</p.version></properties>", "");
        assertSame(inherited, applier.applyDependencyManagementPin(inherited, "g", "a", "2", null, RemediationApplier.PinKind.USER),
                "a property this POM doesn't define is left alone");
    }

    @Test
    void pinningIntoAnEmptyDependencyManagementReusesIt() {
        String result = applier.applyDependencyManagementPin("<project><dependencyManagement/></project>", "g", "a", "1.0", "r");
        assertEquals(1, result.split("<dependencyManagement", -1).length - 1, "a second block would be a duplicate tag: " + result);
        assertTrue(result.contains("<artifactId>a</artifactId>"), result);
    }

    @Test
    void aPropertyManagedPinCollapsesDuplicateEntriesElsewhere() {
        String pom = "<project><properties><p.version>1</p.version></properties>"
                + "<dependencyManagement><dependencies>"
                + "<dependency><groupId>g</groupId><artifactId>a</artifactId><version>${p.version}</version></dependency>"
                + "</dependencies></dependencyManagement>"
                + "<profiles><profile><id>x</id><dependencyManagement><dependencies>"
                + "<!-- stray -->"
                + "<dependency><groupId>g</groupId><artifactId>a</artifactId><version>0.9</version></dependency>"
                + "<dependency><groupId>g</groupId><artifactId>other</artifactId><version>0.9</version></dependency>"
                + "</dependencies></dependencyManagement></profile></profiles></project>";
        String result = applier.applyDependencyManagementPin(pom, "g", "a", "2", "r");
        assertTrue(result.contains("<p.version>2</p.version>"), result);
        assertEquals(1, result.split("<artifactId>a</artifactId>", -1).length - 1, result);
        assertFalse(result.contains("stray"), "the duplicate's own comment goes with it: " + result);
        assertTrue(result.contains("<artifactId>other</artifactId>"), result);
    }

    @Test
    void aCommentOnlyMarkerBecomesARealPin() {
        String pom = "<project><dependencyManagement><dependencies>"
                + "<!-- redkite:ignore groupId=\"g\" artifactId=\"a\" -->"
                + "</dependencies></dependencyManagement></project>";
        String result = applier.applyDependencyManagementPin(pom, "g", "a", "1.5", "r");
        assertTrue(result.contains("redkite:dependency-management pin groupId=\"g\" artifactId=\"a\" version=\"1.5\""), result);
        assertTrue(result.contains("<artifactId>a</artifactId>\n        <version>1.5</version>"), result);
    }
}
