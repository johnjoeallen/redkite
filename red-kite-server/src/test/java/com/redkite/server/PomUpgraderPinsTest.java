package com.redkite.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.RecommendationConfidence;
import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.RiskLevel;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.core.domain.VersionSource;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PomUpgraderPinsTest {
    private static final String POM = """
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>g</groupId>
              <artifactId>app</artifactId>
              <version>1</version>
            </project>
            """;

    private static ScanComponent transitive(String ga) {
        String[] p = ga.split(":");
        return new ScanComponent(1, new ComponentCoordinate(p[0], p[1]), "1.0", DependencyScope.COMPILE, false,
                VersionSource.LITERAL, null, "/project/dependencies/dependency", Map.of(), false, "pom.xml#dependency", "pom.xml");
    }

    private static ReportExporter.Result result(ScanComponent... components) {
        ScanReport report = new ScanReport("s", "p", true, "", Instant.EPOCH, List.of(components), List.of(), List.of(),
                List.of(new UpgradeRecommendation(2, components[0].coordinate(), "1.0", "1.5", RecommendationReason.CVE_FIX,
                        RiskLevel.PATCH, RecommendationConfidence.HIGH, List.of(), List.of())),
                List.of(), List.of(), List.of());
        return new ReportExporter.Result("s", report, List.of());
    }

    private static Path project(Path dir) throws IOException {
        Files.writeString(dir.resolve("pom.xml"), POM);
        return dir;
    }

    private static PomUpgrader.Plan plan(Path dir, ReportExporter.Result r, Map<String, String> req, boolean bulk,
                                         Set<String> drops, Set<String> unpins) throws IOException {
        return PomUpgrader.plan(dir, List.of(dir.resolve("pom.xml")), r, req, bulk, drops, unpins);
    }

    private static void write(Path dir, PomUpgrader.Plan plan) throws IOException {
        PomUpgrader.write(dir, plan);
    }

    @Test
    void anExplicitTransitiveUpgradeWritesAUserPinInTheRootPom(@TempDir Path dir) throws Exception {
        project(dir);
        PomUpgrader.Plan plan = plan(dir, result(transitive("x:lib")), java.util.Collections.singletonMap("x:lib", "1.2"),
                false, Set.of(), Set.of());
        assertEquals(1, plan.changes().size());
        assertTrue(plan.changes().get(0).pin());
        String pom = plan.patchedPoms().get("pom.xml");
        assertTrue(pom.contains("redkite:user-pin"), pom);
        assertTrue(pom.contains("<version>1.2</version>"), pom);
        assertEquals(POM, Files.readString(dir.resolve("pom.xml")), "planning writes nothing");
    }

    @Test
    void aBulkTransitiveFixWritesAComputedPinNotAUserPin(@TempDir Path dir) throws Exception {
        project(dir);
        PomUpgrader.Plan plan = plan(dir, result(transitive("x:lib")), Map.of("x:lib", "1.5"), true, Set.of(), Set.of());
        String pom = plan.patchedPoms().get("pom.xml");
        assertTrue(pom.contains("redkite:dependency-management pin"), pom);
        assertFalse(pom.contains("redkite:user-pin groupId"), pom);
    }

    @Test
    void dropRemovesThePinEntryAndUnpinKeepsTheVersion(@TempDir Path dir) throws Exception {
        project(dir);
        write(dir, plan(dir, result(transitive("x:lib")), Map.of("x:lib", "1.2"), false, Set.of(), Set.of()));

        PomUpgrader.Plan unpin = plan(dir, null, Map.of(), false, Set.of(), Set.of("x:lib"));
        assertEquals(List.of("x:lib"), unpin.unpinned());
        String kept = unpin.patchedPoms().get("pom.xml");
        assertFalse(kept.contains("redkite:user-pin groupId"), "the protection is released: " + kept);
        assertTrue(kept.contains("<version>1.2</version>"), "the version stays: " + kept);

        PomUpgrader.Plan drop = plan(dir, null, Map.of(), false, Set.of("x:lib"), Set.of());
        assertEquals(List.of("x:lib"), drop.dropped());
        assertFalse(drop.patchedPoms().get("pom.xml").contains("x:lib") || drop.patchedPoms().get("pom.xml").contains("<artifactId>lib"));
    }

    @Test
    void dropAndUnpinOfSomethingWithoutAPinAreReported(@TempDir Path dir) throws Exception {
        project(dir);
        PomUpgrader.Plan p = plan(dir, null, Map.of(), false, Set.of("x:lib"), Set.of("y:other"));
        assertTrue(p.patchedPoms().isEmpty());
        assertEquals(2, p.problems().size());
    }

    @Test
    void anUnknownDependencyIsRefused(@TempDir Path dir) throws Exception {
        project(dir);
        PomUpgrader.Plan p = plan(dir, result(transitive("x:lib")), java.util.Collections.singletonMap("no:such", "1.0"),
                false, Set.of(), Set.of());
        assertTrue(p.patchedPoms().isEmpty());
        assertTrue(p.problems().get(0).contains("not a dependency"));
    }
}
