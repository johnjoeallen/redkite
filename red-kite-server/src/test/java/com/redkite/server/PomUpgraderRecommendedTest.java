package com.redkite.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.RecommendationConfidence;
import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.RiskLevel;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.core.domain.VersionSource;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PomUpgraderRecommendedTest {
    private static long id = 1;

    private static ScanComponent component(String ga, boolean direct, boolean snapshot, String sourceFile) {
        String[] p = ga.split(":");
        return new ScanComponent(id++, new ComponentCoordinate(p[0], p[1]), "1.0", DependencyScope.COMPILE, direct,
                VersionSource.LITERAL, sourceFile, "/project/dependencies/dependency", Map.of(), snapshot, "pom.xml#dependency",
                "pom.xml");
    }

    private static UpgradeRecommendation recommendation(String ga, String target) {
        String[] p = ga.split(":");
        return new UpgradeRecommendation(id++, new ComponentCoordinate(p[0], p[1]), "1.0", target, RecommendationReason.CVE_FIX,
                RiskLevel.PATCH, RecommendationConfidence.HIGH, List.of(), List.of());
    }

    private static ReportExporter.Result result(List<ScanComponent> components, List<UpgradeRecommendation> recs) {
        ScanReport report = new ScanReport("s", "p", true, "", Instant.EPOCH, components, List.of(), List.of(), recs, List.of(),
                List.of(), List.of());
        return new ReportExporter.Result("s", report, List.of());
    }

    @Test
    void onlyDirectDeclaredDependenciesWithARecommendationAreChosen() {
        ReportExporter.Result r = result(List.of(
                component("a:direct", true, false, "pom.xml"),
                component("b:transitive", false, false, null),
                component("c:snapshot", true, true, "pom.xml"),
                component("d:undeclared", true, false, null),
                component("e:no-recommendation", true, false, "pom.xml"),
                component("f:excepted", true, false, "pom.xml")),
                List.of(recommendation("a:direct", "1.1"), recommendation("b:transitive", "2.0"),
                        recommendation("c:snapshot", "1.1"), recommendation("d:undeclared", "1.1"),
                        recommendation("f:excepted", "1.1")));

        Map<String, String> chosen = PomUpgrader.recommendedDirect(r, Set.of("f:excepted"));

        assertEquals(Set.of("a:direct"), chosen.keySet());
        assertNull(chosen.get("a:direct"), "null means the recommended version");
    }
}
