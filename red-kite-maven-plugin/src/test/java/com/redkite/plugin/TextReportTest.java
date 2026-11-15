package com.redkite.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.VersionSource;
import com.redkite.core.domain.RecommendationConfidence;
import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.RiskLevel;
import com.redkite.core.domain.UpgradeRecommendation;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TextReportTest {
    private static UpgradeRecommendation rec(RecommendationReason reason) {
        return new UpgradeRecommendation(1, new ComponentCoordinate("g", "a"), "1.0", "1.1", reason,
                RiskLevel.PATCH, RecommendationConfidence.HIGH, List.of(), List.of());
    }

    private static String reportText(boolean showTransitives) {
        ScanComponent transitive = new ScanComponent(1, new ComponentCoordinate("g", "a"), "1.0", DependencyScope.COMPILE,
                false, VersionSource.LITERAL, "pom.xml", "dependencies", Map.of(), false, null, ".");
        ScanReport r = new ScanReport("s", "p", true, "", Instant.now(), List.of(transitive), List.of(), List.of(),
                List.of(rec(RecommendationReason.PATCH_AVAILABLE)), List.of(), List.of(), List.of());
        return TextReport.render(r, showTransitives);
    }

    @Test
    void transitiveUpdatesAreHiddenUnlessAsked() {
        String hidden = reportText(false);
        assertTrue(hidden.contains("Recommendations: 0 (1 transitive-only updates not listed)"), hidden);
        assertFalse(hidden.contains("1.0 -> 1.1"));
        String shown = reportText(true);
        assertTrue(shown.contains("Recommendations: 0 (+ 1 transitive-only updates, listed separately)"), shown);
        assertTrue(shown.indexOf("Transitive-only updates") > shown.indexOf("Recommended upgrades"), shown);
        assertTrue(shown.indexOf("g:a  ") > shown.indexOf("Transitive-only updates"), shown);
        assertTrue(shown.contains("1.0 -> 1.1"), shown);
        assertFalse(shown.contains("not listed"));
    }

    @Test
    void directDependenciesAlwaysListed() {
        assertTrue(TextReport.isActionable(rec(RecommendationReason.PATCH_AVAILABLE), true));
        assertTrue(TextReport.isActionable(rec(RecommendationReason.MAJOR_AVAILABLE), true));
    }

    @Test
    void transitivePlainUpdatesAreLeftOut() {
        assertFalse(TextReport.isActionable(rec(RecommendationReason.PATCH_AVAILABLE), false));
        assertFalse(TextReport.isActionable(rec(RecommendationReason.MINOR_AVAILABLE), false));
        assertFalse(TextReport.isActionable(rec(RecommendationReason.MAJOR_AVAILABLE), false));
    }

    @Test
    void transitiveVulnerabilityFixesAreListed() {
        assertTrue(TextReport.isActionable(rec(RecommendationReason.CVE_FIX), false));
        assertTrue(TextReport.isActionable(rec(RecommendationReason.CVE_FIX_DOWNGRADE), false));
        assertTrue(TextReport.isActionable(rec(RecommendationReason.CVE_BEST_EFFORT), false));
    }

    @Test
    void pinnedDependenciesLoseTheirPlainUpdateButKeepVulnerabilityFixes() throws Exception {
        ScanComponent direct = new ScanComponent(1, new ComponentCoordinate("g", "a"), "1.0", DependencyScope.COMPILE,
                true, VersionSource.LITERAL, "pom.xml", "dependencies", Map.of(), false, null, ".");
        ScanReport plain = new ScanReport("s", "p", true, "", Instant.now(), List.of(direct), List.of(), List.of(),
                List.of(rec(RecommendationReason.PATCH_AVAILABLE)), List.of(), List.of(), List.of());
        String text = TextReport.render(plain, false, java.util.Set.of("g:a"));
        assertTrue(text.contains("Recommendations: 0 (1 updates for pinned dependencies not listed)"), text);
        assertFalse(text.contains("1.0 -> 1.1"));
        ScanReport cve = new ScanReport("s", "p", true, "", Instant.now(), List.of(direct), List.of(), List.of(),
                List.of(rec(RecommendationReason.CVE_FIX)), List.of(), List.of(), List.of());
        assertTrue(TextReport.render(cve, false, java.util.Set.of("g:a")).contains("1.0 -> 1.1"));
    }

    @Test
    void findsUserPinMarkersInProjectPoms(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Files.writeString(dir.resolve("pom.xml"), "<project><dependencyManagement><dependencies>"
                + "<!-- redkite:user-pin groupId=\"com.google.guava\" artifactId=\"guava\" -->"
                + "<dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>1</version></dependency>"
                + "</dependencies></dependencyManagement></project>");
        assertEquals(java.util.Set.of("com.google.guava:guava"), PinnedCoordinates.find(dir));
    }
}
