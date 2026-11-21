package com.redkite.plugin;

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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

class BulkUpgradeMojoTest {
    private static long id = 1;
    private static final Predicate<RecommendationReason> ALL = new UpgradeAllMojo().reasons();
    private static final Predicate<RecommendationReason> CVE = new UpgradeCveMojo().reasons();

    private static ScanComponent component(String ga, boolean direct) {
        String[] p = ga.split(":");
        return new ScanComponent(id++, new ComponentCoordinate(p[0], p[1]), "1.0", DependencyScope.COMPILE, direct,
                VersionSource.LITERAL, direct ? "pom.xml" : null, "/project/dependencies/dependency", Map.of(), false,
                "pom.xml#dependency", "pom.xml");
    }

    private static UpgradeRecommendation rec(String ga, String target, RecommendationReason reason) {
        String[] p = ga.split(":");
        return new UpgradeRecommendation(id++, new ComponentCoordinate(p[0], p[1]), "1.0", target, reason,
                RiskLevel.PATCH, RecommendationConfidence.HIGH, List.of(), List.of());
    }

    private static ScanReport report(List<ScanComponent> components, List<UpgradeRecommendation> recs) {
        return new ScanReport("s", "p", true, "", Instant.EPOCH, components, List.of(), List.of(), recs, List.of(),
                List.of(), List.of());
    }

    @Test
    void upgradeAllTakesCveFixesAndRecommendedUpgradesButNotDowngrades() {
        ScanReport r = report(List.of(component("a:one", true), component("b:two", true), component("c:three", true),
                component("d:four", true), component("e:five", true)),
                List.of(rec("a:one", "1.1", RecommendationReason.CVE_FIX), rec("b:two", "2.0", RecommendationReason.MAJOR_AVAILABLE),
                        rec("c:three", "0.9", RecommendationReason.CVE_FIX_DOWNGRADE),
                        rec("d:four", "1.5", RecommendationReason.CVE_BEST_EFFORT),
                        rec("e:five", "1.1", RecommendationReason.SNAPSHOT_REPLACEMENT)));
        assertEquals(Set.of("a:one", "b:two", "d:four"), BulkUpgradeMojo.select(r, Set.of(), ALL).upgrades().keySet());
    }

    @Test
    void upgradeCveTakesOnlyTheFixingVersion() {
        ScanReport r = report(List.of(component("a:one", true), component("b:two", true), component("d:four", true)),
                List.of(rec("a:one", "1.1", RecommendationReason.CVE_FIX), rec("b:two", "1.1", RecommendationReason.PATCH_AVAILABLE),
                        rec("d:four", "1.5", RecommendationReason.CVE_BEST_EFFORT)));
        assertEquals(Map.of("a:one", "1.1"), BulkUpgradeMojo.select(r, Set.of(), CVE).upgrades());
    }

    @Test
    void aTransitiveIsOnlyChangedForAVulnerability() {
        ScanReport r = report(List.of(component("t:plain", false), component("t:cve", false)),
                List.of(rec("t:plain", "2.0", RecommendationReason.MINOR_AVAILABLE), rec("t:cve", "1.1", RecommendationReason.CVE_FIX)));
        assertEquals(Map.of("t:cve", "1.1"), BulkUpgradeMojo.select(r, Set.of(), ALL).upgrades());
    }

    @Test
    void pinnedDependenciesAreSkippedEvenForACveAndReported() {
        ScanReport r = report(List.of(component("a:pinned", true), component("b:free", true)),
                List.of(rec("a:pinned", "1.1", RecommendationReason.CVE_FIX), rec("b:free", "1.1", RecommendationReason.CVE_FIX)));
        BulkUpgradeMojo.Selection sel = BulkUpgradeMojo.select(r, Set.of("a:pinned"), CVE);
        assertEquals(Map.of("b:free", "1.1"), sel.upgrades());
        assertEquals(List.of("a:pinned"), sel.skippedPinned());
    }

    @Test
    void disagreeingTargetsForOneDependencyAreLeftForTheUserToName() {
        ScanReport r = report(List.of(component("a:one", true)),
                List.of(rec("a:one", "1.1", RecommendationReason.CVE_FIX), rec("a:one", "1.2", RecommendationReason.CVE_FIX),
                        rec("a:one", "1.1", RecommendationReason.CVE_FIX)));
        BulkUpgradeMojo.Selection sel = BulkUpgradeMojo.select(r, Set.of(), CVE);
        assertTrue(sel.upgrades().isEmpty());
        assertEquals(List.of("a:one"), sel.conflicting());
        assertFalse(sel.upgrades().containsKey("a:one"), "a later agreeing recommendation must not bring it back");
    }
}
