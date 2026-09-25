package com.redkite.server;

import com.redkite.core.domain.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/** The remediation view's banner, filters, module picker and client-side indexes, plus the enforcer badge. */
class ScanPageRendererTest {
    private String savedRepos;
    private ScanPageRenderer renderer;

    @BeforeEach
    void setUp() {
        savedRepos = System.getProperty("redkite.maven.repositories");
        System.setProperty("redkite.maven.repositories", "http://127.0.0.1:1/repo");
        Store store = Store.connect("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1", "sa", "");
        renderer = new ScanPageRenderer(store, new ComponentCardRenderer((coordinate, version) -> List.of()));
    }

    @AfterEach
    void restore() {
        if (savedRepos == null) System.clearProperty("redkite.maven.repositories");
        else System.setProperty("redkite.maven.repositories", savedRepos);
    }

    // ---------------------------------------------------------------- enforcer badge

    private static Store.EnforcerResultEntry enforcer(EnforcerStatus status, int findings, List<TransitiveConflictFinding> phase2) {
        List<TransitiveConflictFinding> list = new ArrayList<>();
        for (int i = 0; i < findings; i++) list.add(conflict("c" + i));
        return new Store.EnforcerResultEntry(status, "", list, List.of(), phase2, 0, List.of(), List.of());
    }

    private static TransitiveConflictFinding conflict(String artifactId) {
        return new TransitiveConflictFinding("g", artifactId, "1.0", List.of("1.1"), List.of(), "dependencyConvergence", null, List.of());
    }

    @Test
    void enforcerBadgeForEachOutcome() {
        assertEquals("", ScanPageRenderer.enforcerBadge(null));
        assertEquals("", ScanPageRenderer.enforcerBadge(enforcer(EnforcerStatus.ENFORCER_NOT_CONFIGURED, 0, null)));
        assertTrue(ScanPageRenderer.enforcerBadge(enforcer(EnforcerStatus.ENFORCER_RUN_PASSED, 0, null)).contains(">No conflicts</span>"));
        FailedBadges.check(1, "1 conflict resolved ✓", "1 unresolvable", "1 convergence conflict");
        FailedBadges.check(2, "2 conflicts resolved ✓", "2 unresolvable", "2 convergence conflicts");
    }

    private static final class FailedBadges {
        static void check(int n, String resolved, String unresolvable, String failed) {
            List<TransitiveConflictFinding> remaining = new ArrayList<>();
            for (int i = 0; i < n; i++) remaining.add(conflict("r" + i));
            assertTrue(ScanPageRenderer.enforcerBadge(enforcer(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, n, List.of())).contains(resolved));
            String left = ScanPageRenderer.enforcerBadge(enforcer(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, n, remaining));
            assertTrue(left.contains(">" + unresolvable + "</span>"), left);
            assertTrue(left.contains(n == 1 ? "1 conflict remain unresolvable" : n + " conflicts remain unresolvable"), left);
            assertTrue(ScanPageRenderer.enforcerBadge(enforcer(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, n, null)).contains(failed));
        }
    }

    // ---------------------------------------------------------------- license breakdown

    private static MetadataResult licenses(long id, List<String> licenses) {
        return new MetadataResult("s", id, MetadataType.LICENSE, "pom", "1", null, null, licenses, List.of(), true,
                MetadataStatus.FRESH, CacheState.FRESH, null, null, null, null, "ok");
    }

    private static ScanReport report(List<ScanComponent> components, List<VulnerabilityFinding> findings,
            List<UpgradeRecommendation> recs, List<MetadataResult> metadata, List<DependencyEdge> edges) {
        return new ScanReport("s", "p", true, "ok", Instant.now(), components, edges, findings, recs, List.of(), metadata, List.of());
    }

    @Test
    void licenseBreakdownCountsEachDependencyOnceUnderItsMostPermissiveLicense() {
        String html = renderer.licenseBreakdownHtml(report(List.of(), List.of(), List.of(), List.of(
                licenses(1, List.of("MIT")),
                licenses(2, List.of("Apache-2.0")),
                licenses(3, List.of("The Apache Software License, Version 2.0")),
                licenses(4, List.of()),
                licenses(5, null)), List.of()));
        assertTrue(html.startsWith("<div class=\"rem-banner-row\" style=\"margin-bottom:14px\"><span class=\"sev-chip sev-license\" data-license-value=\"ASL-2.0\""), html);
        assertTrue(html.contains("title=\"Apache-2.0\nThe Apache Software License, Version 2.0\">&#128220; 2 ASL-2.0</span>"), html);
        assertTrue(html.contains("onclick=\"toggleLicenseFilter(this)\">&#128220; 1 MIT</span>"), html);
        assertTrue(html.contains(">&#128220; 2 No License</span>"), html);

        assertEquals("", renderer.licenseBreakdownHtml(report(List.of(), List.of(), List.of(), List.of(), List.of())));
        assertFalse(renderer.licenseBreakdownHtml(report(List.of(), List.of(), List.of(), List.of(licenses(1, List.of("MIT"))), List.of()))
                .contains("No License"));
        assertEquals("GPL-3.0", ScanPageRenderer.representativeLicense(List.of("GPL-3.0", "Custom"), Map.of()));
    }

    // ---------------------------------------------------------------- remediation view

    private static ScanComponent component(long id, String artifactId, String version, boolean direct, boolean snapshot, String module) {
        return new ScanComponent(id, new ComponentCoordinate("g", artifactId), version, DependencyScope.COMPILE, direct,
                direct ? VersionSource.PROPERTY : VersionSource.UNKNOWN, module, null, Map.of(), snapshot, null, module);
    }

    private static VulnerabilityFinding vuln(String artifactId, String severity) {
        return new VulnerabilityFinding("GHSA-" + artifactId, severity, new ComponentCoordinate("g", artifactId), "1.0", null, null,
                false, null, List.of(), null);
    }

    private static UpgradeRecommendation rec(long id, String artifactId, String current, String target, List<Long> affected) {
        return new UpgradeRecommendation(id, new ComponentCoordinate("g", artifactId), current, target,
                RecommendationReason.MINOR_AVAILABLE, RiskLevel.MINOR, RecommendationConfidence.HIGH, List.of(), affected);
    }

    private static MetadataResult version(long id, boolean complete) {
        return new MetadataResult("s", id, MetadataType.VERSION, "maven", "1.0", "1.0", "1.0", List.of(), List.of(), complete,
                complete ? MetadataStatus.FRESH : MetadataStatus.STALE_USED, complete ? CacheState.FRESH : CacheState.STALE,
                null, null, null, null, "m");
    }

    @Test
    void noComponentsMeansNoInventory() {
        assertEquals("<p class=\"muted\">No dependency inventory is available for this scan.</p>",
                renderer.renderRemediationView(report(List.of(), List.of(), List.of(), List.of(), List.of()), "s", true, Map.of(), Map.of(), Map.of()));
    }

    @Test
    void remediationViewSummarisesEveryKindOfFinding() {
        List<ScanComponent> components = List.of(
                component(1, "crit", "1.0", true, false, "pom.xml"),
                component(2, "high", "1.0", true, false, "pom.xml"),
                component(3, "med", "1.0", true, false, "pom.xml"),
                component(4, "low", "1.0", true, false, "pom.xml"),
                component(5, "unk", "1.0", true, false, "pom.xml"),
                component(6, "snap", "1.0-SNAPSHOT", true, true, "a/pom.xml"),
                component(7, "child", "1.0", false, false, "a/pom.xml"),
                component(8, "parent", "2.0", true, false, "a/pom.xml"),
                component(9, "stale", "1.0", true, false, "a/b/pom.xml"),
                component(10, "crit", "1.0", true, false, "pom.xml"),   // exact duplicate of 1: deduped
                component(11, "crit", "1.0", true, false, "a/pom.xml"), // same dependency, another module
                component(12, "conflicted", "1.0", false, false, "pom.xml"),
                component(13, "shared-a", "1.0", true, false, "pom.xml"),
                component(14, "shared-b", "1.0", true, false, "pom.xml"));
        List<VulnerabilityFinding> findings = List.of(vuln("crit", "CRITICAL"), vuln("high", "HIGH"), vuln("med", "MEDIUM"),
                vuln("low", "LOW"), vuln("unk", "weird"));
        List<UpgradeRecommendation> recs = List.of(
                rec(7, "child", "1.0", "1.1", List.of()),
                rec(8, "parent", "2.0", "2.5", List.of(8L)));
        List<DependencyEdge> edges = List.of(
                new DependencyEdge("8", "7", DependencyScope.COMPILE, true),
                new DependencyEdge("module:a/pom.xml", "8", DependencyScope.COMPILE, true),
                new DependencyEdge(null, "8", DependencyScope.COMPILE, true),
                new DependencyEdge("x", "8", DependencyScope.COMPILE, true));
        List<MetadataResult> metadata = List.of(version(9, false), version(8, true));
        String root = """
                <project><properties><!-- redkite:user-pin version="1.0" — pinned --><shared.version>1.0</shared.version></properties>
                <dependencies>
                  <dependency><groupId>g</groupId><artifactId>shared-a</artifactId><version>${shared.version}</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>shared-b</artifactId><version>${shared.version}</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>crit</artifactId><version>1.0</version></dependency>
                  <dependency><artifactId>no-group</artifactId><version>${shared.version}</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>untracked</artifactId><version>${shared.version}</version></dependency>
                </dependencies>
                <build><plugins><plugin><groupId> </groupId><artifactId>p</artifactId><version>${p.version}</version></plugin></plugins></build></project>
                """;
        Map<String, String> sourcePoms = new LinkedHashMap<>();
        sourcePoms.put("pom.xml", root);
        sourcePoms.put("broken.xml", "<project>");
        Map<String, String> moduleIds = new LinkedHashMap<>();
        moduleIds.put("pom.xml", "app");
        moduleIds.put("a/b/pom.xml", "deep");
        moduleIds.put("empty/pom.xml", "empty");
        Map<String, List<TransitiveConflictFinding>> conflicts = Map.of("g:conflicted", List.of(conflict("conflicted")));

        String html = renderer.renderRemediationView(report(components, findings, recs, metadata, edges), "scan-1", false,
                moduleIds, sourcePoms, conflicts);

        assertTrue(html.contains("<span class=\"rem-stat\"><strong>12</strong> components</span>"), html);
        assertTrue(html.contains("&#9762; 1 Critical</span>") && html.contains("&#9760; 1 High</span>")
                && html.contains("&#9888; 1 Medium</span>") && html.contains("&#x2139; 1 Low</span>") && html.contains("? 1 Unknown</span>"), html);
        assertTrue(html.contains(">&#9889; 1 Snapshot</span>"), html);
        assertTrue(html.contains(">&#8635; 1 Stale metadata</span>"), html);
        assertTrue(html.contains(">&#8593; 1 Update recommended</span>"), html);

        // Root first, then by depth; the first module with a finding is preselected.
        assertTrue(html.contains("<script>remModule='pom.xml';</script>"), html);
        assertTrue(html.contains("<option value=\"all\">All modules</option><option value=\"pom.xml\" selected>app</option>"
                + "<option value=\"a/pom.xml\">a</option><option value=\"empty/pom.xml\">empty</option><option value=\"a/b/pom.xml\">deep</option>"), html);

        assertTrue(html.contains("data-filter-value=\"conflict\""), html);
        assertTrue(html.contains(" disabled data-nopom=\"true\""), html);
        assertTrue(html.contains("const rk_scanId=\"scan-1\""), html);
        assertTrue(html.contains("\"8\":{\"g\":\"g\",\"a\":\"parent\",\"v\":\"2.0\""), html);
        assertTrue(html.contains("\"rec\":\"2.5\""), html);
        assertTrue(html.contains("\"pin\":true"), "shared-a/b are pinned through their shared property: " + html);
        assertTrue(html.contains("const rk_propGroups={\"pom.xml:shared.version\":[13,14]};"), html);
        assertTrue(html.contains("const rk_compPropKey={\"13\":\"pom.xml:shared.version\",\"14\":\"pom.xml:shared.version\"};"), html);
        assertTrue(html.contains("const rk_coordGroups={\"g:crit\":[1,11]};"), html);
    }

    @Test
    void singleModuleViewHasNoModulePickerAndAnEnabledApplyBar() {
        String html = renderer.renderRemediationView(report(List.of(component(1, "a", "1.0", true, false, "")),
                        List.of(), List.of(), List.of(version(1, true)), List.of()), "s", true, Map.of(), Map.of(), Map.of());
        assertFalse(html.contains("rem-module-select"), html);
        assertTrue(html.contains("id=\"apply-btn\" disabled onclick"), html);
        assertTrue(html.contains("<span class=\"rem-stat muted\">1 clean</span>"), html);
        assertFalse(html.contains("need remediation"), html);
        for (String chip : List.of("Critical</span>", "High</span>", "Medium</span>", "Low</span>", "Unknown</span>",
                "Snapshot</span>", "Declared version</span>", "Update recommended</span>", "Stale metadata</span>"))
            assertFalse(html.contains(chip), "no chip for a zero count: " + chip);
    }

    @Test
    void modulePickerFallsBackToTheFirstNonEmptyModuleWhenEverythingIsClean() {
        Map<String, String> moduleIds = new LinkedHashMap<>();
        moduleIds.put("aaa/pom.xml", "aaa");
        String html = renderer.renderRemediationView(report(List.of(component(1, "a", "1.0", true, false, "zzz/pom.xml")),
                List.of(), List.of(), List.of(version(1, true)), List.of()), "s", true, moduleIds, Map.of(), Map.of());
        assertTrue(html.contains("<script>remModule='zzz/pom.xml';</script>"), html);
    }

    @Test
    void transitiveCardsSayWhetherTheirDirectParentCanCarryTheUpdate() {
        List<ScanComponent> components = List.of(
                component(1, "same-major-parent", "2.0", true, false, "pom.xml"),
                component(2, "child-a", "1.0", false, false, "pom.xml"),
                component(3, "major-parent", "2.0", true, false, "pom.xml"),
                component(4, "child-b", "1.0", false, false, "pom.xml"),
                component(5, "child-c", "1.0", false, false, "pom.xml"));
        List<UpgradeRecommendation> recs = List.of(
                rec(1, "same-major-parent", "2.0", "2.5", List.of(1L)),
                rec(2, "child-a", "1.0", "1.1", List.of(2L)),
                rec(3, "major-parent", "2.0", "3.0", List.of(3L)),
                rec(4, "child-b", "1.0", "1.1", List.of(4L)),
                rec(5, "child-c", "1.0", "1.1", List.of(5L)));
        List<DependencyEdge> edges = List.of(
                new DependencyEdge("1", "2", DependencyScope.COMPILE, true),
                new DependencyEdge("3", "4", DependencyScope.COMPILE, true),
                new DependencyEdge("2", "5", DependencyScope.COMPILE, true),   // parent is itself transitive
                new DependencyEdge("99", "5", DependencyScope.COMPILE, true)); // unknown parent
        String root = "<project><dependencyManagement><dependencies>"
                + "<dependency><groupId>g</groupId><artifactId>child-a</artifactId><version>1.1</version></dependency>"
                + "<dependency><groupId>g</groupId><artifactId>child-b</artifactId><version>1.1</version></dependency>"
                + "<dependency><groupId>g</groupId><artifactId>child-c</artifactId><version>1.1</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        String html = renderer.renderRemediationView(report(components, List.of(), recs, List.of(), edges), "s", true,
                Map.of(), Map.of("pom.xml", root), Map.of());
        assertTrue(card(html, "child-a").contains("<span class=\"reason-chip\">Update available</span>"), card(html, "child-a"));
        assertTrue(card(html, "child-b").contains("<span class=\"reason-chip\">Major update available</span>"), card(html, "child-b"));
        assertTrue(card(html, "child-c").contains("<span class=\"reason-chip\">Major update available</span>"), card(html, "child-c"));
    }

    private static String card(String html, String artifactId) {
        int start = html.indexOf("data-coord=\"g:" + artifactId + "\"");
        assertTrue(start >= 0, artifactId);
        int end = html.indexOf("<div class=\"rem-card", start);
        return html.substring(start, end < 0 ? html.length() : end);
    }

    @Test
    void modulePickerPrefersTheFirstModuleWithAFinding() {
        Map<String, String> moduleIds = new LinkedHashMap<>();
        moduleIds.put("pom.xml", "root");
        moduleIds.put("b/pom.xml", "b");
        String html = renderer.renderRemediationView(report(
                List.of(component(1, "clean", "1.0", true, false, "pom.xml"), component(2, "risky", "1.0", true, false, "b/pom.xml")),
                List.of(vuln("risky", "HIGH")), List.of(), List.of(version(1, true), version(2, true)), List.of()),
                "s", true, moduleIds, Map.of(), Map.of());
        assertTrue(html.contains("<script>remModule='b/pom.xml';</script>"), html);
    }
}
