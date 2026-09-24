package com.redkite.server;

import com.redkite.core.domain.*;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** One remediation card per scenario: badges, chips, recommendation text and the version selector. */
class ComponentCardRendererTest {
    private static final ComponentCoordinate LIB = new ComponentCoordinate("g", "lib");

    /** Severity of each version's own advisories, as the vulnerability provider reports them. */
    private final Map<String, String> severities = new HashMap<>();
    private final ComponentCardRenderer renderer = new ComponentCardRenderer((coordinate, version) -> {
        String severity = severities.get(version);
        return severity == null ? List.of() : List.of(finding(version, severity, null, List.of()));
    });

    // ---------------------------------------------------------------- builders

    private static ScanComponent component(boolean direct, String version) {
        return component(direct, false, version, DependencyScope.COMPILE);
    }

    private static ScanComponent component(boolean direct, boolean snapshot, String version, DependencyScope scope) {
        return new ScanComponent(7, LIB, version, scope, direct,
                direct ? VersionSource.LITERAL : VersionSource.UNKNOWN, "pom.xml", null, Map.of(), snapshot, null, "pom.xml");
    }

    private static VulnerabilityFinding finding(String version, String severity, String fixed, List<String> cves) {
        return new VulnerabilityFinding("GHSA-" + version, severity, LIB, version, fixed, null, false, null, cves, null);
    }

    private static RemediationStatus status(boolean snapshot, boolean vulnerable, boolean recommended, boolean stale,
            AdvisorySeverity severity, String... reasons) {
        boolean needs = snapshot || vulnerable || recommended || stale;
        return new RemediationStatus(7, needs, snapshot, false, vulnerable, recommended, stale, severity,
                vulnerable ? 1 : 0, List.of(reasons));
    }

    private static RemediationStatus clean() {
        return status(false, false, false, false, AdvisorySeverity.NONE);
    }

    private static RemediationStatus recommended() {
        return status(false, false, true, false, AdvisorySeverity.NONE, "Update recommended");
    }

    private static RemediationStatus vulnerable(AdvisorySeverity severity) {
        return status(false, true, false, false, severity, "Known " + severity.label().toLowerCase() + " severity advisory");
    }

    private static MetadataResult metadata(String current, String latest, String latestSameMajor, List<String> path, List<String> allStable) {
        return new MetadataResult("scan", 7, MetadataType.VERSION, "maven", current, latest, latestSameMajor, path, allStable,
                true, MetadataStatus.FRESH, CacheState.FRESH, null, null, null, null, "ok");
    }

    private static UpgradeRecommendation recommendation(String current, String target, RecommendationReason reason) {
        return new UpgradeRecommendation(7, LIB, current, target, reason, RiskLevel.PATCH, RecommendationConfidence.HIGH,
                List.of(), List.of(7L));
    }

    private static TransitiveConflictFinding conflict(String resolved, List<String> conflicting, List<ConflictCandidateAction> actions) {
        return new TransitiveConflictFinding("g", "lib", resolved, conflicting, List.of(), "dependencyConvergence", null, actions);
    }

    private static ComponentView view(ScanComponent component, RemediationStatus status, MetadataResult metadata,
            UpgradeRecommendation recommendation) {
        return view(component, status, metadata, recommendation, List.of(), null);
    }

    private static ComponentView view(ScanComponent component, RemediationStatus status, MetadataResult metadata,
            UpgradeRecommendation recommendation, List<VulnerabilityFinding> findings, TransitiveConflictFinding conflict) {
        return new ComponentView(component, status, metadata, recommendation, findings, true, conflict, List.of(), null);
    }

    private String render(ComponentView view) {
        return render(view, Set.of(), "", Map.of());
    }

    private String render(ComponentView view, Set<String> pinned, String rootPom, Map<String, List<VulnerabilityFinding>> vulnsByKey) {
        return renderer.renderComponentCard(view, "pom.xml", false, vulnsByKey, pinned, rootPom, Map.of());
    }

    private static String rootPomPinning(String version) {
        return "<project><dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>"
                + "<version>" + version + "</version></dependency></dependencies></dependencyManagement></project>";
    }

    // ---------------------------------------------------------------- card header and data attributes

    @Test
    void cleanDirectDependencyShowsCleanBadgeSelectorAndPin() {
        String html = render(view(component(true, "1.0"), clean(), metadata("1.0", "1.0", null, List.of(), List.of()), null));
        assertTrue(html.startsWith("<div class=\"rem-card clean\" data-clean=\"true\" data-module=\"pom.xml\" data-kind=\"declared\" data-origin=\"direct\""), html);
        assertTrue(html.contains("data-cveupgrade=\"false\" data-cvedowngrade=\"false\" data-cvenofix=\"false\" data-upgradeonly=\"false\" data-hasconflict=\"false\""), html);
        assertTrue(html.contains("data-coord=\"g:lib\" data-dep-key=\"g:lib@1.0\" data-pinned=\"false\" data-pinned-initial=\"false\" data-licenses='[]' data-comp-id=\"7\">"), html);
        assertTrue(html.contains("<span class=\"sev-badge sev-none\">&#10003; Clean</span>"), html);
        assertTrue(html.contains("<span class=\"badge success\">declared</span><span class=\"badge neutral\">compile</span>"), html);
        assertTrue(html.contains("No License"), html);
        assertTrue(html.contains("<span>Current: <strong>1.0</strong></span><span class=\"muted\">(Latest: 1.0)</span>"), html);
        assertTrue(html.contains("<option value=\"\" selected>No change</option>"), html);
        assertTrue(html.contains("<input type=\"checkbox\" class=\"pin-chk\" data-comp-id=\"7\" onchange=\"onPinToggle(this)\"> Pin</label>"), html);
        assertFalse(html.contains("rem-reasons"), html);
        assertFalse(html.contains("card-expand-btn"), html);
    }

    @Test
    void cardWithChildrenGetsAnExpandButton() {
        String html = renderer.renderComponentCard(view(component(true, "1.0"), clean(), null, null),
                "m", true, Map.of(), Set.of(), "", Map.of());
        assertTrue(html.contains("<button class=\"card-expand-btn\" type=\"button\" data-comp-id=\"7\" onclick=\"toggleTree(this)\">+</button>"), html);
        assertTrue(html.contains("<div class=\"dep-tree-panel\" style=\"display:none\"></div>"), html);
        assertFalse(html.contains("rem-actions"), "no metadata and not pinned: no actions row");
    }

    @Test
    void scopeAndKindLabels() {
        assertTrue(render(view(component(false, false, "1.0", DependencyScope.PLUGIN_BUILD), clean(), null, null))
                .contains("<span class=\"badge neutral\">transitive</span><span class=\"badge neutral\">plugin build</span>"));
        assertTrue(render(view(component(true, false, "1.0", null), clean(), null, null))
                .contains("<span class=\"badge neutral\">unknown</span>"));
        String snapshot = render(view(component(true, true, "1.0-SNAPSHOT", DependencyScope.TEST),
                status(true, false, true, false, AdvisorySeverity.NONE, "Snapshot dependency"),
                metadata("1.0-SNAPSHOT", "1.0", null, List.of(), List.of()), recommendation("1.0-SNAPSHOT", "1.0", RecommendationReason.PATCH_AVAILABLE)));
        assertTrue(snapshot.contains("data-kind=\"snapshot\""), snapshot);
        assertTrue(snapshot.contains("<span class=\"badge warn\">snapshot</span><span class=\"badge neutral\">test</span>"), snapshot);
        assertTrue(snapshot.contains("<span class=\"reason-chip\">Snapshot dependency</span>"), snapshot);
        assertFalse(snapshot.contains("Recommended:"), "a snapshot never shows a recommendation");
        assertFalse(snapshot.contains("Upgrade to"), snapshot);
    }

    @Test
    void severityBadgeReflectsTheHighestAdvisoryOrAPendingUpdate() {
        String update = render(view(component(true, "1.0"), status(false, false, false, true, AdvisorySeverity.NONE, "Stale or incomplete metadata"), null, null));
        assertTrue(update.contains("<span class=\"sev-badge sev-recommended\">&#8593; Update</span>"), update);
        assertTrue(update.contains("<span class=\"reason-chip\">Stale or incomplete metadata</span>"), update);
        String critical = render(view(component(true, "1.0"), vulnerable(AdvisorySeverity.CRITICAL), null, null));
        assertTrue(critical.contains("<span class=\"sev-badge sev-critical\">☢ Critical</span>"), critical);
    }

    @Test
    void licensesAreCanonicalizedAndTheMostPermissiveIsHighlighted() {
        ComponentView view = new ComponentView(component(true, "1.0"), clean(), null, null, List.of(), true, null,
                List.of("GPL-3.0", "The Apache Software License, Version 2.0"), null);
        String html = renderer.renderComponentCard(view, "m", false, Map.of(), Set.of(), "", Map.of("ASL-2.0", 1, "GPL-3.0", 5));
        assertTrue(html.contains("data-licenses='[\"ASL-2.0\"]'"), html);
        assertTrue(html.contains("<span class=\"badge license-badge\">GPL-3.0</span>"), html);
        assertTrue(html.contains("<span class=\"badge license-badge license-most-permissive\" title=\"Declared as: The Apache Software License, Version 2.0 — "
                + "Most permissive of this dependency's declared licenses\">ASL-2.0</span>"), html);

        String unranked = renderer.renderComponentCard(new ComponentView(component(true, "1.0"), clean(), null, null, List.of(), true, null,
                List.of("Custom"), null), "m", false, Map.of(), Set.of(), "", Map.of());
        assertTrue(unranked.contains("data-licenses='[\"Custom\"]'"), unranked);
        assertTrue(unranked.contains("<span class=\"badge license-badge\">Custom</span>"), unranked);
    }

    @Test
    void childVulnerabilitiesShowOneChipPerSeverityWithTheChildrenAsTooltip() {
        ChildVulnerabilityCounts counts = new ChildVulnerabilityCounts(1, 2, 3, 4, 5,
                Map.of(AdvisorySeverity.CRITICAL, List.of("a:b@1 (GHSA-1)")));
        String html = renderer.renderComponentCard(new ComponentView(component(true, "1.0"), clean(), null, null, List.of(), true, null,
                List.of(), counts), "m", false, Map.of(), Set.of(), "", Map.of());
        assertTrue(html.contains("<div class=\"rem-child-vulns\"><span class=\"muted\" style=\"font-size:.78rem\">In dependencies:</span>"
                + "<span class=\"sev-chip sev-critical\" title=\"Critical in:\na:b@1 (GHSA-1)\">&#9762; 1</span>"
                + "<span class=\"sev-chip sev-high\">&#9760; 2</span>"
                + "<span class=\"sev-chip sev-medium\">&#9888; 3</span>"
                + "<span class=\"sev-chip sev-low\">&#x2139; 4</span>"
                + "<span class=\"sev-chip sev-unknown\">? 5</span></div>"), html);

        String none = renderer.renderComponentCard(new ComponentView(component(true, "1.0"), clean(), null, null, List.of(), true, null,
                List.of(), ChildVulnerabilityCounts.EMPTY), "m", false, Map.of(), Set.of(), "", Map.of());
        assertFalse(none.contains("rem-child-vulns"));
        String onlyLow = renderer.renderComponentCard(new ComponentView(component(true, "1.0"), clean(), null, null, List.of(), true, null,
                List.of(), new ChildVulnerabilityCounts(0, 0, 0, 1, 0, Map.of())), "m", false, Map.of(), Set.of(), "", Map.of());
        assertTrue(onlyLow.contains("In dependencies:</span><span class=\"sev-chip sev-low\">&#x2139; 1</span></div>"), onlyLow);
    }

    // ---------------------------------------------------------------- CVE fixes on direct dependencies

    @Test
    void directCveFixByUpgradeOffersTheFixInButtonAndSelector() {
        severities.put("1.0", "HIGH");
        List<VulnerabilityFinding> findings = List.of(finding("1.0", "HIGH", "1.2", List.of("CVE-1", "CVE-2")), finding("1.0", "HIGH", "1.2", null));
        String html = render(view(component(true, "1.0"), vulnerable(AdvisorySeverity.HIGH),
                metadata("1.0", "2.0", "1.5", List.of("1.2", "1.5"), List.of()),
                recommendation("1.0", "1.2", RecommendationReason.CVE_FIX), findings, null));
        assertTrue(html.contains("data-clean=\"false\""), html);
        assertTrue(html.contains("data-cveupgrade=\"true\" data-cvedowngrade=\"false\" data-cvenofix=\"false\""), html);
        assertTrue(html.contains("<span class=\"sev-badge sev-high\">☠ High</span>"), html);
        assertTrue(html.contains("<span>&rarr; Recommended: <strong>1.2</strong></span>"), html);
        assertTrue(html.contains("<div class=\"rem-cves\">CVE-1, CVE-2</div>"), html);
        assertTrue(html.contains("<span class=\"reason-chip\">Known high severity advisory</span>"), html);
        assertTrue(html.contains("onclick=\"applyUpgrade(7,'1.2',this)\">Upgrade to 1.2</button>"), html);
        assertTrue(html.contains("<span class=\"version-current cve\">1.0<span class=\"pill sev-high\">High</span></span>"), html);
        assertTrue(html.contains("data-recommended=\"1.2\">"), html);
        assertTrue(html.contains("<option value=\"\">No change</option>"), html);
        assertTrue(html.contains("<option value=\"1.2\" selected>1.2 — recommended, fixes CVE</option>"), html);
        assertTrue(html.contains("<option value=\"1.5\">1.5 — latest same major</option>"), html);
        assertTrue(html.contains("<option value=\"2.0\">2.0 — latest</option>"), html);
        assertFalse(html.contains("<option value=\"1.0\""), "current is not offered without a conflict");
    }

    @Test
    void directCveFixByDowngradeAndBestEffort() {
        String down = render(view(component(true, "2.0"), vulnerable(AdvisorySeverity.MEDIUM),
                metadata("2.0", "2.0", null, List.of(), List.of("1.0", "1.5", "2.0")),
                recommendation("2.0", "1.5", RecommendationReason.CVE_FIX_DOWNGRADE)));
        assertTrue(down.contains("data-cveupgrade=\"false\" data-cvedowngrade=\"true\" data-cvenofix=\"false\""), down);
        assertTrue(down.contains("<span>&rarr; Downgrade to: <strong>1.5</strong></span>"), down);
        assertTrue(down.contains(">Downgrade to 1.5</button>"), down);
        assertTrue(down.contains("<option value=\"1.5\" selected>1.5 — recommended, fixes CVE</option>"), down);
        assertTrue(down.contains("<option value=\"1.0\">1.0</option>"), down);

        severities.put("2.1", "LOW");
        String bestUp = render(view(component(true, "2.0"), vulnerable(AdvisorySeverity.HIGH), metadata("2.0", "2.1", null, List.of(), List.of()),
                recommendation("2.0", "2.1", RecommendationReason.CVE_BEST_EFFORT)));
        assertTrue(bestUp.contains("data-cveupgrade=\"true\" data-cvedowngrade=\"false\""), bestUp);
        assertTrue(bestUp.contains("<span>&rarr; Best available: <strong>2.1</strong></span>"), bestUp);
        assertTrue(bestUp.contains(">Best available: 2.1</button>"), bestUp);
        assertTrue(bestUp.contains("<option value=\"2.1\" selected>2.1 — recommended, lowest known severity, latest, low severity</option>"), bestUp);

        String bestDown = render(view(component(true, "2.0"), vulnerable(AdvisorySeverity.HIGH), null,
                recommendation("2.0", "1.9", RecommendationReason.CVE_BEST_EFFORT)));
        assertTrue(bestDown.contains("data-cveupgrade=\"false\" data-cvedowngrade=\"true\""), bestDown);
    }

    @Test
    void vulnerabilityWithoutRecommendationIsNoFix() {
        String direct = render(view(component(true, "1.0"), vulnerable(AdvisorySeverity.LOW), null, null));
        assertTrue(direct.contains("data-cvenofix=\"true\""), direct);
        String transitive = render(view(component(false, "1.0"), vulnerable(AdvisorySeverity.LOW),
                metadata("1.0", "2.0", null, List.of(), List.of()), null));
        assertTrue(transitive.contains("<span class=\"reason-chip\">No fix available</span>"), transitive);
        assertFalse(transitive.contains("rem-actions"), "no fix: nothing to select");
    }

    @Test
    void plainUpdateOnADirectDependencyIsUpgradeOnly() {
        String html = render(view(component(true, "1.0"), recommended(), metadata("1.0", "1.1", null, List.of("1.1"), List.of()),
                recommendation("1.0", "1.1", RecommendationReason.MINOR_AVAILABLE)));
        assertTrue(html.contains("data-upgradeonly=\"true\""), html);
        assertTrue(html.contains("<span class=\"sev-badge sev-recommended\">&#8593; Update</span>"), html);
        assertTrue(html.contains(">Upgrade to 1.1</button>"), html);
        assertFalse(html.contains("reason-chip\">Update recommended"), "the button replaces the plain reason chip");
        assertTrue(html.contains("<option value=\"1.1\" selected>1.1 — recommended, latest</option>"), html);
    }

    // ---------------------------------------------------------------- transitive dependencies

    @Test
    void transitivePlainUpdateIsCleanAndOnlyDescribesWhatExists() {
        ScanComponent comp = component(false, "1.0");
        UpgradeRecommendation rec = recommendation("1.0", "1.1", RecommendationReason.MINOR_AVAILABLE);
        String sameMajor = render(view(comp, recommended(), metadata("1.0", "1.4", null, List.of(), List.of()), rec));
        assertTrue(sameMajor.contains("data-clean=\"true\""), sameMajor);
        assertTrue(sameMajor.contains("data-upgradeonly=\"false\""), sameMajor);
        assertTrue(sameMajor.contains("<span class=\"reason-chip\">Update available</span>"), sameMajor);
        assertFalse(sameMajor.contains("Recommended:"), sameMajor);
        assertFalse(sameMajor.contains("<select"), sameMajor);

        assertTrue(render(view(comp, recommended(), metadata("1.0", "2.0", null, List.of(), List.of()), rec))
                .contains("<span class=\"reason-chip\">Major update available</span>"));
        assertTrue(render(view(comp, clean(), metadata("1.0", "1.0", null, List.of(), List.of()), null))
                .contains("<span class=\"reason-chip\">No upgrade available</span>"));
        assertTrue(render(view(comp, clean(), metadata("1.0", "unknown", null, List.of(), List.of()), null))
                .contains("<span class=\"reason-chip\">No upgrade available</span>"));
        assertTrue(render(view(comp, clean(), metadata("1.0", null, null, List.of(), List.of()), null))
                .contains("<span class=\"reason-chip\">No upgrade available</span>"));
        assertFalse(render(view(comp, clean(), null, null)).contains("rem-reasons"));
    }

    @Test
    void transitiveDependencyPinnedInTheRootPomMovesToThePin() {
        ScanComponent comp = component(false, "1.0");
        MetadataResult meta = metadata("1.0", "2.0", "1.4", List.of("1.4"), List.of());
        String html = render(view(comp, recommended(), meta, recommendation("1.0", "2.0", RecommendationReason.MAJOR_AVAILABLE)),
                Set.of(), rootPomPinning("1.4"), Map.of());
        assertTrue(html.contains("data-clean=\"true\""), html);
        assertTrue(html.contains("data-upgradeonly=\"true\""), html);
        assertTrue(html.contains("<span>&rarr; Recommended: <strong>1.4</strong></span>"), html);
        assertTrue(html.contains("<span class=\"reason-chip\">Update available</span>"), html);
        assertTrue(html.contains("<option value=\"1.0\">1.0 — current</option>"), html);
        assertTrue(html.contains("<option value=\"1.4\" selected>1.4 — recommended, latest same major</option>"), html);

        ComponentView viaMajor = new ComponentView(comp, recommended(), meta, null, List.of(), false, null, List.of(), null);
        String major = render(viaMajor, Set.of(), rootPomPinning("1.4"), Map.of());
        assertTrue(major.contains("<span class=\"reason-chip\">Major update available</span>"), major);
        assertTrue(major.contains("<option value=\"1.4\" selected>1.4 — recommended, latest same major</option>"), major);
    }

    @Test
    void transitiveCveFixUsesTheRecommendationsDirection() {
        ScanComponent comp = component(false, "2.0");
        MetadataResult meta = metadata("2.0", "2.0", null, List.of(), List.of());
        String down = render(view(comp, vulnerable(AdvisorySeverity.HIGH), meta, recommendation("2.0", "1.5", RecommendationReason.CVE_FIX_DOWNGRADE)));
        assertTrue(down.contains("<span class=\"reason-chip\">Downgrade available</span>"), down);
        assertTrue(down.contains("<option value=\"1.5\" selected>1.5 — recommended, fixes CVE</option>"), down);
        String best = render(view(comp, vulnerable(AdvisorySeverity.HIGH), meta, recommendation("2.0", "2.2", RecommendationReason.CVE_BEST_EFFORT)));
        assertTrue(best.contains("<span class=\"reason-chip\">Lower-severity version available</span>"), best);
        assertTrue(best.contains("<span>&rarr; Best available: <strong>2.2</strong></span>"), best);
    }

    @Test
    void transitiveConflictRecommendsTheHighestVersionInTheTree() {
        TransitiveConflictFinding finding = conflict(null, List.of("1.1", "1.3-rc1", "1.2"), List.of(
                new ConflictCandidateAction(ConflictCandidateAction.ActionType.ADD_DEPENDENCY_MANAGEMENT, "g", "lib", "1.2", null, null),
                new ConflictCandidateAction(ConflictCandidateAction.ActionType.ADD_EXCLUSION, "g", "lib", "1.1", "o'brien", "a"),
                new ConflictCandidateAction(ConflictCandidateAction.ActionType.ADD_EXCLUSION, "g", "lib", null, "x", "y"),
                new ConflictCandidateAction(ConflictCandidateAction.ActionType.ADD_EXCLUSION, "g", "lib", "1.2", "p", "q")));
        String html = render(view(component(false, "1.0"), clean(), null, null, List.of(), finding));
        assertTrue(html.contains("data-clean=\"false\""), html);
        assertTrue(html.contains("data-hasconflict=\"true\""), html);
        assertTrue(html.contains("data-conflict='{\"groupId\":\"g\",\"artifactId\":\"lib\",\"resolvedVersion\":null,\"exclusions\":["
                + "{\"parentGroupId\":\"o&#39;brien\",\"parentArtifactId\":\"a\",\"introducedVersion\":\"1.1\"},"
                + "{\"parentGroupId\":\"p\",\"parentArtifactId\":\"q\",\"introducedVersion\":\"1.2\"}]}'>"), html);
        assertTrue(html.contains("<span class=\"badge conflict-badge\">&#9651; Conflict</span>"), html);
        assertTrue(html.contains("<span>&rarr; Recommended: <strong>1.3-rc1</strong></span>"), html);
        assertTrue(html.contains("<option value=\"1.3-rc1\" selected>1.3-rc1 — recommended, conflict, pre-release</option>"), html);
        assertTrue(html.contains("<option value=\"1.1\">1.1 — conflict</option>"), html);
        assertFalse(html.contains("pin-chk"), "a conflict card has no pin checkbox");
    }

    @Test
    void pinnedCardKeepsItsPinCheckboxWithoutASelector() {
        String html = render(view(component(false, "1.0"), clean(), null, null), Set.of("g:lib"), "", Map.of());
        assertTrue(html.contains("data-pinned=\"true\" data-pinned-initial=\"true\""), html);
        assertTrue(html.contains("<div class=\"rem-actions\"><label class=\"pin-toggle\""), html);
        assertTrue(html.contains("data-comp-id=\"7\" checked onchange"), html);
        assertFalse(html.contains("<select"), html);
    }

    // ---------------------------------------------------------------- direct conflicts

    @Test
    void directConflictDefaultsToTheFirstCleanVersionPastTheConflict() {
        // 1.1 (the conflict's newest) is affected by a CVE fixed in 1.3; the upgrade path reaches it.
        Map<String, List<VulnerabilityFinding>> vulnsByKey = Map.of(
                "g:lib@1.1", List.of(finding("1.1", "HIGH", "1.3", List.of())),
                "other:x@1.1", List.of(finding("1.1", "HIGH", "9.0", List.of())));
        TransitiveConflictFinding finding = conflict("1.0", List.of("1.1"), List.of());
        MetadataResult meta = metadata("1.0", "1.4", null, List.of("1.2", "1.3", "1.4", "2.0"), List.of());
        String html = render(view(component(true, "1.0"), clean(), meta, null, List.of(), finding), Set.of(), "", vulnsByKey);
        assertTrue(html.contains("<option value=\"1.3\" selected>1.3</option>"), html);
        assertTrue(html.contains("<option value=\"1.1\">1.1 — conflict</option>"), html);

        // A recommendation above that default wins.
        String withRec = render(view(component(true, "1.0"), clean(), meta, recommendation("1.0", "1.4", RecommendationReason.MINOR_AVAILABLE),
                List.of(), finding), Set.of(), "", vulnsByKey);
        assertTrue(withRec.contains("<option value=\"1.4\" selected>1.4 — recommended, latest</option>"), withRec);
    }

    @Test
    void directConflictWithoutAFixVersionBumpsPastAnAffectedVersion() {
        Map<String, List<VulnerabilityFinding>> vulnsByKey = Map.of("g:lib@1.1", List.of(finding("1.1", "HIGH", null, List.of())));
        TransitiveConflictFinding finding = conflict("1.1", List.of("1.0"), List.of());
        MetadataResult meta = metadata("1.0", "1.4", null, List.of("1.2-beta", "1.2", "1.4"), List.of());
        String html = render(view(component(true, "1.0"), clean(), meta, null, List.of(), finding), Set.of(), "", vulnsByKey);
        assertTrue(html.contains("<option value=\"1.2\" selected>1.2</option>"), html);
    }

    @Test
    void directConflictKeepsTheCurrentVersionWhenItIsTheNewest() {
        TransitiveConflictFinding finding = conflict("1.0", List.of("0.9"), List.of());
        String html = render(view(component(true, "1.1"), clean(), metadata("1.1", "1.1", null, List.of(), List.of()), null, List.of(), finding));
        assertTrue(html.contains("<option value=\"1.1\" selected>1.1 — current, latest</option>"), html);
    }

    // ---------------------------------------------------------------- version selector contents

    @Test
    void selectorOffersOlderReleasesUpToTheLookbackLimit() {
        System.setProperty("redkite.version.lookback", "2");
        try {
            String html = render(view(component(true, "1.5"), clean(),
                    metadata("1.5", "1.5", null, List.of(), List.of("1.1", "1.2", "1.3-rc1", "1.4", "1.5", "")), null));
            assertTrue(html.contains("<option value=\"1.2\">1.2</option>"), html);
            assertTrue(html.contains("<option value=\"1.4\">1.4 — latest same minor</option>") || html.contains("<option value=\"1.4\">1.4</option>"), html);
            assertFalse(html.contains("<option value=\"1.1\""), "beyond the lookback limit");
            assertFalse(html.contains("1.3-rc1"), "pre-releases are not offered");
        } finally {
            System.clearProperty("redkite.version.lookback");
        }
    }

    @Test
    void selectorLabelsSameMinorAndSameMajorLatestDifferently() {
        String html = render(view(component(true, "1.2.0"), clean(), metadata("1.2.0", "2.0.0", "1.2.9", List.of(), List.of()), null));
        assertTrue(html.contains("<option value=\"1.2.9\">1.2.9 — latest same minor</option>"), html);
        String major = render(view(component(true, "1.2.0"), clean(), metadata("1.2.0", "2.0.0", "1.9.0", List.of(), List.of()), null));
        assertTrue(major.contains("<option value=\"1.9.0\">1.9.0 — latest same major</option>"), major);
    }

    @Test
    void selectorWithNothingToOfferSaysSo() {
        // An "unknown" latest version is a failed lookup, not a version to offer.
        String html = render(view(component(true, "1.0"), clean(), metadata("1.0", "unknown", null, List.of(), List.of()), null));
        assertTrue(html.contains("<span class=\"version-note muted\">No upgrade candidates</span>"), html);
        assertFalse(html.contains("(Latest:"), html);
    }

    // ---------------------------------------------------------------- classification helpers

    @Test
    void transitiveRecommendedVersionFollowsPinThenConflictThenCveFix() {
        ScanComponent comp = component(false, "1.0");
        assertEquals("1.4", renderer.transitiveRecommendedVersion(view(comp, clean(), null, null), rootPomPinning("1.4")));
        assertEquals("1.2", renderer.transitiveRecommendedVersion(
                view(comp, clean(), null, null, List.of(), conflict("1.2", List.of("1.1"), List.of())), ""));
        assertEquals("1.0", renderer.transitiveRecommendedVersion(
                view(comp, clean(), null, null, List.of(), conflict(null, List.of(), List.of())), ""));
        assertEquals("1.3", renderer.transitiveRecommendedVersion(
                view(comp, vulnerable(AdvisorySeverity.HIGH), null, recommendation("1.0", "1.3", RecommendationReason.CVE_FIX)), ""));
        assertEquals("1.0", renderer.transitiveRecommendedVersion(
                view(comp, vulnerable(AdvisorySeverity.HIGH), null, recommendation("1.0", " ", RecommendationReason.CVE_FIX)), ""));
        assertEquals("1.0", renderer.transitiveRecommendedVersion(
                view(comp, recommended(), null, recommendation("1.0", "1.3", RecommendationReason.MINOR_AVAILABLE)), ""));
    }

    @Test
    void outdatedOnlyNeedsAnUpdateTheCardActuallyOffers() {
        UpgradeRecommendation rec = recommendation("1.0", "1.3", RecommendationReason.MINOR_AVAILABLE);
        assertTrue(renderer.isEffectivelyOutdatedOnly(view(component(true, "1.0"), recommended(), null, rec), ""));
        assertFalse(renderer.isEffectivelyOutdatedOnly(view(component(false, "1.0"), recommended(), null, rec), ""));
        assertTrue(renderer.isEffectivelyOutdatedOnly(view(component(false, "1.0"), recommended(), null, rec), rootPomPinning("1.2")));
        assertFalse(renderer.isEffectivelyOutdatedOnly(view(component(true, "1.0"), vulnerable(AdvisorySeverity.LOW), null, rec), ""));
        assertFalse(renderer.isEffectivelyOutdatedOnly(view(component(true, "1.0"),
                status(true, false, true, false, AdvisorySeverity.NONE), null, rec), ""));
    }

    @Test
    void cardCleanlinessIgnoresOnlyPlainTransitiveUpdates() {
        assertTrue(renderer.isCardClean(view(component(false, "1.0"), recommended(), null, null)));
        assertFalse(renderer.isCardClean(view(component(true, "1.0"), recommended(), null, null)));
        assertFalse(renderer.isCardClean(view(component(false, "1.0"), vulnerable(AdvisorySeverity.LOW), null, null)));
        assertFalse(renderer.isCardClean(view(component(false, "1.0"), status(true, false, false, false, AdvisorySeverity.NONE), null, null)));
        assertFalse(renderer.isCardClean(view(component(false, "1.0"), status(false, false, false, true, AdvisorySeverity.NONE), null, null)));
    }
}
