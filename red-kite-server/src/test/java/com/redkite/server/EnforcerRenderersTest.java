package com.redkite.server;

import com.redkite.core.domain.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/** The enforcer section on the scan page and the analysis-log modal, for each enforcer outcome. */
class EnforcerRenderersTest {
    @TempDir
    Path project;

    private String savedRepos, savedOsv;
    private Store store;
    private String scanId;
    private EnforcerSectionRenderer section;
    private LogModalRenderer log;

    @BeforeEach
    void ingestAnEmptyScan() throws Exception {
        savedRepos = System.getProperty("redkite.maven.repositories");
        savedOsv = System.getProperty("redkite.osv.url");
        System.setProperty("redkite.maven.repositories", "http://127.0.0.1:1/repo");
        System.setProperty("redkite.osv.url", "http://127.0.0.1:1");
        Files.writeString(project.resolve("pom.xml"), "<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1</version></project>");
        store = Store.connect("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1", "sa", "");
        ScanInput input = new ScanInput("app", project.toString(), project.toString(), "main", "abc", true, false, Instant.now(),
                List.of(), List.of(), Map.of("pom.xml", "hash"), List.of());
        scanId = store.ingest(input).scanId();
        EnforcerAnalysis analysis = new EnforcerAnalysis(store);
        section = new EnforcerSectionRenderer(store, analysis);
        log = new LogModalRenderer(store, analysis);
    }

    @AfterEach
    void restore() {
        restore("redkite.maven.repositories", savedRepos);
        restore("redkite.osv.url", savedOsv);
    }

    private static void restore(String key, String value) {
        if (value == null) System.clearProperty(key);
        else System.setProperty(key, value);
    }

    private static Store.EnforcerResultEntry entry(EnforcerStatus status, String raw, List<TransitiveConflictFinding> findings,
            List<String> stale, List<TransitiveConflictFinding> phase2, int stripped, List<String> removed, List<String> pins) {
        return new Store.EnforcerResultEntry(status, raw, findings, stale, phase2, stripped, removed, pins);
    }

    private static Store.EnforcerResultEntry passed(int stripped, List<String> removed) {
        return entry(EnforcerStatus.ENFORCER_RUN_PASSED, "", List.of(), List.of(), null, stripped, removed, List.of());
    }

    private static TransitiveConflictFinding conflict(String artifactId, String resolved, String conflicting) {
        return new TransitiveConflictFinding("g", artifactId, resolved, List.of(conflicting), List.of(), "dependencyConvergence", null, List.of());
    }

    // ---------------------------------------------------------------- enforcer section

    @Test
    void sectionExplainsWhyNothingRan() {
        assertTrue(section.renderEnforcerSection(scanId, entry(EnforcerStatus.ENFORCER_CONFIGURED_NO_CONVERGENCE_RULES, "", List.of(), List.of(), null, 0, List.of(), List.of()))
                .contains("no <code>dependencyConvergence</code> or <code>requireUpperBoundDeps</code> rules configured"));
        assertTrue(section.renderEnforcerSection(scanId, entry(EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE, " ", List.of(), List.of(), null, 0, List.of(), List.of()))
                .contains("Could not start Maven"));
        assertTrue(section.renderEnforcerSection(scanId, entry(EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE, null, List.of(), List.of(), null, 0, List.of(), List.of()))
                .contains("Could not start Maven"));
        assertTrue(section.renderEnforcerSection(scanId, entry(EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE, "output", List.of(), List.of(), null, 0, List.of(), List.of()))
                .contains("produced no parseable conflict output"));
        assertTrue(section.renderEnforcerSection(scanId, entry(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, "x", List.of(), List.of(), null, 0, List.of(), List.of()))
                .contains("no structured findings could be extracted"));
    }

    @Test
    void passedSectionSummarisesThePristineRun() {
        assertTrue(section.renderEnforcerSection(scanId, passed(0, List.of())).endsWith("No dependency conflicts found.</p>"));
        assertTrue(section.renderEnforcerSection(scanId, passed(0, List.of("g:a:1")))
                .contains("pristine analysis ran with 1 dep-management entry removed. Existing fixes may be stale."));
        assertTrue(section.renderEnforcerSection(scanId, passed(1, List.of("g:a:1", "g:b:2")))
                .contains("pristine analysis ran with 2 dep-management entries removed and 1 exclusion stripped."));
        assertTrue(section.renderEnforcerSection(scanId, passed(2, List.of()))
                .contains("pristine analysis ran with 2 exclusions stripped."));
    }

    @Test
    void failingSectionPlansPinsFromTheFindings() {
        String html = section.renderEnforcerSection(scanId, entry(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, "x",
                List.of(conflict("a", "1.0", "1.2")), List.of("x:y"), List.of(), 1, List.of("g:a:1.0", "g:b:2.0"), List.of()));
        assertTrue(html.contains(">1 conflict</span>"), html);
        assertTrue(html.contains("Auto-fix verified"), html);
        assertTrue(html.contains("Pristine analysis: 1 exclusion stripped &middot; 2 dep-management entries removed</p>"), html);
        assertTrue(html.contains("applyPhase2Pins(rk_scanId,[{&quot;groupId&quot;:&quot;g&quot;,&quot;artifactId&quot;:&quot;a&quot;,&quot;version&quot;:&quot;1.2&quot;}],this)"), html);
        assertTrue(html.contains("&#10003;</span><code style=\"font-size:.78rem\">g:a</code>"), html);
        assertTrue(html.contains(">1 stale exclusion &mdash; no longer resolving any conflict</div>"), html);
    }

    @Test
    void failingSectionShowsStoredPinsAndWhichStillFail() {
        String html = section.renderEnforcerSection(scanId, entry(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, "x",
                List.of(conflict("a", "1.0", "1.2"), conflict("b", "2.0", "2.1")), List.of("x:y", "x:z"), List.of(conflict("b", "2.0", "2.1")),
                2, List.of("g:a:1.0"), List.of("g:a:1.2", "g:b:2.1", "nocolon", "solo:1.0", ":a:1.0")));
        assertTrue(html.contains(">2 conflicts</span>"), html);
        assertTrue(html.contains(">1 unresolvable</span>"), html);
        assertTrue(html.contains("Pristine analysis: 2 exclusions stripped &middot; 1 dep-management entry removed</p>"), html);
        assertTrue(html.contains("[{&quot;groupId&quot;:&quot;g&quot;,&quot;artifactId&quot;:&quot;a&quot;,&quot;version&quot;:&quot;1.2&quot;},"
                + "{&quot;groupId&quot;:&quot;g&quot;,&quot;artifactId&quot;:&quot;b&quot;,&quot;version&quot;:&quot;2.1&quot;}]"), html);
        assertTrue(html.contains("#e05050\">&#9888;</span><code style=\"font-size:.78rem\">g:b</code>"), html);
        assertTrue(html.contains(">2 stale exclusions &mdash;"), html);
    }

    @Test
    void failingSectionWithOnlyExclusionsStripped() {
        String html = section.renderEnforcerSection(scanId, entry(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, "x",
                List.of(conflict("a", "1.0", "1.2")), List.of(), null, 0, List.of("g:a:1.0"), List.of()));
        assertTrue(html.contains("Pristine analysis: 1 dep-management entry removed</p>"), html);
        assertFalse(html.contains("Auto-fix verified"), html);
        assertFalse(html.contains("stale exclusion"), html);
    }

    // ---------------------------------------------------------------- analysis log

    private static ScanReport report(boolean complete, List<ScanComponent> components, List<MetadataResult> metadata, List<String> warnings) {
        return new ScanReport("s", "p", complete, "message <b>", Instant.parse("2026-01-02T03:04:05Z"), components, List.of(),
                List.of(), List.of(), List.of(), metadata, warnings);
    }

    private static MetadataResult metadata(long id, boolean complete, MetadataStatus status, String message) {
        return new MetadataResult("s", id, MetadataType.VERSION, "maven", "1", "2", "2", List.of(), List.of(), complete,
                status, CacheState.ERROR_CACHED, null, null, null, null, message);
    }

    @Test
    void cleanLogSaysSoAndListsRepositories() {
        String html = log.renderLogModal(report(true, List.of(), List.of(metadata(1, true, MetadataStatus.FRESH, null),
                metadata(2, true, MetadataStatus.NOT_APPLICABLE, null)), null), scanId, null);
        assertTrue(html.contains("<span class=\"badge success\">Complete</span>"), html);
        assertTrue(html.contains("<p class=\"log-text\">message &lt;b&gt;</p><p class=\"log-meta-text\">Analysed: 2026-01-02T03:04:05Z</p>"), html);
        assertTrue(html.contains("No issues. All metadata resolved successfully."), html);
        assertTrue(html.contains("<div class=\"log-section-title\">Maven repositories</div><div class=\"log-code-list\"><div class=\"log-code-line\">http://127.0.0.1:1/repo</div>"), html);
        assertFalse(html.contains("Settings:"), html);
        assertFalse(html.contains("Dependency management"), html);
    }

    @Test
    void failedBuildListsItsErrorsAndMetadataIssues() {
        ScanComponent comp = new ScanComponent(1, new ComponentCoordinate("g", "a"), "1", DependencyScope.COMPILE, true,
                VersionSource.LITERAL, "pom.xml", null, Map.of(), false, null, "pom.xml");
        String html = log.renderLogModal(report(false, List.of(comp), List.of(
                metadata(1, false, MetadataStatus.RATE_LIMITED, "slow down"),
                metadata(9, true, MetadataStatus.STALE_USED, " ")),
                List.of("[BUILD_FAILED] dependency:tree failed", "Could not resolve")), scanId,
                entry(EnforcerStatus.ENFORCER_RUN_FAILED_UNAVAILABLE, "", List.of(), List.of(), null, 0, List.of(), List.of()));
        assertTrue(html.contains(">Failed</span>"), html);
        assertTrue(html.contains("&#10005; Build failure &nbsp;<span class=\"tab-count\">1 error(s)</span>"), html);
        assertTrue(html.contains("<div class=\"log-code-line\">dependency:tree failed</div><div class=\"log-code-line\">Could not resolve</div>"), html);
        assertTrue(html.contains("Metadata issues &nbsp;<span class=\"tab-count\">2</span>"), html);
        assertTrue(html.contains("<div class=\"log-issue-name\">g:a</div><div class=\"log-issue-badges\"><span class=\"badge warn\">rate limited</span>"
                + "<span class=\"badge neutral\">cache: error cached</span></div><div class=\"log-issue-msg\">slow down</div>"), html);
        assertTrue(html.contains("<div class=\"log-issue-name\">component #9</div><div class=\"log-issue-badges\"><span class=\"badge neutral\">stale used</span>"), html);
        assertFalse(html.contains("<div class=\"log-issue-msg\"> </div>"), html);
        assertTrue(html.contains("Dependency management check could not run"), html);
        assertFalse(html.contains("No issues."), html);
    }

    @Test
    void incompleteScanWithUnparsedTreeLines() {
        String html = log.renderLogModal(report(false, List.of(), List.of(), List.of("weird line")), scanId,
                passed(1, List.of()));
        assertTrue(html.contains("<span class=\"badge warn\">Incomplete</span>"), html);
        assertTrue(html.contains("&#9888; Dependency tree issues &nbsp;<span class=\"tab-count\">1</span>"), html);
        assertTrue(html.contains("All enforcer rules passed."), html);
        assertTrue(html.contains("&#10003; 1 exclusion stripped across all POMs</p>"), html);
        assertFalse(html.contains("Dep-management cleared"), html);

        String notConfigured = log.renderLogModal(report(true, List.of(), List.of(), null), scanId,
                entry(EnforcerStatus.ENFORCER_NOT_CONFIGURED, "", List.of(), List.of(), null, 0, List.of(), List.of()));
        assertFalse(notConfigured.contains("Dependency management"), notConfigured);
    }

    @Test
    void logComparesComputedPinsWithTheOriginalDependencyManagement() {
        String html = log.renderLogModal(report(true, List.of(), List.of(), List.of()), scanId,
                entry(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, "x", List.of(conflict("a", "1.0", "1.2")),
                        List.of("x:y", "x:z"), List.of(conflict("c", "3.0", "3.1")), 2,
                        List.of("g:a:1.0", "g:b:2.0", "g:c:3.1", "odd"), List.of("g:a:1.2", "g:c:3.1", "g:d:4.0", "solo")));
        assertTrue(html.contains("&#10005; Dependency management &nbsp;<span class=\"tab-count\">1 conflict</span>"), html);
        assertTrue(html.contains("&#10003; 2 exclusions stripped across all POMs</p>"), html);
        assertTrue(html.contains("Dep-management cleared (4 entries):</p>"), html);
        assertTrue(html.contains("&#10003; g:a &rarr; 1.2 <span style=\"color:#fde68a\">was 1.0</span></div>"), html);
        assertTrue(html.contains("&#9888; g:c &rarr; 3.1 <span style=\"color:#6ee7b7\">(same as before)</span> <span style=\"color:#e05050\">(still failing)</span></div>"), html);
        assertTrue(html.contains("&#10003; g:d &rarr; 4.0 <span style=\"color:var(--muted)\">(new)</span></div>"), html);
        assertTrue(html.contains("&#8722; g:b:2.0 <span>(no longer needed)</span></div>"), html);
        assertTrue(html.contains("2 stale exclusions (no longer resolving any conflict):</p>"), html);

        String single = log.renderLogModal(report(true, List.of(), List.of(), List.of()), scanId,
                entry(EnforcerStatus.ENFORCER_RUN_FAILED_WITH_FINDINGS, "x", List.of(conflict("a", "1.0", "1.2"), conflict("b", "1", "2")),
                        List.of("x:y"), null, 0, List.of("g:a:1.0"), List.of()));
        assertTrue(single.contains("<span class=\"tab-count\">2 conflicts</span>"), single);
        assertTrue(single.contains("Dep-management cleared (1 entry):</p>"), single);
        assertTrue(single.contains("1 stale exclusion (no longer resolving any conflict):</p>"), single);
    }
}
