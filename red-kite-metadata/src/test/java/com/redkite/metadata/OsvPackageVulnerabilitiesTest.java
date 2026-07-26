package com.redkite.metadata;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.VulnerabilityFinding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Validates {@link OsvPackageVulnerabilities} against a real OSV "package query" response for
 * {@code ch.qos.logback:logback-core} (trimmed to just the fields the matcher reads — summaries,
 * references, timestamps etc. stripped). Expected finding counts for 1.5.9 through 1.5.14 are the
 * exact values a live, per-version OSV query returned for those same versions (empirically
 * captured from server logs before this class existed) — this is a differential check against
 * ground truth, not just internal self-consistency.
 */
class OsvPackageVulnerabilitiesTest {

    private static final ComponentCoordinate LOGBACK_CORE = new ComponentCoordinate("ch.qos.logback", "logback-core");

    // Real OSV response for ch.qos.logback:logback-core (POST /v1/query with package+ecosystem,
    // no version), trimmed to id/aliases/severity/affected.ranges — the shape OsvPackageVulnerabilities reads.
    private static final String LOGBACK_CORE_RESPONSE = "{\"vulns\": ["
            + "{\"id\": \"GHSA-25qh-j22f-pwp8\", \"aliases\": [\"CVE-2025-11226\"], \"database_specific\": {\"severity\": \"MODERATE\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.4.0\"}, {\"fixed\": \"1.5.19\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.3.16\"}]}]}]}, "
            + "{\"id\": \"GHSA-668q-qrv7-99fm\", \"aliases\": [\"CVE-2021-42550\"], \"database_specific\": {\"severity\": \"MODERATE\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.2.9\"}]}]}]}, "
            + "{\"id\": \"GHSA-6v67-2wr5-gvf4\", \"aliases\": [\"CVE-2024-12801\"], \"database_specific\": {\"severity\": \"LOW\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.4.0\"}, {\"fixed\": \"1.5.13\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.3.15\"}]}]}]}, "
            + "{\"id\": \"GHSA-gm62-rw4g-vrc4\", \"aliases\": [\"CVE-2023-6481\"], \"database_specific\": {\"severity\": \"HIGH\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.4.13\"}, {\"fixed\": \"1.4.14\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.3.13\"}, {\"fixed\": \"1.3.14\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.2.12\"}, {\"fixed\": \"1.2.13\"}]}]}]}, "
            + "{\"id\": \"GHSA-jhq6-gfmj-v8fx\", \"aliases\": [\"CVE-2026-10532\"], \"database_specific\": {\"severity\": \"LOW\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.5.34\"}]}]}]}, "
            + "{\"id\": \"GHSA-p47f-322f-whfh\", \"aliases\": [\"CVE-2026-9828\"], \"database_specific\": {\"severity\": \"LOW\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.5.33\"}]}]}]}, "
            + "{\"id\": \"GHSA-pr98-23f8-jwxv\", \"aliases\": [\"CVE-2024-12798\"], \"database_specific\": {\"severity\": \"MODERATE\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.4.0\"}, {\"fixed\": \"1.5.13\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.3.15\"}]}]}]}, "
            + "{\"id\": \"GHSA-qqpg-mvqg-649v\", \"aliases\": [\"CVE-2026-1225\"], \"database_specific\": {\"severity\": \"LOW\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.5.25\"}]}]}]}, "
            + "{\"id\": \"GHSA-vmfg-rjjm-rjrj\", \"aliases\": [\"CVE-2017-5929\"], \"database_specific\": {\"severity\": \"CRITICAL\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-classic\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.2.0\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.2.0\"}]}]}]}, "
            + "{\"id\": \"GHSA-vmq6-5m68-f53m\", \"aliases\": [\"CVE-2023-6378\"], \"database_specific\": {\"severity\": \"HIGH\"}, \"affected\": ["
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-classic\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.3.0\"}, {\"fixed\": \"1.3.12\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-classic\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.4.0\"}, {\"fixed\": \"1.4.12\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.3.0\"}, {\"fixed\": \"1.3.12\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"1.4.0\"}, {\"fixed\": \"1.4.12\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-core\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.2.13\"}]}]}, "
            + "{\"package\": {\"name\": \"ch.qos.logback:logback-classic\", \"ecosystem\": \"Maven\"}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"1.2.13\"}]}]}]}"
            + "]}";

    @Test
    void matchesLiveObservedCountsForConsecutiveLogbackCoreVersions() {
        // These exact counts (6,6,6,6,4,4) are what a live per-version OSV query returned for
        // these same versions before the package-level cache existed — ground truth, not just an
        // assertion on this class's own internal consistency.
        assertEquals(6, findings("1.5.9").size());
        assertEquals(6, findings("1.5.10").size());
        assertEquals(6, findings("1.5.11").size());
        assertEquals(6, findings("1.5.12").size());
        assertEquals(4, findings("1.5.13").size());
        assertEquals(4, findings("1.5.14").size());
    }

    @Test
    void versionPastEveryFixedBoundIsClean() {
        // 1.5.34 is the highest "fixed" bound of any advisory affecting logback-core in this
        // fixture (GHSA-jhq6-gfmj-v8fx) — anything at or above it should be free of every finding.
        assertEquals(List.of(), findings("1.5.34"));
        assertEquals(List.of(), findings("1.5.38"));
    }

    @Test
    void oldVersionMatchesOnlyTheInceptionScopedAdvisories() {
        // 1.0.0 predates logback-core's 1.3.x/1.4.x line entirely, so it only matches advisories
        // whose range starts "since inception" (introduced "0") and hasn't fixed yet at this
        // version — every advisory with an introduced bound of 1.2.x/1.3.x/1.4.x correctly misses.
        // Manually verified against the fixture: every advisory except GHSA-gm62-rw4g-vrc4 (whose
        // narrow windows are all >= 1.2.12) matches.
        Set<String> ids = findings("1.0.0").stream().map(VulnerabilityFinding::advisoryId).collect(Collectors.toSet());
        assertEquals(9, ids.size());
        assertTrue(!ids.contains("GHSA-gm62-rw4g-vrc4"));
    }

    @Test
    void severityAndCveAreExtractedPerAdvisory() {
        List<VulnerabilityFinding> found = findings("1.4.13");
        VulnerabilityFinding hit = found.stream()
                .filter(f -> f.advisoryId().equals("GHSA-gm62-rw4g-vrc4"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("expected GHSA-gm62-rw4g-vrc4 to match 1.4.13"));
        assertEquals("HIGH", hit.severity());
        assertEquals(List.of("CVE-2023-6481"), hit.cves());
        assertEquals("1.4.14", hit.fixedVersion());
        assertEquals("1.4.13", hit.introducedVersion());
    }

    @Test
    void packageNameOnlyMatchesRequestedCoordinate() {
        String json = "{\"vulns\": [{\"id\": \"GHSA-fake-0001\", \"affected\": ["
                + "{\"package\": {\"name\": \"com.example:other-artifact\", \"ecosystem\": \"Maven\"}, "
                + "\"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"99.0.0\"}]}]}"
                + "]}]}";
        ComponentCoordinate target = new ComponentCoordinate("com.example", "target-artifact");
        List<VulnerabilityFinding> found = OsvPackageVulnerabilities.findingsForVersion(json, target, "1.0.0");
        assertEquals(List.of(), found, "a range scoped to a different artifact must not apply to the queried one");
    }

    @Test
    void explicitVersionsListIsUsedWhenRangesAreAbsent() {
        String json = "{\"vulns\": [{\"id\": \"GHSA-fake-0002\", \"aliases\": [\"CVE-2099-0001\"], \"affected\": ["
                + "{\"package\": {\"name\": \"com.example:legacy-artifact\", \"ecosystem\": \"Maven\"}, "
                + "\"versions\": [\"1.0\", \"1.1\", \"1.2\"]}"
                + "]}]}";
        ComponentCoordinate target = new ComponentCoordinate("com.example", "legacy-artifact");
        assertEquals(1, OsvPackageVulnerabilities.findingsForVersion(json, target, "1.1").size());
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion(json, target, "1.3"));
    }

    @Test
    void lastAffectedEventIsInclusiveOfUpperBound() {
        String json = "{\"vulns\": [{\"id\": \"GHSA-fake-0003\", \"affected\": ["
                + "{\"package\": {\"name\": \"com.example:old-artifact\", \"ecosystem\": \"Maven\"}, "
                + "\"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"last_affected\": \"2.0.0\"}]}]}"
                + "]}]}";
        ComponentCoordinate target = new ComponentCoordinate("com.example", "old-artifact");
        assertEquals(1, OsvPackageVulnerabilities.findingsForVersion(json, target, "2.0.0").size(),
                "last_affected is inclusive — the boundary version itself is still affected");
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion(json, target, "2.0.1"));
    }

    @Test
    void emptyVulnsArrayMeansNoFindings() {
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion("{\"vulns\": []}", LOGBACK_CORE, "1.5.9"));
    }

    @Test
    void missingVulnsKeyMeansNoFindings() {
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion("{}", LOGBACK_CORE, "1.5.9"));
    }

    @Test
    void malformedJsonIsHandledGracefullyRatherThanThrowing() {
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion("not json at all", LOGBACK_CORE, "1.5.9"));
    }

    @Test
    void distinctAdvisoriesForTheSameVersionAreAllReturned() {
        // 1.4.13 matches both GHSA-gm62-rw4g-vrc4 (its narrow 1.4.13->1.4.14 window) and several
        // of the broad long-lived advisories — confirms multiple simultaneous findings aren't
        // deduplicated or dropped.
        Set<String> ids = findings("1.4.13").stream().map(VulnerabilityFinding::advisoryId).collect(Collectors.toSet());
        assertTrue(ids.contains("GHSA-gm62-rw4g-vrc4"));
        assertTrue(ids.size() >= 4);
    }

    private List<VulnerabilityFinding> findings(String version) {
        return OsvPackageVulnerabilities.findingsForVersion(LOGBACK_CORE_RESPONSE, LOGBACK_CORE, version);
    }
}
