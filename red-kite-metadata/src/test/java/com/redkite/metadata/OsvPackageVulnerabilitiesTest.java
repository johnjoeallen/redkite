package com.redkite.metadata;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.VulnerabilityFinding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    // ---------------------------------------------------------------- synthetic advisories

    private static final ComponentCoordinate LIB = new ComponentCoordinate("com.example", "lib");

    /** One advisory for com.example:lib with the given extra top-level fields and range events. */
    private static String advisory(String extra, String events) {
        return "{\"vulns\": [{\"id\": \"GHSA-x\"" + extra + ", \"affected\": [{\"package\": {\"name\": \"com.example:lib\"}, "
                + "\"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [" + events + "]}]}]}]}";
    }

    private static String cvss(String vector) {
        return ", \"severity\": [{\"type\": \"CVSS_V3\", \"score\": \"" + vector + "\"}]";
    }

    private static VulnerabilityFinding only(String json, String version) {
        List<VulnerabilityFinding> found = OsvPackageVulnerabilities.findingsForVersion(json, LIB, version);
        assertEquals(1, found.size(), "expected exactly one finding for " + version);
        return found.get(0);
    }

    private static final String ALWAYS = "{\"introduced\": \"0\"}, {\"fixed\": \"9.0\"}";

    @Test
    void severityFallsBackToTheCvssVector() {
        assertEquals("CRITICAL", only(advisory(cvss("CVSS:3.1/AV:N/C:H/I:H/A:H"), ALWAYS), "1.0").severity());
        assertEquals("HIGH", only(advisory(cvss("CVSS:3.1/AV:N/C:H/I:H/A:N"), ALWAYS), "1.0").severity());
        assertEquals("HIGH", only(advisory(cvss("CVSS:3.1/AV:N/C:H/I:N/A:H"), ALWAYS), "1.0").severity());
        assertEquals("HIGH", only(advisory(cvss("CVSS:3.1/AV:N/C:N/I:H/A:H"), ALWAYS), "1.0").severity());
        assertEquals("HIGH", only(advisory(cvss("CVSS:3.1/AV:N/C:N/I:N/A:H"), ALWAYS), "1.0").severity());
        assertEquals("MEDIUM", only(advisory(cvss("CVSS:3.1/AV:N/C:M/I:N/A:N"), ALWAYS), "1.0").severity());
        assertEquals("MEDIUM", only(advisory(cvss("CVSS:3.1/AV:N/C:N/I:M/A:N"), ALWAYS), "1.0").severity());
        assertEquals("MEDIUM", only(advisory(cvss("CVSS:3.1/AV:N/C:N/I:N/A:M"), ALWAYS), "1.0").severity());
        assertEquals("LOW", only(advisory(cvss("CVSS:3.1/AV:N/C:L/I:N/A:N"), ALWAYS), "1.0").severity());
        // A blank label defers to the vector; a vector of another type, or a blank score, is ignored.
        assertEquals("HIGH", only(advisory(", \"database_specific\": {\"severity\": \" \"}" + cvss("C:N/I:H/A:N"), ALWAYS), "1.0").severity());
        assertEquals("UNKNOWN", only(advisory(", \"severity\": [{\"type\": \"Ubuntu\", \"score\": \"/C:H\"}]", ALWAYS), "1.0").severity());
        assertEquals("UNKNOWN", only(advisory(", \"severity\": [{\"type\": \"CVSS_V3\", \"score\": \" \"}]", ALWAYS), "1.0").severity());
        assertEquals("UNKNOWN", only(advisory("", ALWAYS), "1.0").severity());
    }

    @Test
    void cvesComeFromAliasesOrFromACveId() {
        assertEquals(List.of("CVE-1"), only(advisory(", \"aliases\": [\"GHSA-y\", \"CVE-1\"]", ALWAYS), "1.0").cves());
        assertEquals(List.of(), only(advisory(", \"aliases\": [\"GHSA-y\"]", ALWAYS), "1.0").cves());
        String cveId = "{\"vulns\": [{\"id\": \"CVE-2\", \"aliases\": [\"GHSA-z\"], \"affected\": [{\"package\": {\"name\": \"com.example:lib\"}, "
                + "\"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [" + ALWAYS + "]}]}]}]}";
        assertEquals(List.of("CVE-2"), only(cveId, "1.0").cves());
        String cveIdWithCveAlias = cveId.replace("GHSA-z", "CVE-3");
        assertEquals(List.of("CVE-3"), only(cveIdWithCveAlias, "1.0").cves());
        String noId = "{\"vulns\": [{\"affected\": [{\"package\": {\"name\": \"com.example:lib\"}, "
                + "\"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [" + ALWAYS + "]}]}]}]}";
        VulnerabilityFinding anonymous = only(noId, "1.0");
        assertEquals("UNKNOWN", anonymous.advisoryId());
        assertEquals(List.of(), anonymous.cves());
    }

    @Test
    void advisoryWithoutAffectedEntriesNeverMatches() {
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion(
                "{\"vulns\": [{\"id\": \"GHSA-x\"}]}", LIB, "1.0"));
    }

    @Test
    void overlappingSegmentsReportTheWidestBounds() {
        String narrowFirst = advisory("", "{\"introduced\": \"1.0\"}, {\"fixed\": \"2.0\"}, {\"introduced\": \"0.5\"}, {\"fixed\": \"3.0\"}");
        VulnerabilityFinding a = only(narrowFirst, "1.5");
        assertEquals("0.5", a.introducedVersion());
        assertEquals("3.0", a.fixedVersion());

        String wideFirst = advisory("", "{\"introduced\": \"0.5\"}, {\"fixed\": \"3.0\"}, {\"introduced\": \"1.0\"}, {\"fixed\": \"2.0\"}");
        VulnerabilityFinding b = only(wideFirst, "1.5");
        assertEquals("0.5", b.introducedVersion());
        assertEquals("3.0", b.fixedVersion());

        // Only the segment containing the version counts.
        VulnerabilityFinding c = only(narrowFirst, "2.5");
        assertEquals("0.5", c.introducedVersion());
        assertEquals("3.0", c.fixedVersion());
        VulnerabilityFinding d = only(advisory("", "{\"introduced\": \"1.0\"}, {\"fixed\": \"2.0\"}, {\"introduced\": \"3.0\"}, {\"fixed\": \"4.0\"}"), "1.5");
        assertEquals("1.0", d.introducedVersion());
        assertEquals("2.0", d.fixedVersion());
    }

    @Test
    void openEndedSegmentsAffectEveryVersionFromTheirIntroduction() {
        String json = advisory("", "{\"introduced\": \"1.0\"}");
        VulnerabilityFinding atStart = only(json, "1.0");
        assertEquals("1.0", atStart.introducedVersion());
        assertEquals(null, atStart.fixedVersion());
        assertEquals("1.0", only(json, "7.0").introducedVersion());
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion(json, LIB, "0.9"));

        // An open-ended segment wins over a fixed one: there is no fixed version to offer.
        String mixed = advisory("", "{\"introduced\": \"0.5\"}, {\"fixed\": \"3.0\"}, {\"introduced\": \"1.0\"}");
        VulnerabilityFinding m = only(mixed, "1.5");
        assertEquals("0.5", m.introducedVersion());
        assertEquals(null, m.fixedVersion());
    }

    @Test
    void lastAffectedSegmentsRespectTheirIntroducedBound() {
        String json = advisory("", "{\"introduced\": \"1.0\"}, {\"last_affected\": \"2.0\"}");
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion(json, LIB, "0.9"));
        VulnerabilityFinding hit = only(json, "1.0");
        assertEquals("1.0", hit.introducedVersion());
        assertEquals(null, hit.fixedVersion());

        VulnerabilityFinding sinceInception = only(advisory("", "{\"last_affected\": \"2.0\"}"), "0.1");
        assertEquals(null, sinceInception.introducedVersion());
    }

    @Test
    void blankFixedBoundNeverMatchesAndExplicitListingOffersTheFirstFixedVersion() {
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion(
                advisory("", "{\"introduced\": \"0\"}, {\"fixed\": \"\"}"), LIB, "1.0"));

        String listed = "{\"vulns\": [{\"id\": \"GHSA-x\", \"affected\": [{\"package\": {\"name\": \"com.example:lib\"}, "
                + "\"versions\": [\"1.1\"], \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": ["
                + "{\"introduced\": \"2.0\"}, {\"fixed\": \"2.1\"}, {\"introduced\": \"3.0\"}, {\"fixed\": \"3.1\"}]}]}]}]}";
        VulnerabilityFinding f = only(listed, "1.1");
        assertEquals("2.1", f.fixedVersion());
        assertEquals(null, f.introducedVersion());
    }

    @Test
    void oddlyShapedAffectedEntriesAndRangesAreSkippedOrTolerated() {
        String json = "{\"vulns\": [{\"id\": \"GHSA-x\", \"severity\": [{}], \"affected\": ["
                // no package at all: applies to whatever was queried
                + "{\"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"2.0\"}]}]},"
                // a package without a name never matches
                + "{\"package\": {}, \"ranges\": [{\"type\": \"ECOSYSTEM\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"9.0\"}]}]},"
                // untyped, non-ECOSYSTEM and event-less ranges, and an event with neither bound, are ignored
                + "{\"package\": {\"name\": \"com.example:lib\"}, \"ranges\": ["
                + "{\"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"8.0\"}]},"
                + "{\"type\": \"GIT\", \"events\": [{\"introduced\": \"0\"}, {\"fixed\": \"7.0\"}]},"
                + "{\"type\": \"ECOSYSTEM\"},"
                + "{\"type\": \"ECOSYSTEM\", \"events\": [{\"limit\": \"6.0\"}]}]}"
                + "]}]}";
        VulnerabilityFinding finding = only(json, "1.0");
        assertEquals("2.0", finding.fixedVersion());
        assertEquals("UNKNOWN", finding.severity());
        assertEquals(List.of(), OsvPackageVulnerabilities.findingsForVersion(json, LIB, "2.5"));
    }

    @Test
    void aBlankIntroducedBoundMeansSinceInceptionAndAnUnlabelledDatabaseEntryUsesTheVector() {
        VulnerabilityFinding fixed = only(advisory(", \"database_specific\": {\"cwe_ids\": []}" + cvss("CVSS:3.1/C:H/I:N/A:N"),
                "{\"introduced\": \"\"}, {\"fixed\": \"2.0\"}"), "1.0");
        assertNull(fixed.introducedVersion());
        assertEquals("HIGH", fixed.severity());
        assertNull(only(advisory("", "{\"introduced\": \"\"}, {\"last_affected\": \"2.0\"}"), "1.0").introducedVersion());
    }

    private List<VulnerabilityFinding> findings(String version) {
        return OsvPackageVulnerabilities.findingsForVersion(LOGBACK_CORE_RESPONSE, LOGBACK_CORE, version);
    }
}
