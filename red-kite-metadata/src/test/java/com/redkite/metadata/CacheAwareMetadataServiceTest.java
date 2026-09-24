package com.redkite.metadata;

import com.redkite.core.domain.CacheState;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.MetadataResult;
import com.redkite.core.domain.MetadataStatus;
import com.redkite.core.domain.MetadataType;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionMetadata;
import com.redkite.core.domain.VersionSource;
import com.redkite.core.domain.VulnerabilityFinding;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CacheAwareMetadataServiceTest {
    private static ScanComponent component(long id, String artifactId, String version, boolean snapshot) {
        return new ScanComponent(id, new ComponentCoordinate("org.example", artifactId), version, DependencyScope.COMPILE,
                true, VersionSource.LITERAL, "pom.xml", "/project", Map.of(), snapshot, "pom.xml#dependency", "pom.xml");
    }

    private final List<String> versionLookups = new ArrayList<>();
    private final List<String> vulnLookups = new ArrayList<>();
    private final Instant checkedAt = Instant.now().minus(Duration.ofHours(1));

    private final VersionMetadataProvider versions = new VersionMetadataProvider() {
        @Override
        public VersionMetadata latestVersion(ComponentCoordinate coordinate) {
            return latestVersion(coordinate, null);
        }

        @Override
        public VersionMetadata latestVersion(ComponentCoordinate coordinate, String currentVersion) {
            versionLookups.add(coordinate.artifactId() + "@" + currentVersion);
            boolean old = coordinate.artifactId().equals("old");
            return new VersionMetadata(coordinate, "2.0", "1.9", List.of("1.9", "2.0"), true,
                    old ? Instant.now().minus(Duration.ofDays(2)) : checkedAt, "src",
                    !old, CacheState.FRESH, MetadataStatus.FRESH, List.of("1.0", "1.9", "2.0"));
        }
    };

    private final VulnerabilityProvider vulns = (coordinate, version) -> {
        vulnLookups.add(coordinate.artifactId() + "@" + version);
        return coordinate.artifactId().equals("bad")
                ? List.of(new VulnerabilityFinding("GHSA-1", "HIGH", coordinate, version, "2.0", "0", true, "pom.xml#dependency", List.of("CVE-1"), null))
                : List.of();
    };

    private final CacheAwareMetadataService service = new CacheAwareMetadataService(versions, vulns);

    @Test
    void versionMetadataSkipsSnapshotsAndCarriesProviderResults() {
        List<MetadataResult> results = service.evaluateVersionMetadata("scan-1",
                List.of(component(1, "lib", "1.0", false), component(2, "snap", "1.0-SNAPSHOT", true)), false);

        assertEquals(List.of("lib@1.0"), versionLookups);
        MetadataResult lib = results.get(0);
        assertEquals("scan-1", lib.scanId());
        assertEquals(1, lib.componentId());
        assertEquals(MetadataType.VERSION, lib.metadataType());
        assertEquals("src", lib.provider());
        assertEquals("2.0", lib.latestVersion());
        assertEquals("1.9", lib.latestSameMajorVersion());
        assertEquals(List.of("1.9", "2.0"), lib.upgradePathVersions());
        assertEquals(List.of("1.0", "1.9", "2.0"), lib.allStableVersions());
        assertTrue(lib.complete());
        assertEquals(checkedAt.plus(Duration.ofHours(24)), lib.cacheExpiryAt());
        assertEquals("Fresh version metadata", lib.message());

        MetadataResult snap = results.get(1);
        assertEquals(MetadataStatus.NOT_APPLICABLE, snap.status());
        assertEquals(CacheState.MISSING, snap.cacheState());
        assertFalse(snap.complete());
        assertEquals("none", snap.provider());
    }

    @Test
    void incompleteExpiredMetadataIsReportedStale() {
        MetadataResult online = service.evaluateVersionMetadata("s", List.of(component(1, "old", "1.0", false)), false).get(0);
        assertEquals("Stale version metadata", online.message());
        assertFalse(online.complete());
        assertEquals(MetadataStatus.STALE_USED, online.status());
        assertEquals(CacheState.STALE, online.cacheState());

        MetadataResult offline = service.evaluateVersionMetadata("s", List.of(component(1, "old", "1.0", false)), true).get(0);
        assertEquals(MetadataStatus.OFFLINE_STALE_USED, offline.status());
    }

    @Test
    void vulnerabilityResultsSkipSnapshotsAndReportFindings() {
        List<MetadataResult> results = service.evaluateVulnerabilities("scan-2",
                List.of(component(1, "bad", "1.0", false), component(2, "good", "1.0", false),
                        component(3, "snap", "1-SNAPSHOT", true)), false);

        assertEquals(List.of("bad@1.0", "good@1.0"), vulnLookups);
        assertEquals("Vulnerabilities found", results.get(0).message());
        assertEquals("No CVEs found in available metadata; metadata complete.", results.get(1).message());
        assertEquals(MetadataType.VULNERABILITY, results.get(1).metadataType());
        assertEquals("osv", results.get(1).provider());
        assertEquals(MetadataStatus.FRESH, results.get(1).status());
        assertEquals(MetadataStatus.NOT_APPLICABLE, results.get(2).status());
    }
}
