package com.redkite.metadata;

import com.redkite.core.domain.*;
import com.redkite.core.service.MetadataPolicy;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class CacheAwareMetadataService {
    private static final Logger LOGGER = Logger.getLogger(CacheAwareMetadataService.class.getName());

    private final VersionMetadataProvider versionProvider;
    private final VulnerabilityProvider vulnerabilityProvider;

    public CacheAwareMetadataService(VersionMetadataProvider versionProvider, VulnerabilityProvider vulnerabilityProvider) {
        this.versionProvider = versionProvider;
        this.vulnerabilityProvider = vulnerabilityProvider;
    }

    public List<MetadataResult> evaluateVersionMetadata(String scanId, List<ScanComponent> components, boolean offlineMode) {
        List<MetadataResult> results = new ArrayList<>();
        Instant now = Instant.now();
        for (ScanComponent component : components) {
            if (component.snapshot()) {
                LOGGER.info(() -> "Skipping Maven version lookup for SNAPSHOT component " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                results.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, "none", component.version(), "unknown", "unknown", List.of(), false, MetadataStatus.NOT_APPLICABLE, CacheState.MISSING, null, null, now, null, "SNAPSHOT dependencies are not scanned for version currency."));
                continue;
            }
            LOGGER.info(() -> "Attempting Maven version metadata lookup for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + "@" + component.version());
            var metadata = versionProvider.latestVersion(component.coordinate(), component.version());
            var freshness = MetadataPolicy.evaluate(now, metadata.checkedAt(), metadata.checkedAt().plus(Duration.ofHours(24)), metadata.complete(), false, offlineMode);
            LOGGER.info(() -> "Maven version metadata result for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + ": complete=" + freshness.complete() + ", status=" + freshness.status() + ", cacheState=" + freshness.cacheState());
            results.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, metadata.source(), component.version(), metadata.latestVersion(), metadata.latestSameMajorVersion(), metadata.upgradePathVersions(), freshness.complete(), freshness.status(), freshness.cacheState(), metadata.checkedAt(), metadata.checkedAt().plus(Duration.ofHours(24)), now, MetadataPolicy.staleUntil(metadata.checkedAt(), Duration.ofHours(24), Duration.ofDays(7)), freshness.complete() ? "Fresh version metadata" : "Stale version metadata"));
        }
        return results;
    }

    public List<MetadataResult> evaluateVulnerabilities(String scanId, List<ScanComponent> components, boolean offlineMode) {
        List<MetadataResult> results = new ArrayList<>();
        Instant now = Instant.now();
        for (ScanComponent component : components) {
            if (component.snapshot()) {
                LOGGER.info(() -> "Skipping CVE lookup for SNAPSHOT component " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                results.add(new MetadataResult(scanId, component.id(), MetadataType.VULNERABILITY, "none", component.version(), "unknown", "unknown", List.of(), false, MetadataStatus.NOT_APPLICABLE, CacheState.MISSING, null, null, now, null, "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata."));
                continue;
            }
            LOGGER.info(() -> "Attempting CVE metadata lookup for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + "@" + component.version());
            var vulns = vulnerabilityProvider.vulnerabilities(component.coordinate(), component.version());
            boolean complete = true;
            LOGGER.info(() -> "CVE metadata lookup complete for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + "; findings=" + vulns.size());
            results.add(new MetadataResult(scanId, component.id(), MetadataType.VULNERABILITY, "osv", component.version(), "unknown", "unknown", List.of(), complete, MetadataStatus.FRESH, CacheState.FRESH, now, now.plus(Duration.ofHours(12)), now, null, vulns.isEmpty() ? "No CVEs found in available metadata; metadata complete." : "Vulnerabilities found"));
        }
        return results;
    }
}
