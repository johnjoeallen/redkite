package com.redkite.server;

import com.redkite.core.domain.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Logger;

import static com.redkite.server.Versions.*;

/** Turns a scan's raw dependency input into a report: version metadata, vulnerabilities, licenses and upgrade recommendations. */
final class ReportBuilder {
    private static final Logger LOGGER = Logger.getLogger(ReportBuilder.class.getName());
    private final Store store;
    private final CveFixFinder cveFixes;

    ReportBuilder(Store store, CveFixFinder cveFixes) {
        this.store = store;
        this.cveFixes = cveFixes;
    }

    ScanReport buildReport(ScanInput input, String projectId, String scanId, Consumer<String> progress) {
        List<ScanComponent> components = input.components();
        int total = components.size();

        // Pass 1: version metadata
        Map<Long, VersionMetadata> versionMap = new LinkedHashMap<>();
        for (int i = 0; i < components.size(); i++) {
            ScanComponent c = components.get(i);
            progress.accept("Version " + (i + 1) + "/" + total);
            if (!c.snapshot()) {
                versionMap.put(c.id(), store.versionProvider.latestVersion(c.coordinate(), c.version()));
            }
        }

        // Pass 2: vulnerability scan
        Map<Long, List<VulnerabilityFinding>> vulnMap = new LinkedHashMap<>();
        for (int i = 0; i < components.size(); i++) {
            ScanComponent c = components.get(i);
            progress.accept("Vulnerability " + (i + 1) + "/" + total);
            if (!c.snapshot()) {
                vulnMap.put(c.id(), store.vulnerabilityProvider.vulnerabilities(c.coordinate(), c.version()));
            }
        }

        // Pass 3: license lookup — unlike version/vulnerability checks, this runs for
        // SNAPSHOT components too: a snapshot artifact's own POM still declares a real
        // license (or inherits one), independent of whether it can be verified against
        // stable Maven/CVE metadata.
        Map<Long, List<String>> licenseMap = new LinkedHashMap<>();
        for (int i = 0; i < components.size(); i++) {
            ScanComponent c = components.get(i);
            progress.accept("License " + (i + 1) + "/" + total);
            licenseMap.put(c.id(), store.licenses.resolveLicenses(c.coordinate(), c.version()));
        }

        // Pass 4: update analysis
        progress.accept("Updates");
        List<SnapshotDependencyRisk> snapshotRisks = new ArrayList<>();
        List<UpgradeRecommendation> recs = new ArrayList<>();
        List<MetadataResult> metadata = new ArrayList<>();
        List<VulnerabilityFinding> vulnerabilityFindings = new ArrayList<>();
        boolean complete = true;
        for (ScanComponent component : components) {
            LOGGER.info(() -> "Enriching component " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " version=" + component.version());
            if (component.snapshot()) {
                LOGGER.info(() -> "Component is SNAPSHOT; recording unverified dependency risk for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                snapshotRisks.add(new SnapshotDependencyRisk(component.id(), "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata.", "Use release.", severity(component.scope())));
                String target = component.version() == null ? "1.0.0" : component.version().replace("-SNAPSHOT", "");
                recs.add(new UpgradeRecommendation(component.id(), component.coordinate(), component.version(), target, RecommendationReason.SNAPSHOT_REPLACEMENT, RiskLevel.MAJOR, RecommendationConfidence.MEDIUM, List.of(), List.of(component.id())));
                LOGGER.info(() -> "No Maven/CVE verification attempted for SNAPSHOT component " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, "none", component.version(), "unknown", "unknown", List.of(), List.of(), false, MetadataStatus.NOT_APPLICABLE, CacheState.MISSING, null, null, Instant.now(), null, "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata."));
                metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VULNERABILITY, "none", component.version(), "unknown", "unknown", List.of(), List.of(), false, MetadataStatus.NOT_APPLICABLE, CacheState.MISSING, null, null, Instant.now(), null, "SNAPSHOT dependency cannot be verified against stable Maven/CVE metadata."));
                List<String> snapshotLicenses = licenseMap.getOrDefault(component.id(), List.of());
                String snapshotLicenseMessage = snapshotLicenses.isEmpty() ? "No license declared." : "Declared: " + String.join(", ", snapshotLicenses) + ".";
                metadata.add(new MetadataResult(scanId, component.id(), MetadataType.LICENSE, "pom", component.version(), "unknown", "unknown", snapshotLicenses, List.of(), true, MetadataStatus.FRESH, CacheState.FRESH, Instant.now(), null, Instant.now(), null, snapshotLicenseMessage));
            } else {
                VersionMetadata versionMetadata = versionMap.get(component.id());
                LOGGER.info(() -> "Maven version metadata for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " => latest=" + versionMetadata.latestVersion() + ", sameMajor=" + versionMetadata.latestSameMajorVersion() + ", complete=" + versionMetadata.complete() + ", status=" + versionMetadata.status());
                String versionMessage = versionMetadata.complete()
                        ? "Latest Maven release is " + versionMetadata.latestVersion() + "."
                        : "No cached Maven metadata was available; version is unknown.";
                metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VERSION, versionMetadata.source(), component.version(), versionMetadata.latestVersion(), versionMetadata.latestSameMajorVersion(), versionMetadata.upgradePathVersions(), versionMetadata.allStableVersions(), versionMetadata.complete(), versionMetadata.status(), versionMetadata.cacheState(), versionMetadata.checkedAt(), null, Instant.now(), null, versionMessage));
                if (!versionMetadata.complete()) {
                    complete = false;
                }

                List<VulnerabilityFinding> compVulns = vulnMap.getOrDefault(component.id(), List.of());
                boolean hasVulns = !compVulns.isEmpty();
                String vulnMessage = hasVulns
                        ? "Found " + compVulns.size() + " vulnerabilit" + (compVulns.size() == 1 ? "y" : "ies") + "."
                        : "No known vulnerabilities.";
                metadata.add(new MetadataResult(scanId, component.id(), MetadataType.VULNERABILITY, "osv.dev", component.version(), "unknown", "unknown", List.of(), List.of(), true, MetadataStatus.FRESH, CacheState.FRESH, Instant.now(), null, Instant.now(), null, vulnMessage));

                List<String> licenses = licenseMap.getOrDefault(component.id(), List.of());
                String licenseMessage = licenses.isEmpty() ? "No license declared." : "Declared: " + String.join(", ", licenses) + ".";
                metadata.add(new MetadataResult(scanId, component.id(), MetadataType.LICENSE, "pom", component.version(), "unknown", "unknown", licenses, List.of(), true, MetadataStatus.FRESH, CacheState.FRESH, Instant.now(), null, Instant.now(), null, licenseMessage));

                for (VulnerabilityFinding f : compVulns) {
                    vulnerabilityFindings.add(new VulnerabilityFinding(f.advisoryId(), f.severity(), f.coordinate(), f.affectedVersion(), f.fixedVersion(), f.introducedVersion(), component.direct(), component.owningVersionControlPoint(), f.cves(), null));
                }

                if (versionMetadata.complete() && canPlanUpgrade(component) && hasVulns) {
                    CveFixFinder.CveFixResult fix = cveFixes.resolveCveFix(component, compVulns, versionMetadata, input.allowMajorUpgrades());
                    if (fix != null) {
                        RiskLevel risk = component.direct() ? upgradeRisk(component.version(), fix.target()) : RiskLevel.ELEVATED;
                        recs.add(new UpgradeRecommendation(component.id(), component.coordinate(), component.version(),
                                fix.target(), fix.reason(), risk, RecommendationConfidence.HIGH, List.of(), List.of(component.id())));
                        LOGGER.info(() -> "Resolved CVE fix (" + fix.reason() + ") for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " => " + component.version() + " -> " + fix.target());
                    } else {
                        LOGGER.info(() -> "No CVE fix found (upgrade, downgrade, or best-effort) for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId());
                    }
                } else if (versionMetadata.complete() && canPlanUpgrade(component)) {
                    String target = selectUpgradeTarget(component.version(), versionMetadata);
                    if (target != null && isUpgradeable(component.version(), target)) {
                        if (!input.allowMajorUpgrades() && isMajorUpgrade(component.version(), target)) {
                            LOGGER.info(() -> "Skipping major upgrade recommendation for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " because the scan did not allow major upgrades");
                        } else {
                            RecommendationReason reason = upgradeReason(component.version(), target);
                            RiskLevel risk = component.direct() ? upgradeRisk(component.version(), target) : RiskLevel.ELEVATED;
                            RecommendationConfidence confidence = RecommendationConfidence.HIGH;
                            recs.add(new UpgradeRecommendation(component.id(), component.coordinate(), component.version(), target, reason, risk, confidence, List.of(), List.of(component.id())));
                            LOGGER.info(() -> "Created Maven upgrade recommendation for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " => " + component.version() + " -> " + target);
                        }
                    } else if (versionMetadata.complete()) {
                        LOGGER.info(() -> "No upgrade recommendation selected for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " because no later version was suitable");
                    }
                } else if (!component.direct()) {
                    LOGGER.info(() -> "Transitive dependency " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " is reported without an edit recommendation");
                } else if (versionMetadata.complete()) {
                    LOGGER.info(() -> "Maven dependency is up to date for " + component.coordinate().groupId() + ":" + component.coordinate().artifactId() + " at version " + component.version());
                }
            }
        }
        List<String> treeWarnings = input.treeParseWarnings() != null ? input.treeParseWarnings() : List.of();
        if (!treeWarnings.isEmpty()) complete = false;
        boolean buildFailed = treeWarnings.stream().anyMatch(w -> w.startsWith("[BUILD_FAILED]"));
        String message;
        if (complete) {
            message = "Analysis complete. Dependency and vulnerability metadata was checked using fresh provider data or fresh cache.";
        } else if (buildFailed) {
            message = "Build failed. Maven could not resolve the project model — check the analysis log for details and re-analyse after fixing the POM.";
        } else if (!treeWarnings.isEmpty()) {
            message = "Analysis incomplete. " + treeWarnings.size() + " dependency tree line(s) could not be parsed. Re-analyse after resolving the issues listed below.";
        } else {
            message = "Analysis incomplete. Some Maven metadata could not be refreshed or was unavailable. The analysis is still shown with unknown metadata and re-analysis is suggested.";
        }
        return new ScanReport(scanId, projectId, complete, message, Instant.now(), input.components(), input.dependencyEdges(), List.copyOf(vulnerabilityFindings), recs, snapshotRisks, metadata, treeWarnings);
    }

    static String selectUpgradeTarget(String currentVersion, VersionMetadata versionMetadata) {
        if (versionMetadata == null) {
            return null;
        }
        String sameMajor = versionMetadata.latestSameMajorVersion();
        if (!isPreRelease(sameMajor) && isUpgradeable(currentVersion, sameMajor)) {
            return sameMajor;
        }
        if (versionMetadata.upgradePathVersions() == null || versionMetadata.upgradePathVersions().isEmpty()) {
            return versionMetadata == null ? null : versionMetadata.latestVersion();
        }
        for (String candidate : versionMetadata.upgradePathVersions()) {
            if (candidate == null || candidate.isBlank() || isPreRelease(candidate)) {
                continue;
            }
            if (!isUpgradeable(currentVersion, candidate)) {
                continue;
            }
            if (major(currentVersion) == major(candidate) && minor(currentVersion) == minor(candidate)) {
                return candidate;
            }
            if (major(currentVersion) == major(candidate) && minor(candidate) > minor(currentVersion)) {
                return candidate;
            }
        }
        for (String candidate : versionMetadata.upgradePathVersions()) {
            if (candidate == null || candidate.isBlank() || isPreRelease(candidate)) {
                continue;
            }
            if (!isUpgradeable(currentVersion, candidate)) {
                continue;
            }
            return candidate;
        }
        String latest = versionMetadata.latestVersion();
        if (!isPreRelease(latest) && isUpgradeable(currentVersion, latest)) {
            return latest;
        }
        return null;
    }

    private static boolean isUpgradeable(String currentVersion, String latestVersion) {
        if (currentVersion == null || currentVersion.isBlank() || latestVersion == null || latestVersion.isBlank()) {
            return false;
        }
        return compareVersions(currentVersion, latestVersion) < 0;
    }

    static RecommendationReason upgradeReason(String currentVersion, String targetVersion) {
        if (isMajorUpgrade(currentVersion, targetVersion)) {
            return RecommendationReason.MAJOR_AVAILABLE;
        }
        int currentMinor = minor(currentVersion);
        int targetMinor = minor(targetVersion);
        if (targetMinor > currentMinor) {
            return RecommendationReason.MINOR_AVAILABLE;
        }
        return RecommendationReason.PATCH_AVAILABLE;
    }

    static RiskLevel upgradeRisk(String currentVersion, String targetVersion) {
        if (isMajorUpgrade(currentVersion, targetVersion)) {
            return RiskLevel.MAJOR;
        }
        int currentMinor = minor(currentVersion);
        int targetMinor = minor(targetVersion);
        if (targetMinor > currentMinor) {
            return RiskLevel.MINOR;
        }
        return RiskLevel.PATCH;
    }

    private String severity(DependencyScope scope) {
        return switch (scope) {
            case COMPILE, RUNTIME -> "HIGH";
            case PROVIDED, PLUGIN_BUILD -> "MEDIUM";
            case TEST -> "LOW";
            default -> "UNKNOWN";
        };
    }

    private static boolean canPlanUpgrade(ScanComponent component) {
        return component != null;
    }
}
