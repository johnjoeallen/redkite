package com.redkite.core.service;

import com.redkite.core.domain.*;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class RemediationClassifier {
    private RemediationClassifier() {
    }

    public static RemediationStatus classify(
            ScanComponent component,
            List<VulnerabilityFinding> allFindings,
            List<UpgradeRecommendation> allRecommendations,
            List<MetadataResult> allMetadata) {
        return classify(component, allFindings, allRecommendations, allMetadata, Set.of());
    }

    /**
     * @param pinnedCoordinates coordinates the user has explicitly pinned. A pin records a
     *      deliberate decision to hold a dependency at its current version, so a plain (non-CVE)
     *      update recommendation is suppressed for a pinned coordinate — counting it as still
     *      "needing remediation" would contradict the decision the pin itself records. CVE
     *      findings are never suppressed this way, pinned or not; only the "update recommended"
     *      reason is.
     */
    public static RemediationStatus classify(
            ScanComponent component,
            List<VulnerabilityFinding> allFindings,
            List<UpgradeRecommendation> allRecommendations,
            List<MetadataResult> allMetadata,
            Set<ComponentCoordinate> pinnedCoordinates) {

        List<String> reasons = new ArrayList<>();
        boolean isSnapshot = component.snapshot();
        if (isSnapshot) reasons.add("Snapshot dependency");

        boolean hasDeclaredVersion = component.direct()
                && component.versionSource() == VersionSource.LITERAL;
        if (hasDeclaredVersion) reasons.add("Declared inline version");

        List<VulnerabilityFinding> componentFindings = findingsFor(component, allFindings);
        boolean hasVulnerability = !componentFindings.isEmpty();
        AdvisorySeverity highestSeverity = AdvisoryClassifier.highest(componentFindings);
        if (hasVulnerability) {
            reasons.add("Known " + highestSeverity.label().toLowerCase() + " severity advisory");
        }

        boolean isPinned = pinnedCoordinates != null && pinnedCoordinates.contains(component.coordinate());
        boolean hasRecommendation = hasRecommendationFor(component, allRecommendations) && !isPinned;
        if (hasRecommendation && !hasVulnerability && !isSnapshot) {
            reasons.add("Update recommended");
        }

        boolean hasStaleMetadata = hasStaleMetadataFor(component, allMetadata);
        if (hasStaleMetadata) reasons.add("Stale or incomplete metadata");

        boolean needsRemediation = isSnapshot || hasDeclaredVersion || hasVulnerability
                || hasRecommendation || hasStaleMetadata;

        return new RemediationStatus(component.id(), needsRemediation, isSnapshot,
                hasDeclaredVersion, hasVulnerability, hasRecommendation, hasStaleMetadata,
                highestSeverity, componentFindings.size(), List.copyOf(reasons));
    }

    public static ReportSummary summarize(ScanReport report) {
        return summarize(report, Set.of());
    }

    /** @param pinnedCoordinates see {@link #classify(ScanComponent, List, List, List, Set)}. */
    public static ReportSummary summarize(ScanReport report, Set<ComponentCoordinate> pinnedCoordinates) {
        // Group by distinct dependency (coordinate + version), not by per-module ScanComponent
        // instance — the same dependency resolved into many modules is one real dependency, not
        // one per module. This keeps every number in the banner (totals, severities, reasons) on
        // the same unit so they reconcile with each other.
        Map<String, List<ScanComponent>> byDependency = new LinkedHashMap<>();
        for (ScanComponent component : report.components()) {
            String dependency = component.coordinate().groupId() + ":" + component.coordinate().artifactId()
                    + "@" + component.version();
            byDependency.computeIfAbsent(dependency, k -> new ArrayList<>()).add(component);
        }

        int total = 0;
        int needsRemediationCount = 0;
        int snapshotCount = 0;
        int declaredVersionCount = 0;
        int staleMetadataCount = 0;
        int recommendationCount = 0;
        Map<RemediationReason, List<String>> depsByReason = new EnumMap<>(RemediationReason.class);

        for (Map.Entry<String, List<ScanComponent>> entry : byDependency.entrySet()) {
            String dependency = entry.getKey();
            total++;
            // A dependency can appear direct in one module and transitive in another, or have its
            // metadata lookup succeed in one module and fail in another — combine every module
            // occurrence with OR, so the dependency is flagged if any occurrence needs attention.
            boolean needsRemediation = false, isSnapshot = false, hasDeclaredVersion = false,
                    hasVulnerability = false, hasRecommendation = false, hasStaleMetadata = false;
            for (ScanComponent component : entry.getValue()) {
                RemediationStatus status = classify(component,
                        report.vulnerabilityFindings(),
                        report.recommendations(),
                        report.metadataResults(),
                        pinnedCoordinates);
                needsRemediation |= status.needsRemediation();
                isSnapshot |= status.isSnapshot();
                hasDeclaredVersion |= status.hasDeclaredVersionDeclaration();
                hasVulnerability |= status.hasVulnerability();
                hasRecommendation |= status.hasUpgradeRecommendation();
                hasStaleMetadata |= status.hasStaleMetadata();
            }
            if (needsRemediation) needsRemediationCount++;
            if (isSnapshot) {
                snapshotCount++;
                depsByReason.computeIfAbsent(RemediationReason.SNAPSHOT, k -> new ArrayList<>()).add(dependency);
            }
            if (hasDeclaredVersion) {
                declaredVersionCount++;
                depsByReason.computeIfAbsent(RemediationReason.DECLARED_VERSION, k -> new ArrayList<>()).add(dependency);
            }
            // Matches the "Update recommended" reason in classify(): only counted here when it's
            // not already covered by the vulnerability or snapshot buckets, so a dependency isn't
            // double-labeled across banners for essentially the same underlying issue.
            if (hasRecommendation && !hasVulnerability && !isSnapshot) {
                recommendationCount++;
                depsByReason.computeIfAbsent(RemediationReason.UPGRADE_RECOMMENDED, k -> new ArrayList<>()).add(dependency);
            }
            if (hasStaleMetadata) {
                staleMetadataCount++;
                depsByReason.computeIfAbsent(RemediationReason.STALE_METADATA, k -> new ArrayList<>()).add(dependency);
            }
        }

        // A vulnerability finding is duplicated once per module a dependency resolves into
        // (the same groupId:artifactId:version can appear as a distinct ScanComponent per
        // module). Dedupe by advisory + coordinate + affected version so a single CVE is only
        // counted once, regardless of how many modules pulled in the vulnerable dependency.
        int criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0, unknownCount = 0;
        Set<String> seenFindings = new LinkedHashSet<>();
        Map<AdvisorySeverity, List<String>> depsBySeverity = new EnumMap<>(AdvisorySeverity.class);
        for (VulnerabilityFinding f : report.vulnerabilityFindings()) {
            String dependency = f.coordinate().groupId() + ":" + f.coordinate().artifactId() + "@" + f.affectedVersion();
            String findingKey = (f.advisoryId() == null ? "" : f.advisoryId()) + "|" + dependency;
            if (!seenFindings.add(findingKey)) continue;

            AdvisorySeverity severity = AdvisoryClassifier.severity(f);
            switch (severity) {
                case CRITICAL -> criticalCount++;
                case HIGH -> highCount++;
                case MEDIUM -> mediumCount++;
                case LOW -> lowCount++;
                case UNKNOWN -> unknownCount++;
                default -> {
                }
            }
            depsBySeverity.computeIfAbsent(severity, k -> new ArrayList<>()).add(dependency);
        }

        return new ReportSummary(total, needsRemediationCount, total - needsRemediationCount,
                criticalCount, highCount, mediumCount, lowCount, unknownCount,
                snapshotCount, declaredVersionCount, staleMetadataCount, recommendationCount,
                depsBySeverity, depsByReason);
    }

    private static List<VulnerabilityFinding> findingsFor(
            ScanComponent component, List<VulnerabilityFinding> allFindings) {
        List<VulnerabilityFinding> result = new ArrayList<>();
        if (allFindings == null) return result;
        String groupId = component.coordinate().groupId();
        String artifactId = component.coordinate().artifactId();
        String version = component.version();
        for (VulnerabilityFinding f : allFindings) {
            if (f == null || f.coordinate() == null) continue;
            if (groupId.equals(f.coordinate().groupId())
                    && artifactId.equals(f.coordinate().artifactId())
                    && version.equals(f.affectedVersion())) {
                result.add(f);
            }
        }
        return result;
    }

    private static boolean hasRecommendationFor(
            ScanComponent component, List<UpgradeRecommendation> allRecommendations) {
        if (allRecommendations == null) return false;
        for (UpgradeRecommendation rec : allRecommendations) {
            if (rec.id() == component.id()) return true;
            if (rec.affectedComponentIds() != null
                    && rec.affectedComponentIds().contains(component.id())) return true;
        }
        return false;
    }

    private static boolean hasStaleMetadataFor(
            ScanComponent component, List<MetadataResult> allMetadata) {
        if (allMetadata == null) return false;
        for (MetadataResult m : allMetadata) {
            if (m.componentId() != component.id()) continue;
            if (!m.complete()) return true;
            if (isProblematicCacheState(m.cacheState())) return true;
            if (isProblematicStatus(m.status())) return true;
        }
        return false;
    }

    private static boolean isProblematicCacheState(CacheState state) {
        if (state == null) return false;
        return switch (state) {
            case STALE, MISSING, NEGATIVE_STALE, ERROR_CACHED -> true;
            default -> false;
        };
    }

    private static boolean isProblematicStatus(MetadataStatus status) {
        if (status == null) return false;
        return switch (status) {
            case RATE_LIMITED, PROVIDER_ERROR, OFFLINE_MISSING, OFFLINE_STALE_USED,
                    STALE_USED, MISSING -> true;
            default -> false;
        };
    }
}
