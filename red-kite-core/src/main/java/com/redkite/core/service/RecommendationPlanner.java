package com.redkite.core.service;

import com.redkite.core.domain.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class RecommendationPlanner {
    private RecommendationPlanner() {
    }

    public static List<UpgradeRecommendation> recommendOutdatedDependencies(List<ScanComponent> components, List<VersionMetadata> versions) {
        List<UpgradeRecommendation> recommendations = new ArrayList<>();
        for (ScanComponent component : components) {
            if (component.snapshot()) {
                recommendations.add(new UpgradeRecommendation(
                        component.id(),
                        component.coordinate(),
                        component.version(),
                        "released-version-needed",
                        RecommendationReason.SNAPSHOT_REPLACEMENT,
                        scopeToRisk(component.scope()),
                        RecommendationConfidence.MEDIUM,
                        List.of(),
                        List.of(component.id()),
                        new PlannedFileChange(
                                component.sourceFilePath(),
                                "",
                                versionSourceToChange(component.versionSource()),
                                component.coordinate().groupId(),
                                component.coordinate().artifactId(),
                                null,
                                component.version(),
                                "released-version-needed",
                                "Use release.",
                                component.id())));
            }
        }
        return recommendations;
    }

    public static RiskLevel scopeToRisk(DependencyScope scope) {
        return switch (scope) {
            case COMPILE, RUNTIME -> RiskLevel.MAJOR;
            case PROVIDED, PLUGIN_BUILD -> RiskLevel.ELEVATED;
            case TEST -> RiskLevel.MINOR;
            default -> RiskLevel.UNKNOWN;
        };
    }

    public static ChangeType versionSourceToChange(VersionSource source) {
        return switch (source) {
            case PROPERTY -> ChangeType.MAVEN_PROPERTY_UPDATE;
            case PARENT_MANAGED -> ChangeType.MAVEN_PARENT_VERSION_UPDATE;
            case BOM_MANAGED -> ChangeType.MAVEN_BOM_VERSION_UPDATE;
            case LITERAL, UNKNOWN -> ChangeType.MAVEN_DIRECT_DEPENDENCY_VERSION_UPDATE;
        };
    }

    public static String completenessMessage(boolean complete, boolean rateLimited, boolean staleUsed) {
        if (complete) {
            return "Report complete. Dependency and vulnerability metadata was checked using fresh provider data or fresh cache.";
        }
        if (rateLimited && staleUsed) {
            return "Report incomplete. Some metadata could not be refreshed because a provider rate-limited the local RedKite server. Stale cached data was used where available. Components with stale or missing data require rescan.";
        }
        if (rateLimited) {
            return "Report incomplete. Some metadata could not be refreshed because a provider rate-limited the local RedKite server.";
        }
        return "Report incomplete. Some components have unknown metadata because no cached metadata was available and the provider could not be queried.";
    }

    public static Instant suggestedRetry(Instant now, int hours) {
        return now.plusSeconds(hours * 3600L);
    }
}
