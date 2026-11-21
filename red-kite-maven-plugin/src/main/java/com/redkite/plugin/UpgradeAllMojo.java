package com.redkite.plugin;

import com.redkite.core.domain.RecommendationReason;
import java.util.function.Predicate;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;

/**
 * Upgrades everything RedKite recommends: CVE fixes, plus newer versions of direct dependencies. A direct
 * dependency is upgraded where it is declared. A transitive dependency is only changed for a vulnerability,
 * by a pin in the root POM. Downgrades and SNAPSHOT replacements are never done in bulk, and pinned
 * dependencies are left alone (change those with {@code redkite:upgrade}).
 */
@Mojo(name = "upgrade-all", aggregator = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class UpgradeAllMojo extends BulkUpgradeMojo {
    @Override
    Predicate<RecommendationReason> reasons() {
        return reason -> switch (reason) {
            case CVE_FIX, CVE_BEST_EFFORT, PATCH_AVAILABLE, MINOR_AVAILABLE, MAJOR_AVAILABLE -> true;
            case CVE_FIX_DOWNGRADE, SNAPSHOT_REPLACEMENT -> false;
        };
    }
}
