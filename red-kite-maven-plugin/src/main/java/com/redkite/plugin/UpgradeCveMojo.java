package com.redkite.plugin;

import com.redkite.core.domain.RecommendationReason;
import java.util.function.Predicate;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;

/**
 * Upgrades only to clear vulnerabilities, to the version that fixes them. A direct dependency is upgraded
 * where it is declared; a transitive one gets a pin in the root POM. Best-effort and downgrade fixes are not
 * applied, and pinned dependencies are left alone (change those with {@code redkite:upgrade}).
 */
@Mojo(name = "upgrade-cve", aggregator = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class UpgradeCveMojo extends BulkUpgradeMojo {
    @Override
    Predicate<RecommendationReason> reasons() {
        return reason -> reason == RecommendationReason.CVE_FIX;
    }
}
