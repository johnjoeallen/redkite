package com.redkite.plugin;

import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.server.ReportExporter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import org.apache.maven.plugin.MojoFailureException;

/** Shared by the goals where RedKite chooses the upgrades. A pinned dependency is never touched; it is
 *  listed so it can be named explicitly with {@code redkite:upgrade}. */
abstract class BulkUpgradeMojo extends PomChangeMojo {
    /** Which recommendation reasons this goal acts on. */
    abstract Predicate<RecommendationReason> reasons();

    /** What RedKite chose, and what it left alone. */
    record Selection(Map<String, String> upgrades, List<String> skippedPinned, List<String> conflicting) {}

    /**
     * Picks one target per dependency from the recommendations: those whose reason is accepted, that the
     * report would list (any for a direct dependency, only vulnerability-driven for a transitive one), and
     * that are not user-pinned. A dependency recommended to different targets in different modules is left
     * for the user to name explicitly.
     */
    static Selection select(ScanReport report, Set<String> pinned, Predicate<RecommendationReason> reasons) {
        Set<String> directCoords = new HashSet<>();
        for (ScanComponent c : report.components()) {
            if (c.direct()) directCoords.add(c.coordinate().groupId() + ":" + c.coordinate().artifactId());
        }
        Map<String, String> upgrades = new LinkedHashMap<>();
        List<String> skippedPinned = new ArrayList<>();
        Set<String> conflicting = new java.util.LinkedHashSet<>();
        for (UpgradeRecommendation r : report.recommendations()) {
            if (!reasons.test(r.reason())) continue;
            String coord = r.coordinate().groupId() + ":" + r.coordinate().artifactId();
            if (r.targetVersion() == null || r.targetVersion().equals(r.currentVersion())) continue;
            if (!TextReport.isActionable(r, directCoords.contains(coord))) continue;
            if (pinned.contains(coord)) {
                if (!skippedPinned.contains(coord)) skippedPinned.add(coord);
                continue;
            }
            if (conflicting.contains(coord)) continue;
            String existing = upgrades.get(coord);
            if (existing != null && !existing.equals(r.targetVersion())) {
                upgrades.remove(coord);
                conflicting.add(coord);
            } else {
                upgrades.put(coord, r.targetVersion());
            }
        }
        return new Selection(upgrades, skippedPinned, new ArrayList<>(conflicting));
    }

    @Override
    void execute(ReportExporter.Result result) throws MojoFailureException {
        Set<String> pinned = PinnedCoordinates.find(project.getBasedir().toPath(), excludes);
        Selection sel = select(result.report(), pinned, reasons());
        for (String coord : sel.skippedPinned()) {
            getLog().warn("Left " + coord + " alone: it is pinned. Name it with redkite:upgrade -Dredkite.upgrades=" + coord + " to change it.");
        }
        for (String coord : sel.conflicting()) {
            getLog().warn("Left " + coord + " alone: different modules are recommended different versions. Name one with redkite:upgrade.");
        }
        if (sel.upgrades().isEmpty()) {
            getLog().info("RedKite: nothing to upgrade.");
            return;
        }
        change(result, sel.upgrades(), true, Set.of(), Set.of());
    }
}
