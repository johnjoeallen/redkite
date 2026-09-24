package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.metadata.VulnerabilityProvider;
import java.util.ArrayList;
import java.util.List;

import static com.redkite.server.Versions.*;

/** Searches a vulnerable component's published versions for the nearest one that clears its CVEs: an upgrade, a downgrade, or the lowest remaining severity. */
final class CveFixFinder {
    private final VulnerabilityProvider vulnerabilities;

    CveFixFinder(VulnerabilityProvider vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    record CveFixResult(String target, RecommendationReason reason) {}

    /**
     * Resolves a fix for a vulnerable component's CVE(s): tries an upgrade first (the smallest
     * version at or above every finding's fixedVersion), then a downgrade (the largest version
     * below every finding's introducedVersion) if no upgrade clears all findings, then a bounded
     * best-effort search of nearby versions for the lowest residual severity. Returns null only
     * when the current version is already the best available.
     */
    /** Bounds how many candidates each tier will verify with a live vulnerability query, so
     *  a component with a genuinely unfixable CVE doesn't trigger unbounded OSV lookups. */
    private static final int MAX_FIX_VERIFY_CANDIDATES = 6;

    CveFixResult resolveCveFix(ScanComponent component, List<VulnerabilityFinding> compVulns,
            VersionMetadata versionMetadata, boolean allowMajorUpgrades) {
        String current = component.version();
        List<String> allVersions = versionMetadata.allStableVersions() == null
                ? List.of() : versionMetadata.allStableVersions();

        String upgradeTarget = smallestCleanUpgrade(component, current, compVulns, allVersions, allowMajorUpgrades);
        if (upgradeTarget != null) {
            return new CveFixResult(upgradeTarget, RecommendationReason.CVE_FIX);
        }

        String downgradeTarget = largestCleanDowngrade(component, current, compVulns, allVersions);
        if (downgradeTarget != null) {
            return new CveFixResult(downgradeTarget, RecommendationReason.CVE_FIX_DOWNGRADE);
        }

        String bestEffort = bestEffortLowestSeverity(component, current, allVersions);
        if (bestEffort != null) {
            return new CveFixResult(bestEffort, RecommendationReason.CVE_BEST_EFFORT);
        }
        return null;
    }

    /** Smallest available version that clears every finding's fixedVersion AND is itself
     *  verified free of any known vulnerability (a version can escape *this* CVE's range
     *  while carrying an entirely unrelated one of its own, especially further from current).
     *  Null if any finding has no known fixedVersion (open-ended — upgrading can never
     *  resolve it), or no verified-clean candidate is found within the search bound. */
    private String smallestCleanUpgrade(ScanComponent component, String current,
            List<VulnerabilityFinding> compVulns, List<String> allVersions, boolean allowMajorUpgrades) {
        String requiredFix = null;
        for (VulnerabilityFinding f : compVulns) {
            if (f.fixedVersion() == null || f.fixedVersion().isBlank()) return null;
            if (requiredFix == null || compareVersions(f.fixedVersion(), requiredFix) > 0) {
                requiredFix = f.fixedVersion();
            }
        }
        if (requiredFix == null) return null;
        List<String> candidates = new ArrayList<>();
        for (String v : allVersions) {
            if (isPreRelease(v) || compareVersions(v, requiredFix) < 0) continue;
            if (!allowMajorUpgrades && isMajorUpgrade(current, v)) continue;
            candidates.add(v);
        }
        candidates.sort(Versions::compareVersions); // ascending — verify the smallest (closest) first
        return firstVerifiedClean(component, candidates);
    }

    /** Largest available version strictly below every finding's introducedVersion — the
     *  newest release that predates the CVE being introduced — AND itself verified free of
     *  any known vulnerability (older releases are especially likely to carry their own,
     *  unrelated CVEs, so escaping this advisory's range is not sufficient on its own). Null
     *  if any finding has no known introducedVersion (affected since the dependency's first
     *  release — no downgrade can help), or no verified-clean candidate is found.*/
    private String largestCleanDowngrade(ScanComponent component, String current,
            List<VulnerabilityFinding> compVulns, List<String> allVersions) {
        String requiredBelow = null;
        for (VulnerabilityFinding f : compVulns) {
            if (f.introducedVersion() == null || f.introducedVersion().isBlank()) return null;
            if (requiredBelow == null || compareVersions(f.introducedVersion(), requiredBelow) < 0) {
                requiredBelow = f.introducedVersion();
            }
        }
        if (requiredBelow == null) return null;
        List<String> candidates = new ArrayList<>();
        for (String v : allVersions) {
            if (isPreRelease(v) || compareVersions(v, current) >= 0) continue;
            if (compareVersions(v, requiredBelow) >= 0) continue;
            candidates.add(v);
        }
        candidates.sort((a, b) -> compareVersions(b, a)); // descending — verify the largest (closest) first
        return firstVerifiedClean(component, candidates);
    }

    /** Walks candidates in the order given, querying live vulnerability data for each (cached
     *  thereafter) until one comes back with zero findings, bounded to avoid unbounded lookups
     *  against a component with no genuinely clean version nearby. */
    private String firstVerifiedClean(ScanComponent component, List<String> candidates) {
        int checked = 0;
        for (String candidate : candidates) {
            if (checked++ >= MAX_FIX_VERIFY_CANDIDATES) break;
            if (vulnerabilities.vulnerabilities(component.coordinate(), candidate).isEmpty()) {
                return candidate;
            }
        }
        return null;
    }

    /** Neither direction fully clears the CVE(s). Checks a bounded window of nearby versions
     *  on each side plus the true latest release (live OSV queries, cached thereafter).
     *  Upgrade candidates that only *tie* the current severity are still eligible — a CVE
     *  with no known fix at all (unbounded advisory range) affects every later release
     *  identically, and moving to a newer release is still preferable to staying put even
     *  without a severity win (it's likely to carry other, unrelated fixes). Downgrade
     *  candidates are held to a stricter bar: a downgrade must *strictly* beat the current
     *  severity to be worth suggesting — an older release with no CVE improvement is pure
     *  downside (missing later fixes) and should never be offered just because it ties.
     *  Within whichever direction wins, ties are broken toward the candidate closest to
     *  current. Returns null if nothing at least as good as current is found. */
    private String bestEffortLowestSeverity(ScanComponent component, String current, List<String> allVersions) {
        // Located by value, not by exact string match against allVersions — the current
        // version's string may not literally appear there (different qualifier formatting,
        // filtered out by the stable-version regex, cache staleness, etc.), and indexOf
        // silently aborting the whole search on a mismatch was the earlier bug: it looked
        // like no fix existed even when a strictly better nearby version clearly did.
        List<String> below = new ArrayList<>();
        List<String> above = new ArrayList<>();
        for (String v : allVersions) {
            if (isPreRelease(v)) continue;
            int cmp = compareVersions(v, current);
            if (cmp < 0) below.add(v);
            else if (cmp > 0) above.add(v);
        }
        below.sort((a, b) -> compareVersions(b, a)); // descending — closest below first
        above.sort(Versions::compareVersions); // ascending — closest above first
        List<String> aboveWindow = new ArrayList<>(above.subList(0, Math.min(MAX_FIX_VERIFY_CANDIDATES, above.size())));
        // Always check the true latest release too, even if it fell outside the window above —
        // it's the one version most likely to have picked up an eventual fix.
        if (!above.isEmpty()) {
            String latest = above.get(above.size() - 1);
            if (!aboveWindow.contains(latest)) aboveWindow.add(latest);
        }
        List<String> belowWindow = below.subList(0, Math.min(3, below.size()));

        AdvisorySeverity currentSeverity = AdvisoryClassifier.highest(
                vulnerabilities.vulnerabilities(component.coordinate(), current));
        String best = null;
        AdvisorySeverity bestSeverity = null;

        // Upgrades first (closest-first) — ties with current severity are acceptable.
        for (String candidate : aboveWindow) {
            AdvisorySeverity candidateSeverity = AdvisoryClassifier.highest(
                    vulnerabilities.vulnerabilities(component.coordinate(), candidate));
            if (candidateSeverity.ordinal() > currentSeverity.ordinal()) continue; // never regress
            if (bestSeverity == null || candidateSeverity.ordinal() < bestSeverity.ordinal()) {
                best = candidate;
                bestSeverity = candidateSeverity;
            }
        }
        // Downgrades only count if they strictly improve on both current and whatever
        // upgrade was already found — no free pass for ties in this direction.
        for (String candidate : belowWindow) {
            AdvisorySeverity candidateSeverity = AdvisoryClassifier.highest(
                    vulnerabilities.vulnerabilities(component.coordinate(), candidate));
            if (candidateSeverity.ordinal() >= currentSeverity.ordinal()) continue;
            if (bestSeverity == null || candidateSeverity.ordinal() < bestSeverity.ordinal()) {
                best = candidate;
                bestSeverity = candidateSeverity;
            }
        }
        return best;
    }
}
