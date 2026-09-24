package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.core.service.LicenseNormalizer;
import com.redkite.core.service.LicensePermissiveness;
import com.redkite.metadata.VulnerabilityProvider;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.redkite.server.Json.*;
import static com.redkite.server.Html.*;
import static com.redkite.server.PomXml.*;
import static com.redkite.server.Versions.*;
import static com.redkite.server.ScanPageRenderer.*;

/** One component's card on the analysis page: status, findings, recommendation and the version selector. */
final class ComponentCardRenderer {
    private final VulnerabilityProvider vulnerabilities;

    ComponentCardRenderer(VulnerabilityProvider vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    /**
     * The version RedKite recommends for a TRANSITIVE component, which deliberately does not
     * follow the same "latest compatible" logic as direct dependencies — a transitive dependency
     * was never chosen by the project, so recommending a move for it needs a concrete reason:
     * <ol>
     *   <li>An existing dependencyManagement entry (RedKite-pinned or plain project-declared)
     *       already governs this artifact — respect it as-is, whatever its version.
     *   <li>Otherwise, an active enforcer convergence conflict for this artifact — recommend the
     *       highest version already present among the conflict's resolved/conflicting versions
     *       (never a fresh "latest on Maven Central" lookup, which could cross a release line
     *       nothing in the tree actually requires).
     *   <li>Otherwise, a fixable CVE on this component — recommend the fix's target version
     *       (upgrade, downgrade, or best-effort, whichever direction the fix actually moves). A
     *       known vulnerability with a known fix is exactly the "concrete reason to move" this
     *       method otherwise withholds — unlike a bare "newer version exists" signal, it isn't
     *       optional busywork.
     *   <li>Otherwise, the current version — i.e. no upgrade is recommended at all. A transitive
     *       dependency with no conflict, no existing pin, and no CVE fix has nothing forcing it to
     *       move, so "newer version available" alone isn't reason enough to override it.
     * </ol>
     */
    String transitiveRecommendedVersion(ComponentView view, String rootPomContent) {
        ScanComponent comp = view.component();
        String pinned = extractDepMgmtVersion(rootPomContent, comp.coordinate().groupId(), comp.coordinate().artifactId());
        if (pinned != null && !pinned.isBlank()) {
            return pinned;
        }
        TransitiveConflictFinding finding = view.convergenceFinding();
        if (finding != null) {
            String winner = finding.resolvedVersion() != null ? finding.resolvedVersion() : "";
            for (String v : finding.conflictingVersions()) {
                if (compareVersionsSemantic(v, winner) > 0) winner = v;
            }
            if (!winner.isBlank()) return winner;
        }
        if (hasFixableCve(view) && view.recommendation() != null
                && view.recommendation().targetVersion() != null && !view.recommendation().targetVersion().isBlank()) {
            return view.recommendation().targetVersion();
        }
        return comp.version();
    }

    private static String scopeLabel(DependencyScope scope) {
        if (scope == null) return "unknown";
        return switch (scope) {
            case PLUGIN_BUILD -> "plugin build";
            default -> scope.name().toLowerCase();
        };
    }

    /** A CVE resolved by upgrading — tier 1 (RecommendationReason.CVE_FIX), or tier 3 best-effort
     *  when its suggested target happens to be above the current version. */
    boolean isCveFixByUpgrade(ComponentView view) {
        if (!view.status().hasVulnerability() || view.recommendation() == null) return false;
        RecommendationReason reason = view.recommendation().reason();
        if (reason == RecommendationReason.CVE_FIX) return true;
        return reason == RecommendationReason.CVE_BEST_EFFORT
                && compareVersionsSemantic(view.recommendation().targetVersion(), view.component().version()) > 0;
    }

    /** A CVE with no upgrade fix, resolved by downgrading — tier 2 (CVE_FIX_DOWNGRADE), or tier 3
     *  best-effort when its suggested target happens to be below the current version. */
    boolean isCveFixByDowngrade(ComponentView view) {
        if (!view.status().hasVulnerability() || view.recommendation() == null) return false;
        RecommendationReason reason = view.recommendation().reason();
        if (reason == RecommendationReason.CVE_FIX_DOWNGRADE) return true;
        return reason == RecommendationReason.CVE_BEST_EFFORT
                && compareVersionsSemantic(view.recommendation().targetVersion(), view.component().version()) < 0;
    }

    /** Whether a vulnerability on this component has any recommended target version — a full fix
     *  (upgrade/downgrade) or a best-effort suggestion, which is folded into whichever of those
     *  two directions its target version actually moves. */
    private boolean hasFixableCve(ComponentView view) {
        return isCveFixByUpgrade(view) || isCveFixByDowngrade(view);
    }

    /** A CVE with no recommendation at all — no upgrade, no downgrade, and no best-effort
     *  candidate beat the current version's own severity. Genuinely nothing to suggest. */
    boolean isCveNofix(ComponentView view) {
        return view.status().hasVulnerability() && view.recommendation() == null;
    }

    /** Matches the "Update recommended" reason counted in RemediationClassifier.summarize() —
     *  the single source of truth for both the "Update recommended" banner chip and the
     *  Outdated filter chip, so the two numbers never diverge like they did when a tab computed
     *  its own definition client-side. */
    private static boolean isUpgradeRecommendedOnly(RemediationStatus status) {
        return status.hasUpgradeRecommendation() && !status.hasVulnerability() && !status.isSnapshot();
    }

    /** {@link #isUpgradeRecommendedOnly}, further narrowed to cases where a target version is
     *  actually offered — matching renderComponentCard's own effectiveRecommendation/upgradeOnly
     *  logic. A transitive dependency's raw recommendation is withheld (see
     *  transitiveRecommendedVersion) when there's no concrete reason to move it, and its version
     *  selector defaults to "No change" accordingly; counting it toward "Outdated" anyway would
     *  advertise an update the UI itself doesn't actually offer. */
    boolean isEffectivelyOutdatedOnly(ComponentView view, String rootPomContent) {
        if (!isUpgradeRecommendedOnly(view.status())) return false;
        ScanComponent comp = view.component();
        if (comp.direct()) return true;
        String transitiveTarget = transitiveRecommendedVersion(view, rootPomContent);
        return transitiveTarget != null && !transitiveTarget.equals(comp.version());
    }

    /** Whether a card is treated as "clean" for tab-filtering/counting purposes — the single
     *  source of truth shared by the banner counts and the per-card rendering, so the CVE and
     *  Clean tabs can never double-count the same card.
     *
     *  <p>Mostly matches {@link RemediationStatus#needsRemediation()} (the same definition
     *  {@link RemediationClassifier#summarize} uses for the banner's "need remediation"/"clean"
     *  counts) plus an active convergence finding — with one deliberate exception: a transitive
     *  dependency whose ONLY reason is a plain, non-CVE update recommendation is still treated as
     *  clean. {@link #transitiveRecommendedVersion} never offers a target for that case (no pin, no
     *  conflict, no CVE — nothing forcing the move), so it isn't something RedKite actually acts
     *  on; counting it as a finding is pure noise a user can't do anything about from this list. A
     *  real vulnerability on a transitive dependency — fixable or not — a snapshot, or stale
     *  metadata still counts as a finding regardless of direct/transitive; only "a newer version
     *  happens to exist, unprompted by anything else" is suppressed. */
    boolean isCardClean(ComponentView view) {
        ScanComponent comp = view.component();
        RemediationStatus status = view.status();
        if (view.convergenceFinding() != null) return false;
        if (!status.needsRemediation()) return true;
        boolean onlyPlainRecommendation = !comp.direct() && !status.hasVulnerability()
                && !status.isSnapshot() && !status.hasStaleMetadata();
        return onlyPlainRecommendation;
    }

    String renderComponentCard(ComponentView view, String module, boolean hasChildren, Map<String, List<VulnerabilityFinding>> vulnsByKey, Set<String> pinnedCoords, String rootPomContent, Map<String, Integer> licenseRanks) {
        ScanComponent comp = view.component();
        RemediationStatus status = view.status();
        boolean hasFixableCve = hasFixableCve(view);
        String coordStr = comp.coordinate().groupId() + ":" + comp.coordinate().artifactId();
        boolean pinned = pinnedCoords.contains(coordStr);
        // For transitive components only: override what "recommended" means (see
        // transitiveRecommendedVersion doc) — null when it resolves to a no-op (== current
        // version), so display code can treat "nothing to recommend" and "no recommendation
        // object" identically.
        String transitiveTarget = comp.direct() ? null
                : transitiveRecommendedVersion(view, rootPomContent);
        boolean transitiveHasTarget = transitiveTarget != null && !transitiveTarget.equals(comp.version());
        UpgradeRecommendation effectiveRecommendation = comp.direct() ? view.recommendation()
                : (transitiveHasTarget
                    ? new UpgradeRecommendation(comp.id(), comp.coordinate(), comp.version(), transitiveTarget,
                        view.recommendation() != null ? view.recommendation().reason() : RecommendationReason.MINOR_AVAILABLE,
                        view.recommendation() != null ? view.recommendation().riskLevel() : RiskLevel.ELEVATED,
                        view.recommendation() != null ? view.recommendation().confidence() : RecommendationConfidence.HIGH,
                        view.recommendation() != null ? view.recommendation().fixedCves() : List.of(),
                        List.of(comp.id()))
                    : null);

        StringBuilder html = new StringBuilder();
        String kind = comp.snapshot() ? "snapshot" : comp.direct() ? "declared" : "transitive";
        // Matches effectiveRecommendation above: a transitive dependency with no concrete reason
        // to move has its recommendation withheld there (the version selector defaults to "No
        // change" for it), so it must be withheld here too — otherwise the Outdated chip's count
        // and card-matching would include cards with nothing actually shown as available to apply.
        boolean upgradeOnly = isUpgradeRecommendedOnly(status) && (comp.direct() || transitiveHasTarget);
        boolean actionableConvergence = view.convergenceFinding() != null;
        String conflictJson = actionableConvergence ? buildConflictJson(view.convergenceFinding()) : "";
        boolean dataClean = isCardClean(view);
        // Three-way CVE fix status. isCardClean() guarantees clean and any of these three stay
        // mutually exclusive, and every vulnerable component falls into exactly one of them.
        boolean dataCveUpgrade = isCveFixByUpgrade(view);
        boolean dataCveDowngrade = isCveFixByDowngrade(view);
        boolean dataCveNofix = isCveNofix(view);
        // Origin (direct/transitive) purely from comp.direct() — independent of snapshot status,
        // unlike "kind" below, which conflates the two. A snapshot dependency is still either
        // direct or transitive for filtering purposes; "kind" stays as-is since badge/label text
        // elsewhere still wants snapshot called out as its own thing.
        String origin = comp.direct() ? "direct" : "transitive";
        // Matches the panel's own counting: a dependency is filterable under the one license
        // it's actually counted under (its most permissive, when it declares more than one), not
        // every license it happens to also offer — otherwise clicking a chip could surface more
        // dependencies than the chip's own displayed count.
        String licensesJson = view.licenses().isEmpty() ? "[]"
                : "[" + jsonStr(LicenseNormalizer.canonicalize(representativeLicense(view.licenses(), licenseRanks))) + "]";
        // Identifies the underlying dependency (not the module occurrence) — the same dependency
        // can produce a card per module it's declared/resolved in, but the Findings/Clean/All tab
        // counts dedupe by this key (see updateRemChipCounts in scripts.js) so they stay consistent
        // with the banner's per-dependency counts instead of counting one card per module.
        String depKey = coordStr + "@" + comp.version();
        html.append("<div class=\"rem-card").append(dataClean ? " clean" : "").append("\" data-clean=\"").append(dataClean)
                .append("\" data-module=\"").append(escape(module))
                .append("\" data-kind=\"").append(kind)
                .append("\" data-origin=\"").append(origin)
                .append("\" data-cveupgrade=\"").append(dataCveUpgrade)
                .append("\" data-cvedowngrade=\"").append(dataCveDowngrade)
                .append("\" data-cvenofix=\"").append(dataCveNofix)
                .append("\" data-upgradeonly=\"").append(upgradeOnly)
                .append("\" data-hasconflict=\"").append(actionableConvergence)
                .append("\" data-coord=\"").append(escape(coordStr))
                .append("\" data-dep-key=\"").append(escape(depKey))
                .append("\" data-pinned=\"").append(pinned)
                .append("\" data-pinned-initial=\"").append(pinned)
                .append("\" data-licenses='").append(licensesJson).append("'")
                .append(" data-comp-id=\"").append(comp.id());
        if (actionableConvergence) {
            html.append("\" data-conflict='").append(conflictJson).append("'>");
        } else {
            html.append("\">");
        }

        // Header: coordinate + badges
        html.append("<div class=\"rem-header\">");
        html.append("<span class=\"rem-title\">").append(escape(coordStr)).append("</span>");
        html.append("<div class=\"rem-badges\">");
        html.append(severityBadgeHtml(status.highestSeverity(), dataClean));
        String kindClass = comp.snapshot() ? "warn" : comp.direct() ? "success" : "neutral";
        String kindLabel = comp.snapshot() ? "snapshot" : comp.direct() ? "declared" : "transitive";
        html.append("<span class=\"badge ").append(kindClass).append("\">").append(kindLabel).append("</span>");
        html.append("<span class=\"badge neutral\">").append(scopeLabel(comp.scope())).append("</span>");
        if (view.licenses().isEmpty()) {
            html.append("<span class=\"badge license-badge license-none\">No License</span>");
        } else {
            // A license that LicenseNormalizer recognises is shown in its canonicalized form (e.g.
            // "ASL-2.0" rather than "The Apache Software License, Version 2.0") so the common cases
            // read consistently across every card; the original declared string is never lost, just
            // moved into the tooltip. An unrecognised license passes through unchanged either way.
            // The most permissive declared license (per the configured rank table) gets a distinct
            // highlight — even when there's only one, so a quick visual scan across many cards shows
            // which dependencies have a known-permissive license at all, not just which ones had a
            // choice between several. A license with no configured rank is never highlighted.
            String mostPermissive = LicensePermissiveness.mostPermissive(view.licenses(), licenseRanks);
            for (String license : view.licenses()) {
                String canonical = LicenseNormalizer.canonicalize(license);
                boolean isMostPermissive = license.equals(mostPermissive);
                String cls = isMostPermissive ? "badge license-badge license-most-permissive" : "badge license-badge";
                List<String> notes = new ArrayList<>();
                if (!canonical.equals(license)) notes.add("Declared as: " + license);
                if (isMostPermissive) notes.add("Most permissive of this dependency's declared licenses");
                String title = notes.isEmpty() ? "" : " title=\"" + escape(String.join(" — ", notes)) + "\"";
                html.append("<span class=\"").append(cls).append("\"").append(title).append(">").append(escape(canonical)).append("</span>");
            }
        }
        if (actionableConvergence) {
            html.append("<span class=\"badge conflict-badge\">&#9651; Conflict</span>");
        }
        html.append("</div>");
        html.append("</div>");

        // Version info
        html.append("<div class=\"rem-meta\">");
        html.append("<span>Current: <strong>").append(escape(comp.version() != null ? comp.version() : "unknown")).append("</strong></span>");
        if (effectiveRecommendation != null && !status.isSnapshot()) {
            String recLabel = switch (effectiveRecommendation.reason()) {
                case CVE_FIX_DOWNGRADE -> "Downgrade to";
                case CVE_BEST_EFFORT -> "Best available";
                default -> "Recommended";
            };
            html.append("<span>&rarr; ").append(recLabel).append(": <strong>").append(escape(effectiveRecommendation.targetVersion())).append("</strong></span>");
        }
        if (view.versionMetadata() != null && view.versionMetadata().latestVersion() != null
                && !view.versionMetadata().latestVersion().isBlank()
                && !"unknown".equalsIgnoreCase(view.versionMetadata().latestVersion())) {
            html.append("<span class=\"muted\">(Latest: ").append(escape(view.versionMetadata().latestVersion())).append(")</span>");
        }
        html.append("</div>");

        // CVE identifiers
        if (status.hasVulnerability() && !view.findings().isEmpty()) {
            List<String> allCves = new ArrayList<>();
            for (VulnerabilityFinding f : view.findings()) {
                if (f.cves() != null) allCves.addAll(f.cves());
            }
            if (!allCves.isEmpty()) {
                html.append("<div class=\"rem-cves\">").append(escape(String.join(", ", allCves))).append("</div>");
            }
        }

        // CVEs found among this dependency's own transitive dependencies, not its own findings —
        // lets a clean direct dependency still surface that something it pulls in is vulnerable.
        html.append(childVulnerabilitiesHtml(view.childVulnerabilities()));

        // Remediation reason chips
        List<String> otherReasons = status.reasons().stream()
                .filter(r -> !"Update recommended".equals(r)).toList();
        boolean showUpgradeBtn = effectiveRecommendation != null && !status.isSnapshot();
        boolean showNoUpgradeChip = !comp.direct() && !status.isSnapshot()
                && effectiveRecommendation == null && view.versionMetadata() != null;
        if (!otherReasons.isEmpty() || showUpgradeBtn || showNoUpgradeChip) {
            html.append("<div class=\"rem-reasons\">");
            for (String reason : otherReasons) {
                html.append("<span class=\"reason-chip\">").append(escape(reason)).append("</span>");
            }
            if (showUpgradeBtn) {
                RecommendationReason recReason = effectiveRecommendation.reason();
                String verb = switch (recReason) {
                    case CVE_FIX_DOWNGRADE -> "Downgrade to";
                    case CVE_BEST_EFFORT -> "Best available:";
                    default -> "Upgrade to";
                };
                if (comp.direct()) {
                    html.append("<button class=\"reason-chip reason-chip-btn\" type=\"button\" onclick=\"applyUpgrade(")
                        .append(comp.id()).append(",'").append(escape(effectiveRecommendation.targetVersion())).append("',this)\">")
                        .append(verb).append(" ").append(escape(effectiveRecommendation.targetVersion())).append("</button>");
                } else {
                    String transitiveChip = switch (recReason) {
                        case CVE_FIX_DOWNGRADE -> "Downgrade available";
                        case CVE_BEST_EFFORT -> "Lower-severity version available";
                        default -> view.canUpgradeViaDirect() ? "Update available" : "Major update available";
                    };
                    html.append("<span class=\"reason-chip\">").append(transitiveChip).append("</span>");
                }
            } else if (showNoUpgradeChip) {
                // A newer version can genuinely exist even when RedKite isn't offering to apply
                // it — a transitive dependency only gets an actionable recommendation for a
                // concrete reason (a pin, a conflict, a fixable CVE; see
                // transitiveRecommendedVersion), never merely because something newer was
                // published. "No upgrade available" must be reserved for when that's actually
                // true, not used as a catch-all for "not offering one."
                String latestVersion = view.versionMetadata() != null ? view.versionMetadata().latestVersion() : null;
                boolean newerVersionExists = latestVersion != null && !latestVersion.isBlank()
                        && !"unknown".equalsIgnoreCase(latestVersion)
                        && compareVersionsSemantic(latestVersion, comp.version()) > 0;
                String noFixChip;
                if (status.hasVulnerability()) {
                    noFixChip = "No fix available";
                } else if (newerVersionExists) {
                    noFixChip = sameMajor(comp.version(), latestVersion) ? "Update available" : "Major update available";
                } else {
                    noFixChip = "No upgrade available";
                }
                html.append("<span class=\"reason-chip\">").append(noFixChip).append("</span>");
            }
            html.append("</div>");
        }

        // Show version selector for: direct deps with metadata or conflict, transitive conflict deps,
        // and transitive deps with a fixable CVE (upgrade, downgrade, or best-effort — hasFixableCve
        // covers all three) or a plain upgrade recommendation that transitiveRecommendedVersion
        // actually offers a target for (transitiveHasTarget) — in every case there's a concrete
        // target version to apply. isUpgradeRecommendedOnly(status) alone isn't enough: it's true
        // whenever Pass 4 created ANY plain recommendation, including for a transitive dependency
        // with no concrete reason to move (no pin, no conflict, no CVE) — transitiveRecommendedVersion
        // deliberately withholds a target for exactly that case, so a selector gated on
        // isUpgradeRecommendedOnly alone would render with nothing to select but "No change."
        boolean showVersionSelector = view.convergenceFinding() != null
                || (comp.direct() && view.versionMetadata() != null)
                || (!comp.direct() && (hasFixableCve || (isUpgradeRecommendedOnly(status) && transitiveHasTarget))
                    && view.versionMetadata() != null);
        // A pinned component that's since become fully clean (e.g. already at the version it was
        // pinned to, with nothing left to recommend) would otherwise lose its version selector —
        // and with it, the only way to reach the Pin checkbox and un-pin it. Keep the actions row
        // (checkbox only, no dropdown) for that case.
        if (showVersionSelector || (pinned && !actionableConvergence)) {
            html.append("<div class=\"rem-actions\">");
            if (showVersionSelector && comp.direct()) {
                String selectorId = "view_" + comp.id();
                List<String> directConflictVersions = view.convergenceFinding() != null
                        ? view.convergenceFinding().conflictingVersions() : List.of();
                String selectedVersion = view.convergenceFinding() != null
                        ? conflictDefaultVersion(view.convergenceFinding(), comp, view.findings(), vulnsByKey, view.versionMetadata())
                        : (view.recommendation() != null ? view.recommendation().targetVersion() : comp.version());
                if (view.convergenceFinding() != null && view.recommendation() != null
                        && view.recommendation().targetVersion() != null
                        && compareVersionsSemantic(view.recommendation().targetVersion(), selectedVersion != null ? selectedVersion : "") > 0) {
                    selectedVersion = view.recommendation().targetVersion();
                }
                html.append(renderVersionSelect(selectorId, comp.coordinate(), comp.version(), selectedVersion,
                        view.versionMetadata(), view.recommendation(), false, directConflictVersions,
                        view.convergenceFinding() != null));
            } else if (showVersionSelector && (view.versionMetadata() != null || view.convergenceFinding() != null)) {
                // Transitive: the selector's default is exactly transitiveTarget's 3-tier result
                // (existing pin > highest version already in the conflict > current/no-op) — never
                // conflictDefaultVersion's CVE-driven walk beyond what's already in the tree, and
                // never the scan-time recommendation's own target.
                String selectorId = "view_" + comp.id();
                List<String> conflictVersions = view.convergenceFinding() != null
                        ? view.convergenceFinding().conflictingVersions()
                        : List.of();
                String selectedVersion = transitiveTarget != null ? transitiveTarget : comp.version();
                html.append(renderVersionSelect(selectorId, comp.coordinate(), comp.version(), selectedVersion,
                        view.versionMetadata(), effectiveRecommendation, false,
                        conflictVersions, true));
            }
            if (!actionableConvergence) {
                html.append("<label class=\"pin-toggle\" title=\"Keep this dependency at its current/selected version through bulk upgrades\">")
                        .append("<input type=\"checkbox\" class=\"pin-chk\" data-comp-id=\"").append(comp.id())
                        .append("\"").append(pinned ? " checked" : "")
                        .append(" onchange=\"onPinToggle(this)\"> Pin</label>");
            }
            html.append("</div>");
        }

        if (hasChildren) {
            html.append("<div class=\"card-expand-row\">");
            html.append("<button class=\"card-expand-btn\" type=\"button\" data-comp-id=\"").append(comp.id())
                .append("\" onclick=\"toggleTree(this)\">+</button>");
            html.append("</div>");
            html.append("<div class=\"dep-tree-panel\" style=\"display:none\"></div>");
        }

        html.append("</div>");
        return html.toString();
    }

    private String severityBadgeHtml(AdvisorySeverity severity, boolean clean) {
        if (clean) {
            return "<span class=\"sev-badge sev-none\">&#10003; Clean</span>";
        }
        // A component with no CVE (severity NONE) can still need remediation for a non-CVE reason
        // (a plain update recommendation, stale metadata, a declared inline version, ...) — showing
        // "Clean" here regardless used to hide that from the badge entirely.
        if (severity == AdvisorySeverity.NONE) {
            return "<span class=\"sev-badge sev-recommended\">&#8593; Update</span>";
        }
        String cls = "sev-" + severity.name().toLowerCase();
        return "<span class=\"sev-badge " + cls + "\">" + escape(severity.icon()) + " " + escape(severity.label()) + "</span>";
    }

    /** One chip per non-zero severity found among this dependency's own transitive children —
     *  deduped per {@link ChildVulnerabilityAggregator}, so a diamond-shaped child only counts
     *  once even though it's rendered here from the parent's point of view. */
    private String childVulnerabilitiesHtml(ChildVulnerabilityCounts counts) {
        if (counts == null || counts.total() == 0) return "";
        StringBuilder html = new StringBuilder();
        html.append("<div class=\"rem-child-vulns\">");
        html.append("<span class=\"muted\" style=\"font-size:.78rem\">In dependencies:</span>");
        if (counts.criticalCount() > 0) html.append("<span class=\"sev-chip sev-critical\"").append(childSevChipTitle(counts, AdvisorySeverity.CRITICAL)).append(">&#9762; ").append(counts.criticalCount()).append("</span>");
        if (counts.highCount() > 0) html.append("<span class=\"sev-chip sev-high\"").append(childSevChipTitle(counts, AdvisorySeverity.HIGH)).append(">&#9760; ").append(counts.highCount()).append("</span>");
        if (counts.mediumCount() > 0) html.append("<span class=\"sev-chip sev-medium\"").append(childSevChipTitle(counts, AdvisorySeverity.MEDIUM)).append(">&#9888; ").append(counts.mediumCount()).append("</span>");
        if (counts.lowCount() > 0) html.append("<span class=\"sev-chip sev-low\"").append(childSevChipTitle(counts, AdvisorySeverity.LOW)).append(">&#x2139; ").append(counts.lowCount()).append("</span>");
        if (counts.unknownCount() > 0) html.append("<span class=\"sev-chip sev-unknown\"").append(childSevChipTitle(counts, AdvisorySeverity.UNKNOWN)).append(">? ").append(counts.unknownCount()).append("</span>");
        html.append("</div>");
        return html.toString();
    }

    /** Mirrors {@link ScanPageRenderer#sevChipTitle(ReportSummary, AdvisorySeverity)}: the chip itself only shows
     *  a count, so the tooltip is what actually says which child dependency (and advisory) that
     *  severity's count refers to. */
    private static String childSevChipTitle(ChildVulnerabilityCounts counts, AdvisorySeverity severity) {
        List<String> children = counts.childrenBySeverity().getOrDefault(severity, List.of());
        if (children.isEmpty()) return "";
        return " title=\"" + escape(severity.label() + " in:\n" + String.join("\n", children)) + "\"";
    }

    // ---- Stage 8: Compact version selector dropdown ----

    private String renderVersionSelect(String selectorId, ComponentCoordinate coordinate, String currentVersion,
            String selectedVersion, MetadataResult versionMetadata, UpgradeRecommendation recommendation,
            boolean includeNameAttr, List<String> conflictVersions,
            boolean includeCurrentOption) {
        List<String> choices = versionChoices(versionMetadata, recommendation);
        // Build deduplicated ordered set: recommended first, then choices, then latest
        LinkedHashSet<String> ordered = new LinkedHashSet<>();
        if (includeCurrentOption && currentVersion != null && !currentVersion.isBlank()) {
            ordered.add(currentVersion);
        }
        if (recommendation != null && recommendation.targetVersion() != null && !recommendation.targetVersion().isBlank()) {
            ordered.add(recommendation.targetVersion());
        }
        ordered.addAll(choices);
        if (conflictVersions != null) {
            ordered.addAll(conflictVersions);
            // Guarantee the conflict-default version is always selectable
            if (!conflictVersions.isEmpty() && selectedVersion != null && !selectedVersion.isBlank()) {
                ordered.add(selectedVersion);
            }
        }
        if (versionMetadata != null && versionMetadata.latestVersion() != null
                && !versionMetadata.latestVersion().isBlank()
                && !"unknown".equalsIgnoreCase(versionMetadata.latestVersion())
                && !isPreRelease(versionMetadata.latestVersion())) {
            ordered.add(versionMetadata.latestVersion());
        }

        if (ordered.isEmpty()) {
            return "<span class=\"version-note muted\">No upgrade candidates</span>";
        }

        // Sort versions in semantic ascending order before rendering
        List<String> sortedVersions = new ArrayList<>(ordered);
        sortedVersions.sort(Versions::compareVersionsSemantic);

        StringBuilder html = new StringBuilder();
        html.append("<div class=\"version-sel-wrap\">");

        // Show current version chip
        if (currentVersion != null && !currentVersion.isBlank()) {
            AdvisorySeverity currentSeverity = severityForVersion(coordinate, currentVersion);
            boolean currentHasCve = currentSeverity != AdvisorySeverity.NONE;
            html.append("<span class=\"version-current").append(currentHasCve ? " cve" : "").append("\">");
            html.append(escape(currentVersion));
            if (currentHasCve) {
                html.append("<span class=\"pill sev-").append(currentSeverity.name().toLowerCase())
                        .append("\">").append(escape(currentSeverity.label())).append("</span>");
            }
            html.append("</span>");
            html.append("<span style=\"color:var(--muted)\">&#8594;</span>");
        }

        String recommendedVersion = recommendation != null ? recommendation.targetVersion() : null;
        String latestVersion = versionMetadata != null ? versionMetadata.latestVersion() : null;
        String latestSameMajor = versionMetadata != null ? versionMetadata.latestSameMajorVersion() : null;
        java.util.Set<String> conflictSet = conflictVersions == null ? java.util.Set.of() : new java.util.LinkedHashSet<>(conflictVersions);

        // Explicit selectedVersion (e.g. conflict default) takes priority over the recommendation.
        // For conflict cards, allow the current version to be selected (current may already be the resolution target).
        boolean hasConflict = conflictVersions != null && !conflictVersions.isEmpty();
        boolean hasExplicitSelection = selectedVersion != null && !selectedVersion.isBlank()
                && (hasConflict || !selectedVersion.equals(currentVersion)) && ordered.contains(selectedVersion);
        boolean hasPreSelection = hasExplicitSelection
                || (recommendedVersion != null && !recommendedVersion.isBlank()
                    && !recommendedVersion.equals(currentVersion) && ordered.contains(recommendedVersion));
        String preSelectedVersion = hasExplicitSelection ? selectedVersion : recommendedVersion;
        String nameAttr = includeNameAttr ? " name=\"" + escape(selectorId) + "\"" : "";
        html.append("<select class=\"version-sel\" id=\"").append(escape(selectorId)).append("\"").append(nameAttr)
                .append(" onchange=\"onVersionSelect(this)\"");
        if (recommendedVersion != null && !recommendedVersion.isBlank()) {
            html.append(" data-recommended=\"").append(escape(recommendedVersion)).append("\"");
        }
        html.append(">");
        // Blank placeholder shown only when nothing is pre-selected
        html.append("<option value=\"\"").append(hasPreSelection ? "" : " selected").append(">No change</option>");
        for (String version : sortedVersions) {
            AdvisorySeverity severity = severityForVersion(coordinate, version);
            String label = buildVersionOptionLabel(version, recommendedVersion, latestVersion, latestSameMajor,
                    recommendation != null ? recommendation.reason() : null, severity, currentVersion,
                    conflictSet.contains(version), includeCurrentOption && version.equals(currentVersion));
            html.append("<option value=\"").append(escape(version)).append("\"")
                    .append(hasPreSelection && version.equals(preSelectedVersion) ? " selected" : "")
                    .append(">").append(escape(label)).append("</option>");
        }
        html.append("</select>");
        html.append("</div>");
        return html.toString();
    }

    private String buildVersionOptionLabel(String version, String recommendedVersion, String latestVersion,
            String latestSameMajor, RecommendationReason reason, AdvisorySeverity severity, String currentVersion,
            boolean isConflictVersion, boolean isCurrentVersion) {
        List<String> tags = new ArrayList<>();
        if (isCurrentVersion) tags.add("current");
        if (version.equals(recommendedVersion)) {
            tags.add("recommended");
            if (reason == RecommendationReason.CVE_FIX || reason == RecommendationReason.CVE_FIX_DOWNGRADE) {
                tags.add("fixes CVE");
            } else if (reason == RecommendationReason.CVE_BEST_EFFORT) {
                tags.add("lowest known severity");
            }
        }
        if (version.equals(latestVersion)) tags.add("latest");
        if (version.equals(latestSameMajor) && !version.equals(latestVersion)) {
            tags.add(sameMajorMinor(version, currentVersion) ? "latest same minor" : "latest same major");
        }
        // Show the actual severity level rather than a generic "vulnerable" flag, so a Low CVE
        // doesn't read the same as a Critical one when comparing candidates in the dropdown.
        if (severity != null && severity != AdvisorySeverity.NONE) {
            tags.add(severity.label().toLowerCase() + " severity");
        }
        if (isConflictVersion) tags.add("conflict");
        if (version.contains("-SNAPSHOT") || version.contains("-alpha") || version.contains("-beta") || version.contains("-rc")) {
            tags.add("pre-release");
        }
        return tags.isEmpty() ? version : version + " — " + String.join(", ", tags);
    }

    private String conflictDefaultVersion(TransitiveConflictFinding f, ScanComponent comp,
            List<VulnerabilityFinding> vulnFindings, Map<String, List<VulnerabilityFinding>> vulnsByKey) {
        return conflictDefaultVersion(f, comp, vulnFindings, vulnsByKey, null);
    }

    private String conflictDefaultVersion(TransitiveConflictFinding f, ScanComponent comp,
            List<VulnerabilityFinding> vulnFindings, Map<String, List<VulnerabilityFinding>> vulnsByKey,
            MetadataResult versionMeta) {
        String newest = f.resolvedVersion() != null ? f.resolvedVersion() : "";
        for (String v : f.conflictingVersions()) {
            if (compareVersionsSemantic(v, newest) > 0) newest = v;
        }
        if (comp.version() != null && compareVersionsSemantic(comp.version(), newest) > 0) {
            newest = comp.version();
        }
        if (comp.coordinate() == null) return newest.isBlank() ? null : newest;

        // Collect all known vulnerability findings for this artifact across all affected versions.
        // This lets us do range-based checking: if affectedVersion <= candidate < fixedVersion,
        // the candidate is still vulnerable even if we have no finding keyed exactly to it.
        String ga = comp.coordinate().groupId() + ":" + comp.coordinate().artifactId();
        List<VulnerabilityFinding> allArtifactVulns = new ArrayList<>();
        if (vulnFindings != null) allArtifactVulns.addAll(vulnFindings);
        if (vulnsByKey != null) {
            String prefix = ga + "@";
            for (Map.Entry<String, List<VulnerabilityFinding>> e : vulnsByKey.entrySet()) {
                if (e.getKey().startsWith(prefix)) {
                    for (VulnerabilityFinding vf : e.getValue()) {
                        if (vf.coordinate() != null
                                && comp.coordinate().groupId().equals(vf.coordinate().groupId())
                                && comp.coordinate().artifactId().equals(vf.coordinate().artifactId())) {
                            allArtifactVulns.add(vf);
                        }
                    }
                }
            }
        }

        // Walk up through available versions (same major) until finding a clean one.
        List<String> upgradePath = (versionMeta != null && versionMeta.upgradePathVersions() != null)
                ? versionMeta.upgradePathVersions() : List.of();
        String candidate = newest;
        int maxPasses = upgradePath.size() + allArtifactVulns.size() + 2;
        for (int pass = 0; pass < maxPasses; pass++) {
            // Find the lowest fixedVersion that covers the candidate (affectedVersion <= candidate < fixedVersion, same major)
            String fixVersion = null;
            for (VulnerabilityFinding finding : allArtifactVulns) {
                if (finding.fixedVersion() == null) continue;
                if (!sameMajor(candidate, finding.fixedVersion())) continue;
                if (compareVersionsSemantic(candidate, finding.fixedVersion()) >= 0) continue;
                // candidate < fixedVersion — check range: affectedVersion <= candidate
                if (finding.affectedVersion() != null
                        && compareVersionsSemantic(finding.affectedVersion(), candidate) > 0) continue;
                if (fixVersion == null || compareVersionsSemantic(finding.fixedVersion(), fixVersion) < 0) {
                    fixVersion = finding.fixedVersion();
                }
            }
            if (fixVersion == null) break; // candidate is clean
            // Find the lowest available version >= fixVersion within same major
            String next = null;
            for (String v : upgradePath) {
                if (!sameMajor(candidate, v)) continue;
                if (compareVersionsSemantic(v, fixVersion) >= 0
                        && (next == null || compareVersionsSemantic(v, next) < 0)) {
                    next = v;
                }
            }
            if (next == null) next = fixVersion; // no upgrade path entry, use fix directly
            if (next.equals(candidate)) break;
            candidate = next;
        }
        // Fallback: if candidate is still listed as an affectedVersion in CVE data but no fixedVersion
        // was resolvable (fixedVersion=null), bump to the lowest same-major version in the upgrade path.
        if (!allArtifactVulns.isEmpty()) {
            String finalCandidate = candidate;
            boolean candidateIsAffected = allArtifactVulns.stream().anyMatch(vf ->
                    finalCandidate.equals(vf.affectedVersion())
                    || (vf.affectedVersion() != null
                        && compareVersionsSemantic(vf.affectedVersion(), finalCandidate) <= 0
                        && vf.fixedVersion() == null));
            if (candidateIsAffected) {
                for (String v : upgradePath) {
                    if (sameMajor(candidate, v) && compareVersionsSemantic(v, candidate) > 0
                            && !isPreRelease(v)) {
                        candidate = v;
                        break;
                    }
                }
            }
        }
        return candidate.isBlank() ? null : candidate;
    }

    private String buildConflictJson(TransitiveConflictFinding f) {
        StringBuilder json = new StringBuilder("{");
        json.append("\"groupId\":").append(jsonStr(f.groupId())).append(",");
        json.append("\"artifactId\":").append(jsonStr(f.artifactId())).append(",");
        json.append("\"resolvedVersion\":").append(jsonStr(f.resolvedVersion())).append(",");
        json.append("\"exclusions\":[");
        boolean first = true;
        for (ConflictCandidateAction a : f.candidateActions()) {
            if (a.type() != ConflictCandidateAction.ActionType.ADD_EXCLUSION || a.version() == null) continue;
            if (!first) json.append(",");
            first = false;
            json.append("{\"parentGroupId\":").append(jsonStr(a.parentGroupId()))
                .append(",\"parentArtifactId\":").append(jsonStr(a.parentArtifactId()))
                .append(",\"introducedVersion\":").append(jsonStr(a.version())).append("}");
        }
        json.append("]}");
        return json.toString().replace("'", "&#39;");
    }

    /** Highest known severity for a specific candidate version (not just the currently-scanned
     *  one) — a real per-version lookup (cached, so repeat renders and versions already checked
     *  during the scan's CVE fix resolution are typically free) rather than string-matching
     *  against the current version's own findings, which could never be true for any other
     *  version in the dropdown and made every non-current choice look falsely clean. Returns
     *  the actual severity level rather than a boolean so the dropdown can distinguish a Low
     *  residual CVE from a Critical one instead of showing them identically. */
    private AdvisorySeverity severityForVersion(ComponentCoordinate coordinate, String candidateVersion) {
        if (coordinate == null || candidateVersion == null || candidateVersion.isBlank()) {
            return AdvisorySeverity.NONE;
        }
        return AdvisoryClassifier.highest(vulnerabilities.vulnerabilities(coordinate, candidateVersion));
    }

    private List<String> versionChoices(MetadataResult versionMetadata, UpgradeRecommendation recommendation) {
        java.util.LinkedHashSet<String> choices = new java.util.LinkedHashSet<>();
        if (recommendation != null && recommendation.targetVersion() != null && !recommendation.targetVersion().isBlank()
                && !isPreRelease(recommendation.targetVersion())) {
            choices.add(recommendation.targetVersion());
        }
        if (versionMetadata != null) {
            if (versionMetadata.latestSameMajorVersion() != null && !versionMetadata.latestSameMajorVersion().isBlank()
                    && !isPreRelease(versionMetadata.latestSameMajorVersion())) {
                choices.add(versionMetadata.latestSameMajorVersion());
            }
            if (versionMetadata.upgradePathVersions() != null) {
                for (String version : versionMetadata.upgradePathVersions()) {
                    if (version != null && !version.isBlank() && !isPreRelease(version)) {
                        choices.add(version);
                    }
                }
            }
            if (versionMetadata.latestVersion() != null && !versionMetadata.latestVersion().isBlank()
                    && !"unknown".equalsIgnoreCase(versionMetadata.latestVersion())
                    && !isPreRelease(versionMetadata.latestVersion())) {
                choices.add(versionMetadata.latestVersion());
            }
            // Also offer older releases, not just the automated upgrade/downgrade path, so the
            // user can always manually pick something different — the algorithm's choice is a
            // default, not the only option. Capped to the N closest below the current version
            // (configurable, default 10) rather than the entire release history, which for a
            // long-lived library can run to hundreds of entries and swamp the dropdown.
            if (versionMetadata.allStableVersions() != null && versionMetadata.currentVersion() != null) {
                List<String> olderVersions = new ArrayList<>();
                for (String version : versionMetadata.allStableVersions()) {
                    if (version == null || version.isBlank() || isPreRelease(version)) continue;
                    if (compareVersionsSemantic(version, versionMetadata.currentVersion()) < 0) {
                        olderVersions.add(version);
                    }
                }
                olderVersions.sort((a, b) -> compareVersionsSemantic(b, a)); // descending — closest first
                for (int i = 0; i < Math.min(versionLookbackLimit(), olderVersions.size()); i++) {
                    choices.add(olderVersions.get(i));
                }
            }
        }
        if (recommendation != null && recommendation.currentVersion() != null) {
            choices.remove(recommendation.currentVersion());
        }
        return List.copyOf(choices);
    }
}
