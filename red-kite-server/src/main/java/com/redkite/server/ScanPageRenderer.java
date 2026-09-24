package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.maven.RemediationApplier;
import com.redkite.core.service.ChildVulnerabilityAggregator;
import com.redkite.core.service.LicenseNormalizer;
import com.redkite.core.service.LicensePermissiveness;
import com.redkite.core.service.RemediationClassifier;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import static com.redkite.server.Json.*;
import static com.redkite.server.Html.*;
import static com.redkite.server.PomXml.*;
import static com.redkite.server.PomPatcher.*;
import static com.redkite.server.Versions.*;

/** The remediation view of an analysis page: summary chips, filters, license breakdown and the list of component cards. */
final class ScanPageRenderer {
    private final Store store;
    private final ComponentCardRenderer cards;

    ScanPageRenderer(Store store, ComponentCardRenderer cards) {
        this.store = store;
        this.cards = cards;
    }

    static String enforcerBadge(Store.EnforcerResultEntry e) {
        if (e == null) return "";
        return switch (e.status()) {
            case ENFORCER_RUN_PASSED ->
                "<span class=\"badge success\" title=\"Dependency management check passed\">No conflicts</span>";
            case ENFORCER_RUN_FAILED_WITH_FINDINGS -> {
                int n = e.findings().size();
                List<TransitiveConflictFinding> phase2 = e.phase2Findings();
                if (phase2 != null && phase2.isEmpty()) {
                    // All conflicts resolved by auto-fix
                    yield "<span class=\"badge success\" title=\"" + n + " conflict" + (n == 1 ? "" : "s")
                        + " resolved by dep-management pins\">"
                        + n + " conflict" + (n == 1 ? "" : "s") + " resolved ✓</span>";
                }
                if (phase2 != null && !phase2.isEmpty()) {
                    yield "<span class=\"badge\" style=\"background:rgba(220,38,38,.16);border-color:rgba(220,38,38,.4);color:#fca5a5\""
                        + " title=\"" + phase2.size() + " conflict" + (phase2.size() == 1 ? "" : "s") + " remain unresolvable\">"
                        + phase2.size() + " unresolvable</span>";
                }
                yield "<span class=\"badge\" style=\"background:rgba(220,38,38,.16);border-color:rgba(220,38,38,.4);color:#fca5a5\""
                    + " title=\"Dependency management check failed\">"
                    + n + " convergence " + (n == 1 ? "conflict" : "conflicts") + "</span>";
            }
            default -> "";
        };
    }

    /** Every distinct license declared across all components, most common first, plus a
     *  "No License" bucket for components with nothing declared anywhere in their POM's own
     *  chain. A dual-licensed component counts toward every license it declares, so these can sum
     *  to more than the total component count. Raw declared strings are normalised via
     *  {@link LicenseNormalizer} before counting — "Apache-2.0" and "The Apache Software License,
     *  Version 2.0" are the same license and share one bucket — with the distinct raw variants
     *  that rolled into each bucket shown in its tooltip, so nothing is silently hidden. */
    String licenseBreakdownHtml(ScanReport report) {
        Map<String, Integer> ranks = store.loadLicenseRanks();
        Map<String, Long> licenseCounts = new LinkedHashMap<>();
        Map<String, Set<String>> rawVariantsByCanonical = new LinkedHashMap<>();
        long noLicenseCount = 0;
        for (MetadataResult m : report.metadataResults()) {
            if (m.metadataType() != MetadataType.LICENSE) continue;
            List<String> licenses = m.upgradePathVersions();
            if (licenses == null || licenses.isEmpty()) {
                noLicenseCount++;
                continue;
            }
            // Counted once per dependency, not once per declared license: a dual-licensed
            // dependency is only as restrictive as its most permissive option, so it belongs in
            // that one bucket rather than inflating every license it happens to also offer.
            String representative = representativeLicense(licenses, ranks);
            String canonical = LicenseNormalizer.canonicalize(representative);
            licenseCounts.merge(canonical, 1L, Long::sum);
            rawVariantsByCanonical.computeIfAbsent(canonical, k -> new java.util.TreeSet<>()).add(representative);
        }
        if (licenseCounts.isEmpty() && noLicenseCount == 0) return "";
        StringBuilder html = new StringBuilder();
        html.append("<div class=\"rem-banner-row\" style=\"margin-bottom:14px\">");
        licenseCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .forEach(e -> {
                    Set<String> variants = rawVariantsByCanonical.getOrDefault(e.getKey(), Set.of());
                    String title = variants.size() > 1 ? " title=\"" + escape(String.join("\n", variants)) + "\"" : "";
                    html.append("<span class=\"sev-chip sev-license\" data-license-value=\"").append(escape(e.getKey()))
                            .append("\" onclick=\"toggleLicenseFilter(this)\"").append(title).append(">&#128220; ")
                            .append(e.getValue()).append(" ").append(escape(e.getKey())).append("</span>");
                });
        if (noLicenseCount > 0) {
            html.append("<span class=\"sev-chip sev-license-none\" data-license-value=\"__no_license__\" onclick=\"toggleLicenseFilter(this)\">&#128220; ")
                    .append(noLicenseCount).append(" No License</span>");
        }
        html.append("</div>");
        return html.toString();
    }

    /** The single license a dependency is counted and filtered under: its only declared license,
     *  or — if it declares more than one — the most permissive per the configured rank table,
     *  falling back to the first declared if several are unranked. Badge display is unaffected by
     *  this: a card always shows every declared license exactly as-is, this is only for the
     *  breakdown's counts and the license filter's matching. */
    static String representativeLicense(List<String> licenses, Map<String, Integer> ranks) {
        if (licenses.size() == 1) return licenses.get(0);
        String best = LicensePermissiveness.mostPermissive(licenses, ranks);
        return best != null ? best : licenses.get(0);
    }

    private static String sevChipTitle(ReportSummary summary, AdvisorySeverity severity) {
        List<String> deps = summary.dependenciesBySeverity().getOrDefault(severity, List.of());
        if (deps.isEmpty()) return "";
        return " title=\"" + escape(String.join("\n", deps)) + "\"";
    }

    private static String reasonChipTitle(ReportSummary summary, RemediationReason reason) {
        List<String> deps = summary.dependenciesByReason().getOrDefault(reason, List.of());
        if (deps.isEmpty()) return "";
        return " title=\"" + escape(String.join("\n", deps)) + "\"";
    }

    String renderRemediationView(ScanReport report, String scanId, boolean pomExists, Map<String, String> moduleArtifactIds, Map<String, String> sourcePoms, Map<String, List<TransitiveConflictFinding>> conflictsByKey) {
        List<ScanComponent> components = report.components();
        if (components.isEmpty()) {
            return "<p class=\"muted\">No dependency inventory is available for this scan.</p>";
        }

        // Computed up front (rather than down where this was historically built) so both
        // summarize() and the per-component classify() loop below can use it — a pinned
        // coordinate's plain "update recommended" reason is suppressed by RemediationClassifier
        // itself, so the summary banner and every per-card/chip count stay consistent instead of
        // separately re-deciding what a pin means.
        Set<String> pinnedCoords = new LinkedHashSet<>();
        RemediationApplier pinScanApplier = new RemediationApplier();
        for (String pomContent : sourcePoms.values()) {
            try {
                pinnedCoords.addAll(pinScanApplier.findUserPinnedCoordinates(pomContent));
            } catch (Exception ignored) {}
        }
        Set<ComponentCoordinate> pinnedCoordinates = new LinkedHashSet<>();
        for (String coordStr : pinnedCoords) {
            int idx = coordStr.indexOf(':');
            if (idx > 0) pinnedCoordinates.add(new ComponentCoordinate(coordStr.substring(0, idx), coordStr.substring(idx + 1)));
        }

        ReportSummary summary = RemediationClassifier.summarize(report, pinnedCoordinates);

        // Build lookup maps
        Map<Long, UpgradeRecommendation> recByComponent = new LinkedHashMap<>();
        for (UpgradeRecommendation rec : report.recommendations()) {
            if (!rec.affectedComponentIds().isEmpty()) {
                for (Long id : rec.affectedComponentIds()) {
                    recByComponent.put(id, rec);
                }
            } else {
                recByComponent.put(rec.id(), rec);
            }
        }
        Map<Long, MetadataResult> versionMetaByComponent = new LinkedHashMap<>();
        Map<Long, List<String>> licensesByComponent = new LinkedHashMap<>();
        for (MetadataResult m : report.metadataResults()) {
            if (m.metadataType() == MetadataType.VERSION) {
                versionMetaByComponent.put(m.componentId(), m);
            } else if (m.metadataType() == MetadataType.LICENSE) {
                licensesByComponent.put(m.componentId(), m.upgradePathVersions());
            }
        }
        Map<String, List<VulnerabilityFinding>> vulnsByKey = new LinkedHashMap<>();
        for (VulnerabilityFinding f : report.vulnerabilityFindings()) {
            vulnsByKey.computeIfAbsent(
                    f.coordinate().groupId() + ":" + f.coordinate().artifactId() + "@" + f.affectedVersion(),
                    k -> new ArrayList<>()).add(f);
        }

        // Deduplicate and classify
        Map<String, ScanComponent> unique = new LinkedHashMap<>();
        for (ScanComponent c : components) {
            String key = c.sourceFilePath() + "|" + c.coordinate().groupId() + ":"
                    + c.coordinate().artifactId() + "|" + c.version() + "|" + c.direct();
            unique.putIfAbsent(key, c);
        }

        // Build id→component index and reverse edge map (child → parent component ids)
        Map<Long, ScanComponent> componentsById = new LinkedHashMap<>();
        for (ScanComponent c : unique.values()) componentsById.put(c.id(), c);
        Map<Long, List<Long>> parentIdsByChild = new LinkedHashMap<>();
        Map<Long, List<Long>> childrenByParent = new LinkedHashMap<>();
        for (DependencyEdge edge : report.dependencyEdges()) {
            if (edge.fromComponentId() == null || edge.fromComponentId().startsWith("module:")) continue;
            try {
                long fromId = Long.parseLong(edge.fromComponentId());
                long toId = Long.parseLong(edge.toComponentId());
                parentIdsByChild.computeIfAbsent(toId, k -> new ArrayList<>()).add(fromId);
                childrenByParent.computeIfAbsent(fromId, k -> new ArrayList<>()).add(toId);
            } catch (NumberFormatException ignored) {}
        }

        String rootPomContent = rootPomXml(sourcePoms);
        Map<Long, ChildVulnerabilityCounts> childVulnCounts = ChildVulnerabilityAggregator.computeByComponentId(report);
        List<ComponentView> views = new ArrayList<>();
        for (ScanComponent c : unique.values()) {
            RemediationStatus status = RemediationClassifier.classify(
                    c, report.vulnerabilityFindings(), report.recommendations(), report.metadataResults(), pinnedCoordinates);
            MetadataResult versionMeta = versionMetaByComponent.get(c.id());
            UpgradeRecommendation rec = recByComponent.get(c.id());
            TransitiveConflictFinding conflict = findMatchingConflict(conflictsByKey, c);
            List<VulnerabilityFinding> vulns = vulnsByKey.getOrDefault(
                    c.coordinate().groupId() + ":" + c.coordinate().artifactId() + "@" + c.version(), List.of());
            boolean canUpgradeViaDirect = false;
            if (!c.direct() && rec != null) {
                for (long parentId : parentIdsByChild.getOrDefault(c.id(), List.of())) {
                    ScanComponent parent = componentsById.get(parentId);
                    if (parent != null && parent.direct()) {
                        UpgradeRecommendation parentRec = recByComponent.get(parentId);
                        if (parentRec != null && sameMajor(parent.version(), parentRec.targetVersion())) {
                            canUpgradeViaDirect = true;
                            break;
                        }
                    }
                }
            }
            List<String> licenses = licensesByComponent.getOrDefault(c.id(), List.of());
            ChildVulnerabilityCounts childVulns = childVulnCounts.getOrDefault(c.id(), ChildVulnerabilityCounts.EMPTY);
            views.add(new ComponentView(c, status, versionMeta, rec, vulns, canUpgradeViaDirect, conflict, licenses, childVulns));
        }

        // Sort: CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN advisory → SNAPSHOT → STALE → VERSION_MGMT → UPGRADE → CLEAN
        // Within same bucket: direct before transitive, then alphabetical
        views.sort((a, b) -> {
            int ka = remediationSortKey(a);
            int kb = remediationSortKey(b);
            if (ka != kb) return Integer.compare(ka, kb);
            if (a.component().direct() != b.component().direct()) return a.component().direct() ? -1 : 1;
            return a.component().coordinate().artifactId()
                    .compareTo(b.component().coordinate().artifactId());
        });

        // Computed here (rather than solely from summary.recommendationCount(), which is a
        // RemediationClassifier/core computation with no visibility into POM content or conflict
        // findings) so the "Update recommended" banner chip and the Outdated filter chip below
        // both reflect the same, more accurate signal: a transitive dependency with no concrete
        // reason to move (see transitiveRecommendedVersion) is excluded from both, not just one.
        long outdatedCount = views.stream().filter(v -> cards.isEffectivelyOutdatedOnly(v, rootPomContent)).count();

        // Deduped by dependency (coordinate + version), not by card — the same dependency can
        // produce a card per module it's declared/resolved in (see `unique` above). A card in ANY
        // of its modules with a finding counts the whole dependency as a finding, mirroring
        // RemediationClassifier's own per-dependency OR-combine. This is also the single source of
        // truth for the banner's "components"/"need remediation"/"clean" numbers below — they used
        // to come from RemediationClassifier.summarize() instead, which has no visibility into
        // isCardClean's transitive-noise exception (a plain, non-CVE update recommendation on a
        // transitive dependency with no concrete reason to move), so the banner and the
        // Findings/Clean/All tabs could disagree about a component the tabs deliberately don't
        // treat as a finding.
        Map<String, Boolean> hasFindingByDependency = new LinkedHashMap<>();
        for (ComponentView v : views) {
            String depKey = v.component().coordinate().groupId() + ":" + v.component().coordinate().artifactId()
                    + "@" + v.component().version();
            hasFindingByDependency.merge(depKey, !cards.isCardClean(v), Boolean::logicalOr);
        }
        long findingsCount = hasFindingByDependency.values().stream().filter(Boolean::booleanValue).count();
        long cleanCount = hasFindingByDependency.size() - findingsCount;
        StringBuilder html = new StringBuilder();

        // Summary banner
        html.append("<div class=\"rem-banner\">");
        html.append("<div class=\"rem-banner-row\">");
        html.append("<span class=\"rem-stat\"><strong>").append(hasFindingByDependency.size()).append("</strong> components</span>");
        if (findingsCount > 0) {
            html.append("<span class=\"rem-stat\"><strong>").append(findingsCount).append("</strong> need remediation</span>");
        }
        html.append("<span class=\"rem-stat muted\">").append(cleanCount).append(" clean</span>");
        html.append("</div>");
        html.append("<div class=\"rem-banner-row\">");
        if (summary.criticalCount() > 0) html.append("<span class=\"sev-chip sev-critical\"").append(sevChipTitle(summary, AdvisorySeverity.CRITICAL)).append(">&#9762; ").append(summary.criticalCount()).append(" Critical</span>");
        if (summary.highCount() > 0) html.append("<span class=\"sev-chip sev-high\"").append(sevChipTitle(summary, AdvisorySeverity.HIGH)).append(">&#9760; ").append(summary.highCount()).append(" High</span>");
        if (summary.mediumCount() > 0) html.append("<span class=\"sev-chip sev-medium\"").append(sevChipTitle(summary, AdvisorySeverity.MEDIUM)).append(">&#9888; ").append(summary.mediumCount()).append(" Medium</span>");
        if (summary.lowCount() > 0) html.append("<span class=\"sev-chip sev-low\"").append(sevChipTitle(summary, AdvisorySeverity.LOW)).append(">&#x2139; ").append(summary.lowCount()).append(" Low</span>");
        if (summary.unknownCount() > 0) html.append("<span class=\"sev-chip sev-unknown\"").append(sevChipTitle(summary, AdvisorySeverity.UNKNOWN)).append(">? ").append(summary.unknownCount()).append(" Unknown</span>");
        html.append("</div>");
        // Breakdown of "need remediation" by reason, mirroring the OR-conditions in
        // RemediationClassifier.classify() exactly, except vulnerabilities — those are covered
        // by the deduped-by-CVE severity row above, so they're not repeated here. A component
        // can trip more than one reason at once (e.g. a snapshot with a known CVE), so these
        // chips can legitimately sum to more than "need remediation", and a component whose
        // only reason is a vulnerability won't appear in this row (see the severity row instead).
        html.append("<div class=\"rem-banner-row\">");
        if (summary.snapshotCount() > 0) html.append("<span class=\"sev-chip sev-snap\"").append(reasonChipTitle(summary, RemediationReason.SNAPSHOT)).append(">&#9889; ").append(summary.snapshotCount()).append(" Snapshot</span>");
        if (summary.declaredVersionWarningCount() > 0) html.append("<span class=\"sev-chip sev-declared\"").append(reasonChipTitle(summary, RemediationReason.DECLARED_VERSION)).append(">&#128196; ").append(summary.declaredVersionWarningCount()).append(" Declared version</span>");
        if (outdatedCount > 0) html.append("<span class=\"sev-chip sev-recommended\"").append(reasonChipTitle(summary, RemediationReason.UPGRADE_RECOMMENDED)).append(">&#8593; ").append(outdatedCount).append(" Update recommended</span>");
        if (summary.staleMetadataCount() > 0) html.append("<span class=\"sev-chip sev-stale\"").append(reasonChipTitle(summary, RemediationReason.STALE_METADATA)).append(">&#8635; ").append(summary.staleMetadataCount()).append(" Stale metadata</span>");
        html.append("</div>");
        html.append("</div>");

        // Build module index — seed from all known source POMs so empty modules still appear
        Map<String, List<ComponentView>> byModule = new LinkedHashMap<>();
        for (String modPath : moduleArtifactIds.keySet()) {
            byModule.put(modPath, new ArrayList<>());
        }
        for (ComponentView v : views) {
            String mod = v.component().modulePath() == null || v.component().modulePath().isBlank()
                    ? "(root)" : v.component().modulePath();
            byModule.computeIfAbsent(mod, k -> new ArrayList<>()).add(v);
        }

        // Module dropdown — root POM (shallowest path, typically "pom.xml") listed first
        if (byModule.size() > 1) {
            List<String> moduleOrder = new ArrayList<>(byModule.keySet());
            moduleOrder.sort((a, b) -> {
                int depthA = a.equals("(root)") ? 0 : (int) a.chars().filter(c -> c == '/').count();
                int depthB = b.equals("(root)") ? 0 : (int) b.chars().filter(c -> c == '/').count();
                if (depthA != depthB) return Integer.compare(depthA, depthB);
                return a.compareTo(b);
            });
            String firstModule = moduleOrder.stream()
                    .filter(m -> byModule.getOrDefault(m, List.of()).stream().anyMatch(this::isDefaultVisibleRemediationCard))
                    .findFirst()
                    .orElseGet(() -> moduleOrder.stream()
                            .filter(m -> !byModule.getOrDefault(m, List.of()).isEmpty())
                            .findFirst()
                            .orElse(moduleOrder.get(0)));
            html.append("<script>remModule=").append(jsString(firstModule)).append(";</script>");
            html.append("<select class=\"rem-module-select\" onchange=\"filterRemediationModule(this.value)\">");
            html.append("<option value=\"all\">All modules</option>");
            for (String mod : moduleOrder) {
                String label = moduleArtifactIds.getOrDefault(mod, modulePathLabel(mod));
                html.append("<option value=\"").append(escape(mod)).append("\"")
                        .append(mod.equals(firstModule) ? " selected" : "").append(">")
                        .append(escape(label)).append("</option>");
            }
            html.append("</select>");
        }

        // Three workflow-level views (mutually exclusive, like a tab really is one) plus, within
        // Findings, independent multi-select filter chips — CVE/Conflict/Transitive/etc. are
        // overlapping properties a dependency can have at once, not disjoint categories, so they
        // no longer compete for one exclusive tab slot the way Findings/Clean/All genuinely do.
        long cveUpgradeCount = views.stream().filter(cards::isCveFixByUpgrade).count();
        long cveDowngradeCount = views.stream().filter(cards::isCveFixByDowngrade).count();
        long cveNofixCount = views.stream().filter(cards::isCveNofix).count();
        long conflictCount = views.stream().filter(v -> v.convergenceFinding() != null).count();
        long snapshotCount = views.stream().filter(v -> v.status().isSnapshot()).count();
        long directCount = views.stream().filter(v -> v.component().direct()).count();
        long transitiveOriginCount = views.stream().filter(v -> !v.component().direct()).count();

        html.append("<div class=\"rem-toggle\">");
        html.append("<button class=\"button primary rem-toggle-btn\" type=\"button\" data-view=\"findings\" onclick=\"setRemView('findings')\">Findings <span class=\"tab-count\">").append(findingsCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-view=\"clean\" onclick=\"setRemView('clean')\">Clean <span class=\"tab-count\">").append(cleanCount).append("</span></button>");
        html.append("<button class=\"button rem-toggle-btn\" type=\"button\" data-view=\"all\" onclick=\"setRemView('all')\">All <span class=\"tab-count\">").append(hasFindingByDependency.size()).append("</span></button>");
        html.append("</div>");

        html.append("<div class=\"rem-filters\" id=\"rem-filters\">");
        html.append("<div class=\"filter-group\" data-group=\"reason\">");
        html.append("<span class=\"filter-group-label\">Reason</span>");
        html.append(filterChipHtml("reason", "cveupgrade", "CVE Upgrade", cveUpgradeCount));
        html.append(filterChipHtml("reason", "cvedowngrade", "CVE Downgrade", cveDowngradeCount));
        html.append(filterChipHtml("reason", "cvenofix", "CVE Nofix", cveNofixCount));
        html.append(filterChipHtml("reason", "conflict", "Conflict", conflictCount));
        html.append(filterChipHtml("reason", "outdated", "Outdated", outdatedCount));
        html.append(filterChipHtml("reason", "snapshot", "Snapshot", snapshotCount));
        html.append("</div>");
        html.append("<div class=\"filter-group\" data-group=\"origin\">");
        html.append("<span class=\"filter-group-label\">Origin</span>");
        html.append(filterChipHtml("origin", "direct", "Direct", directCount));
        html.append(filterChipHtml("origin", "transitive", "Transitive", transitiveOriginCount));
        html.append("</div>");
        html.append("<div class=\"filter-rule\" id=\"rem-filter-rule\"></div>");
        html.append("</div>");

        // Apply bar
        html.append("<div class=\"pom-actions\">");
        html.append("<button class=\"button primary\" type=\"button\" id=\"apply-btn\"");
        if (!pomExists) {
            html.append(" disabled data-nopom=\"true\" title=\"No source POMs available for this scan\"");
        } else {
            html.append(" disabled");
        }
        html.append(" onclick=\"applyPomChanges()\">Apply selected</button>");
        html.append("</div>");

        // Emit component index + edge map for client-side tree expansion
        html.append("<script>const rk_scanId=").append(jsonStr(scanId)).append(";const rk_comps={");
        boolean firstComp = true;
        for (ComponentView v : views) {
            if (!firstComp) html.append(",");
            firstComp = false;
            ScanComponent c = v.component();
            RemediationStatus s = v.status();
            html.append("\"").append(c.id()).append("\":{")
                .append("\"g\":").append(jsonStr(c.coordinate().groupId())).append(",")
                .append("\"a\":").append(jsonStr(c.coordinate().artifactId())).append(",")
                .append("\"v\":").append(jsonStr(c.version())).append(",")
                .append("\"icon\":").append(jsonStr(s.highestSeverity().icon())).append(",")
                .append("\"label\":").append(jsonStr(s.highestSeverity().label())).append(",")
                .append("\"sev\":").append(jsonStr(s.highestSeverity().name().toLowerCase())).append(",")
                .append("\"kind\":").append(jsonStr(c.snapshot() ? "snapshot" : c.direct() ? "declared" : "transitive")).append(",")
                .append("\"clean\":").append(!s.needsRemediation()).append(",")
                .append("\"pin\":").append(pinnedCoords.contains(c.coordinate().groupId() + ":" + c.coordinate().artifactId())).append(",")
                .append("\"hasvuln\":").append(s.hasVulnerability());
            String recTarget = c.direct()
                    ? (v.recommendation() != null ? v.recommendation().targetVersion() : null)
                    : cards.transitiveRecommendedVersion(v, rootPomContent);
            if (recTarget != null && !recTarget.equals(c.version())) {
                html.append(",\"rec\":").append(jsonStr(recTarget));
            }
            if (v.versionMetadata() != null) {
                String latest = v.versionMetadata().latestVersion();
                if (latest != null && !latest.isBlank() && !"unknown".equalsIgnoreCase(latest)
                        && !latest.equals(c.version())) {
                    html.append(",\"latest\":").append(jsonStr(latest));
                }
            }
            html.append("}");
        }
        html.append("};const rk_edges={");
        boolean firstEdge = true;
        for (Map.Entry<Long, List<Long>> entry : parentIdsByChild.entrySet()) {
            if (!firstEdge) html.append(",");
            firstEdge = false;
            html.append("\"").append(entry.getKey()).append("\":[");
            boolean firstChild = true;
            for (Long cid : entry.getValue()) {
                if (!firstChild) html.append(",");
                firstChild = false;
                html.append(cid);
            }
            html.append("]");
        }
        html.append("};");

        // Build rk_propGroups: "filePath:propName" → [compId, ...] for shared property references.
        // rk_compPropKey: compId → "filePath:propName" (only for comps in a shared-prop group).
        // Used client-side to sync sibling dropdowns when the user changes a version.
        {
            Map<String, Long> coordFileKey = new LinkedHashMap<>();
            for (ScanComponent c : report.components()) {
                if (!c.direct() || c.sourceFilePath() == null) continue;
                coordFileKey.put(c.sourceFilePath() + "|" + c.coordinate().groupId() + ":" + c.coordinate().artifactId(), c.id());
            }
            Map<String, List<Long>> propGroups = new LinkedHashMap<>();
            Map<Long, String> compPropKey = new LinkedHashMap<>();
            for (Map.Entry<String, String> pomEntry : sourcePoms.entrySet()) {
                String filePath = pomEntry.getKey();
                try {
                    var dbf2 = DocumentBuilderFactory.newInstance();
                    dbf2.setNamespaceAware(false);
                    Document pdoc = dbf2.newDocumentBuilder().parse(new InputSource(new StringReader(pomEntry.getValue())));
                    NodeList nl = pdoc.getElementsByTagName("*");
                    for (int i = 0; i < nl.getLength(); i++) {
                        if (!(nl.item(i) instanceof Element de)) continue;
                        if (!"dependency".equals(de.getNodeName()) && !"plugin".equals(de.getNodeName())) continue;
                        String pg = childText(de, "groupId"), pa = childText(de, "artifactId");
                        if (pg == null || pa == null) continue;
                        if ("plugin".equals(de.getNodeName()) && pg.trim().isEmpty()) pg = "org.apache.maven.plugins";
                        pg = pg.trim(); pa = pa.trim();
                        Node pvn = directChildVersion(de);
                        if (pvn == null) continue;
                        String pvt = pvn.getTextContent().trim();
                        if (!pvt.startsWith("${") || !pvt.endsWith("}")) continue;
                        String propName = pvt.substring(2, pvt.length() - 1);
                        Long cid = coordFileKey.get(filePath + "|" + pg + ":" + pa);
                        if (cid == null) continue;
                        String groupKey = filePath + ":" + propName;
                        propGroups.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(cid);
                        compPropKey.put(cid, groupKey);
                    }
                } catch (Exception ignored) {}
            }
            // Only emit groups with 2+ members; single-member groups need no syncing
            html.append("const rk_propGroups={");
            boolean fg = true;
            for (Map.Entry<String, List<Long>> e : propGroups.entrySet()) {
                if (e.getValue().size() < 2) continue;
                if (!fg) html.append(",");
                fg = false;
                html.append(jsonStr(e.getKey())).append(":[");
                for (int i = 0; i < e.getValue().size(); i++) {
                    if (i > 0) html.append(",");
                    html.append(e.getValue().get(i));
                }
                html.append("]");
            }
            html.append("};const rk_compPropKey={");
            boolean fk = true;
            for (Map.Entry<Long, String> e : compPropKey.entrySet()) {
                if (!propGroups.containsKey(e.getValue()) || propGroups.get(e.getValue()).size() < 2) continue;
                if (!fk) html.append(",");
                fk = false;
                html.append("\"").append(e.getKey()).append("\":").append(jsonStr(e.getValue()));
            }
            html.append("};");
        }
        // Coordinate groups: g:a → [compId, ...] for cross-POM sibling syncing
        {
            Map<String, List<Long>> coordGroups = new LinkedHashMap<>();
            for (ComponentView v : views) {
                ScanComponent c = v.component();
                if (c.coordinate() == null) continue;
                String coord = c.coordinate().groupId() + ":" + c.coordinate().artifactId();
                coordGroups.computeIfAbsent(coord, k -> new ArrayList<>()).add(c.id());
            }
            html.append("const rk_coordGroups={");
            boolean first = true;
            for (Map.Entry<String, List<Long>> e : coordGroups.entrySet()) {
                if (e.getValue().size() < 2) continue;
                if (!first) html.append(",");
                first = false;
                html.append(jsonStr(e.getKey())).append(":[");
                for (int i = 0; i < e.getValue().size(); i++) {
                    if (i > 0) html.append(",");
                    html.append(e.getValue().get(i));
                }
                html.append("]");
            }
            html.append("};");
        }
        html.append("</script>");

        // Component cards
        Map<String, Integer> licenseRanks = store.loadLicenseRanks();
        html.append("<div class=\"rem-list\">");
        for (ComponentView view : views) {
            String mod = view.component().modulePath() == null || view.component().modulePath().isBlank()
                    ? "(root)" : view.component().modulePath();
            boolean hasParents = !parentIdsByChild.getOrDefault(view.component().id(), List.of()).isEmpty();
            html.append(cards.renderComponentCard(view, mod, hasParents, vulnsByKey, pinnedCoords, rootPomContent, licenseRanks));
        }
        html.append("</div>");

        // POM preview modal
        html.append("<div id=\"pom-modal\" class=\"pom-modal\" style=\"display:none\">");
        html.append("<div class=\"pom-modal-backdrop\" onclick=\"closePomModal()\"></div>");
        html.append("<div class=\"pom-modal-box\">");
        html.append("<div class=\"pom-modal-head\">");
        html.append("<div style=\"display:flex;align-items:center;gap:10px;min-width:0;overflow:hidden\">");
        html.append("<span id=\"pom-modal-filename\" class=\"pom-modal-filename\"></span>");
        html.append("<select id=\"pom-file-sel\" style=\"display:none;padding:4px 10px;border-radius:8px;"
                + "border:1px solid var(--line);background:var(--surf-nav);color:var(--text);"
                + "font-size:.82rem;font-family:ui-monospace,monospace;cursor:pointer\" onchange=\"switchPomFile(this.value)\"></select>");
        html.append("</div>");
        html.append("<div style=\"display:flex;gap:8px;flex-shrink:0\">");
        html.append("<button class=\"button\" type=\"button\" onclick=\"copyPomContent()\">Copy</button>");
        html.append("<button class=\"button\" type=\"button\" onclick=\"closePomModal()\">Close</button>");
        html.append("</div></div>");
        html.append("<div class=\"pom-modal-body\"><pre id=\"pom-modal-content\"></pre></div>");
        html.append("</div></div>");

        // Apply preview modal — shown on every "Apply selected" click before the apply-batch job runs
        html.append("<div id=\"apply-preview-modal\" class=\"pom-modal\" style=\"display:none\">");
        html.append("<div class=\"pom-modal-backdrop\" onclick=\"closeApplyPreview()\"></div>");
        html.append("<div class=\"pom-modal-box\" style=\"width:min(560px,92vw)\">");
        html.append("<div class=\"pom-modal-head\">");
        html.append("<span class=\"pom-modal-filename\">Apply changes</span>");
        html.append("<div style=\"display:flex;gap:8px;flex-shrink:0\">");
        html.append("<button class=\"button\" type=\"button\" onclick=\"closeApplyPreview()\">Cancel</button>");
        html.append("<button class=\"button primary\" type=\"button\" id=\"apply-preview-ok\" onclick=\"confirmApplyPreview()\">OK</button>");
        html.append("</div></div>");
        html.append("<div class=\"pom-modal-body\"><div id=\"apply-preview-body\" style=\"padding:20px\"></div></div>");
        html.append("</div></div>");

        return html.toString();
    }

    static boolean isBuildFailed(ScanReport report) {
        List<String> w = report.treeParseWarnings();
        return w != null && w.stream().anyMatch(s -> s.startsWith("[BUILD_FAILED]"));
    }

    private int remediationSortKey(ComponentView view) {
        ScanComponent component = view.component();
        RemediationStatus status = view.status();
        if (view.convergenceFinding() != null) {
            return 80;
        }
        if (status.hasVulnerability()) {
            return switch (status.highestSeverity()) {
                case CRITICAL -> 0;
                case HIGH -> 10;
                case MEDIUM -> 20;
                case LOW -> 30;
                default -> 40; // UNKNOWN
            };
        }
        if (status.isSnapshot()) return 50;
        if (status.hasStaleMetadata()) return 60;
        if (status.hasDeclaredVersionDeclaration()) return 70;
        if (status.hasUpgradeRecommendation()) return 80;
        return 90;
    }

    /** Whether a card shows up in the default view (Findings) — used only to pick which module
     *  tab is initially selected, so it should match exactly what the Findings view itself shows. */
    private boolean isDefaultVisibleRemediationCard(ComponentView view) {
        return view != null && !cards.isCardClean(view);
    }
}
