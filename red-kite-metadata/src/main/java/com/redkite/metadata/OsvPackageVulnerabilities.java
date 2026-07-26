package com.redkite.metadata;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.VulnerabilityFinding;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure parsing/matching logic over a single OSV "package query" response — the {@code vulns}
 * array returned when querying OSV by package name alone (no version), which lists every known
 * advisory for that package regardless of which version each one affects. Kept separate from
 * {@link HttpVulnerabilityProvider}'s network/caching orchestration so the matching rules (the
 * part correctness actually depends on) can be unit-tested against real fixture JSON with no HTTP
 * or DB involved.
 *
 * <p>Unlike the per-version OSV query this replaced, nothing external has already confirmed a
 * given advisory applies to {@code version} — this class is the sole authority for that decision.
 * {@link #findingsForVersion} treats an advisory as affecting a version only if either its
 * explicit {@code versions} enumeration lists it, or a range segment's bounds contain it; an
 * advisory whose range shape this can't interpret (a non-ECOSYSTEM range, say) with no explicit
 * enumeration either is simply not counted, rather than defensively included the way the old
 * per-version-trusting code could afford to.
 */
final class OsvPackageVulnerabilities {

    private OsvPackageVulnerabilities() {
    }

    static List<VulnerabilityFinding> findingsForVersion(String packageResponseJson, ComponentCoordinate coordinate, String version) {
        JsonObject root;
        try {
            root = JsonParser.parseString(packageResponseJson).getAsJsonObject();
        } catch (Exception e) {
            return List.of();
        }
        if (!root.has("vulns")) {
            return List.of();
        }
        List<VulnerabilityFinding> findings = new ArrayList<>();
        for (JsonElement vulnElem : root.getAsJsonArray("vulns")) {
            JsonObject vuln = vulnElem.getAsJsonObject();
            Match match = evaluate(vuln, coordinate, version);
            if (!match.affected) continue;
            String advisoryId = vuln.has("id") ? vuln.get("id").getAsString() : "UNKNOWN";
            findings.add(new VulnerabilityFinding(advisoryId, extractSeverity(vuln), coordinate, version,
                    match.fixedVersion, match.introducedVersion, false, null, extractCves(vuln), null));
        }
        return List.copyOf(findings);
    }

    private record Match(boolean affected, String introducedVersion, String fixedVersion) {
        static final Match NOT_AFFECTED = new Match(false, null, null);
    }

    /**
     * Determines whether {@code vuln} affects {@code version} and, if so, the display bounds —
     * combining two independent signals so a gap in one doesn't silently drop a real finding:
     * exact membership in an {@code affected[].versions} enumeration (when OSV supplies one), and
     * range-segment containment (the same union-of-overlapping-segments logic
     * {@code HttpVulnerabilityProvider}'s old per-version path used, preserved here verbatim).
     */
    private static Match evaluate(JsonObject vuln, ComponentCoordinate coordinate, String version) {
        if (!vuln.has("affected")) return Match.NOT_AFFECTED;
        String packageName = coordinate.groupId() + ":" + coordinate.artifactId();
        boolean explicitListed = false;
        String fallbackFixed = null;
        // "0" is the sentinel for "affected since inception" — kept as a real comparable value
        // (rather than null) while combining, so an inception bound correctly dominates the MIN
        // even when another matching segment supplies a specific, higher introduced version.
        String lowestIntroducedRaw = null;
        String highestFixed = null;
        boolean anyUnbounded = false;
        boolean matchedAny = false;

        for (JsonElement affectedElem : vuln.getAsJsonArray("affected")) {
            JsonObject affected = affectedElem.getAsJsonObject();
            if (affected.has("package")) {
                String name = affected.getAsJsonObject("package").has("name")
                        ? affected.getAsJsonObject("package").get("name").getAsString() : "";
                if (!packageName.equals(name)) continue;
            }
            if (affected.has("versions")) {
                for (JsonElement ve : affected.getAsJsonArray("versions")) {
                    if (version.equals(ve.getAsString())) {
                        explicitListed = true;
                        break;
                    }
                }
            }
            if (!affected.has("ranges")) continue;
            for (JsonElement rangeElem : affected.getAsJsonArray("ranges")) {
                JsonObject range = rangeElem.getAsJsonObject();
                if (!"ECOSYSTEM".equals(range.has("type") ? range.get("type").getAsString() : "")) continue;
                if (!range.has("events")) continue;
                String segmentIntroduced = null;
                for (JsonElement event : range.getAsJsonArray("events")) {
                    JsonObject eventObj = event.getAsJsonObject();
                    if (eventObj.has("introduced")) {
                        segmentIntroduced = eventObj.get("introduced").getAsString();
                    } else if (eventObj.has("fixed")) {
                        String segmentFixed = eventObj.get("fixed").getAsString();
                        if (fallbackFixed == null) fallbackFixed = segmentFixed;
                        if (versionInRange(version, segmentIntroduced, segmentFixed)) {
                            matchedAny = true;
                            String raw = segmentIntroduced == null || segmentIntroduced.isBlank() ? "0" : segmentIntroduced;
                            lowestIntroducedRaw = lowerBoundRaw(lowestIntroducedRaw, raw);
                            highestFixed = higherBound(highestFixed, segmentFixed);
                        }
                        segmentIntroduced = null;
                    } else if (eventObj.has("last_affected")) {
                        String lastAffected = eventObj.get("last_affected").getAsString();
                        if (versionInRangeInclusive(version, segmentIntroduced, lastAffected)) {
                            matchedAny = true;
                            anyUnbounded = true;
                            String raw = segmentIntroduced == null || segmentIntroduced.isBlank() ? "0" : segmentIntroduced;
                            lowestIntroducedRaw = lowerBoundRaw(lowestIntroducedRaw, raw);
                        }
                        segmentIntroduced = null;
                    }
                }
                // Open-ended segment: introduced but never closed by a fixed/last_affected event.
                if (segmentIntroduced != null
                        && HttpVersionMetadataProvider.compareVersions(version, segmentIntroduced) >= 0) {
                    matchedAny = true;
                    anyUnbounded = true;
                    lowestIntroducedRaw = lowerBoundRaw(lowestIntroducedRaw, segmentIntroduced);
                }
            }
        }

        if (matchedAny) {
            return new Match(true, normalizeIntroduced(lowestIntroducedRaw), anyUnbounded ? null : highestFixed);
        }
        if (explicitListed) {
            // OSV's explicit enumeration says this version is affected, but no range segment
            // could be matched (an unusual range shape, say) — include it defensively, same as
            // the old code did whenever OSV had told it a version applied, just gated on our own
            // signal (the versions list) instead of an externally pre-filtered response.
            return new Match(true, null, fallbackFixed);
        }
        return Match.NOT_AFFECTED;
    }

    private static List<String> extractCves(JsonObject vuln) {
        List<String> cves = new ArrayList<>();
        if (vuln.has("aliases")) {
            for (JsonElement alias : vuln.getAsJsonArray("aliases")) {
                String s = alias.getAsString();
                if (s.startsWith("CVE-")) cves.add(s);
            }
        }
        if (cves.isEmpty() && vuln.has("id") && vuln.get("id").getAsString().startsWith("CVE-")) {
            cves.add(vuln.get("id").getAsString());
        }
        return List.copyOf(cves);
    }

    private static String extractSeverity(JsonObject vuln) {
        // Prefer explicit severity label from database-specific metadata (e.g. GHSA)
        if (vuln.has("database_specific")) {
            JsonObject dbSpecific = vuln.getAsJsonObject("database_specific");
            if (dbSpecific.has("severity")) {
                String sev = dbSpecific.get("severity").getAsString().trim();
                if (!sev.isBlank()) return sev.toUpperCase();
            }
        }
        // Fall back to CVSS vector analysis
        if (vuln.has("severity")) {
            for (JsonElement sev : vuln.getAsJsonArray("severity")) {
                JsonObject obj = sev.getAsJsonObject();
                String type = obj.has("type") ? obj.get("type").getAsString() : "";
                String score = obj.has("score") ? obj.get("score").getAsString() : "";
                if (type.startsWith("CVSS_V") && !score.isBlank()) {
                    return severityFromVector(score);
                }
            }
        }
        return "UNKNOWN";
    }

    private static String severityFromVector(String cvss) {
        boolean cH = cvss.contains("/C:H");
        boolean iH = cvss.contains("/I:H");
        boolean aH = cvss.contains("/A:H");
        // All three CIA metrics at High → CRITICAL
        if (cH && iH && aH) return "CRITICAL";
        if (cH || iH || aH) return "HIGH";
        if (cvss.contains("/C:M") || cvss.contains("/I:M") || cvss.contains("/A:M")) return "MEDIUM";
        return "LOW";
    }

    private static String lowerBoundRaw(String a, String b) {
        if (a == null) return b;
        if (b == null) return a;
        return HttpVersionMetadataProvider.compareVersions(a, b) <= 0 ? a : b;
    }

    private static String higherBound(String a, String b) {
        if (a == null) return b;
        if (b == null) return a;
        return HttpVersionMetadataProvider.compareVersions(a, b) >= 0 ? a : b;
    }

    private static String normalizeIntroduced(String introduced) {
        return (introduced == null || introduced.isBlank() || "0".equals(introduced)) ? null : introduced;
    }

    private static boolean versionInRange(String version, String introduced, String fixed) {
        if (fixed == null || fixed.isBlank()) return false;
        boolean aboveIntroduced = normalizeIntroduced(introduced) == null
                || HttpVersionMetadataProvider.compareVersions(version, introduced) >= 0;
        boolean belowFixed = HttpVersionMetadataProvider.compareVersions(version, fixed) < 0;
        return aboveIntroduced && belowFixed;
    }

    private static boolean versionInRangeInclusive(String version, String introduced, String lastAffected) {
        boolean aboveIntroduced = normalizeIntroduced(introduced) == null
                || HttpVersionMetadataProvider.compareVersions(version, introduced) >= 0;
        boolean belowOrEqual = HttpVersionMetadataProvider.compareVersions(version, lastAffected) <= 0;
        return aboveIntroduced && belowOrEqual;
    }
}
