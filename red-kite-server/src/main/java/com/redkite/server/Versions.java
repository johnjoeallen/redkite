package com.redkite.server;

import com.redkite.core.domain.*;
import java.util.List;
import java.util.Map;

/** Version comparison and classification helpers. */
final class Versions {
    private Versions() {
    }

    /** Whether two versions share a release line (equal first two version tokens, e.g. "1.5"). */
    static boolean sameReleaseLine(String a, String b) {
        return com.redkite.core.service.SemanticVersionComparator.sameReleaseLine(a, b);
    }

    static int compareVersionsSemantic(String a, String b) {
        return com.redkite.core.service.SemanticVersionComparator.compare(a, b);
    }

    static boolean sameMajorMinor(String v1, String v2) {
        if (v1 == null || v2 == null) return false;
        String[] p1 = v1.split("\\.", 3);
        String[] p2 = v2.split("\\.", 3);
        return p1.length >= 2 && p2.length >= 2 && p1[0].equals(p2[0]) && p1[1].equals(p2[1]);
    }

    static boolean sameMajor(String v1, String v2) {
        if (v1 == null || v2 == null) return false;
        String[] p1 = v1.split("[.\\-]", 2);
        String[] p2 = v2.split("[.\\-]", 2);
        return p1.length >= 1 && p2.length >= 1 && !p1[0].isBlank() && p1[0].equals(p2[0]);
    }

    static TransitiveConflictFinding findMatchingConflict(Map<String, List<TransitiveConflictFinding>> conflictsByKey, ScanComponent component) {
        if (conflictsByKey == null || component == null || component.coordinate() == null) {
            return null;
        }
        String key = component.coordinate().groupId() + ":" + component.coordinate().artifactId();
        List<TransitiveConflictFinding> conflicts = conflictsByKey.get(key);
        if (conflicts == null || conflicts.isEmpty()) {
            return null;
        }
        String currentVersion = component.version();
        if (currentVersion != null && !currentVersion.isBlank()) {
            for (TransitiveConflictFinding conflict : conflicts) {
                if (currentVersion.equals(conflict.resolvedVersion())) {
                    return conflict;
                }
            }
        }
        return conflicts.get(0);
    }

    /** How many older releases the version-selector dropdown offers below the current version.
     *  Read fresh on each call (cheap) rather than cached, so it can be changed without a
     *  restart. Defaults to 10; override with -Dredkite.version.lookback=N. */
    static int versionLookbackLimit() {
        try {
            return Integer.parseInt(System.getProperty("redkite.version.lookback", "10"));
        } catch (NumberFormatException e) {
            return 10;
        }
    }

    static boolean isPreRelease(String version) {
        if (version == null || version.isBlank()) return false;
        String v = version.toLowerCase();
        return v.contains("snapshot") || v.contains("alpha") || v.contains("beta")
                || v.matches(".*[.\\-]rc\\d*([.\\-].*)?")
                || v.matches(".*[.\\-]m\\d+([.\\-].*)?")
                || v.contains("milestone") || v.contains("preview") || v.contains("incubat")
                || v.matches(".*[.\\-]cr\\d*([.\\-].*)?");
    }

    static boolean isMajorUpgrade(String currentVersion, String targetVersion) {
        return major(currentVersion) < major(targetVersion);
    }

    static int major(String version) {
        return parseVersionPart(version, 0);
    }

    static int minor(String version) {
        return parseVersionPart(version, 1);
    }

    private static int parseVersionPart(String version, int index) {
        if (version == null) {
            return 0;
        }
        String[] parts = version.replace('_', '.').split("[.-]");
        if (index >= parts.length) {
            return 0;
        }
        try {
            String token = parts[index].replaceAll("[^0-9].*$", "");
            if (token.isBlank()) {
                return 0;
            }
            return Integer.parseInt(token);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    static int compareVersions(String left, String right) {
        String[] leftParts = normalizeVersion(left).split("\\.");
        String[] rightParts = normalizeVersion(right).split("\\.");
        int max = Math.max(leftParts.length, rightParts.length);
        for (int i = 0; i < max; i++) {
            int leftPart = i < leftParts.length ? parsePart(leftParts[i]) : 0;
            int rightPart = i < rightParts.length ? parsePart(rightParts[i]) : 0;
            if (leftPart != rightPart) {
                return Integer.compare(leftPart, rightPart);
            }
        }
        return 0;
    }

    private static String normalizeVersion(String version) {
        if (version == null || version.isBlank()) {
            return "0";
        }
        return version.trim().replace('-', '.').replace('_', '.');
    }

    private static int parsePart(String part) {
        try {
            String digits = part.replaceAll("[^0-9].*$", "");
            if (digits.isBlank()) {
                return 0;
            }
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
