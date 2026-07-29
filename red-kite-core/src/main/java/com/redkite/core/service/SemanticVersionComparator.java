package com.redkite.core.service;

public final class SemanticVersionComparator {
    private SemanticVersionComparator() {
    }

    public static int compare(String a, String b) {
        if (a == null) return b == null ? 0 : -1;
        if (b == null) return 1;
        String[] pa = a.replace('-', '.').split("\\.");
        String[] pb = b.replace('-', '.').split("\\.");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            String sa = i < pa.length ? pa[i] : "0";
            String sb = i < pb.length ? pb[i] : "0";
            try {
                int diff = Integer.compare(Integer.parseInt(sa), Integer.parseInt(sb));
                if (diff != 0) return diff;
            } catch (NumberFormatException e) {
                int diff = sa.compareTo(sb);
                if (diff != 0) return diff;
            }
        }
        return 0;
    }

    /** Whether two versions share a release line (equal first two version tokens, e.g. "1.5"). */
    public static boolean sameReleaseLine(String a, String b) {
        return releaseLineOf(a).equals(releaseLineOf(b));
    }

    private static String releaseLineOf(String version) {
        String[] tokens = version.split("[.\\-]");
        String major = tokens.length > 0 ? tokens[0] : "0";
        String minor = tokens.length > 1 ? tokens[1] : "0";
        return major + "." + minor;
    }
}
