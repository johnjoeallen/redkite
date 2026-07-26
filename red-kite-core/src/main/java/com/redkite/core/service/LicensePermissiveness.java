package com.redkite.core.service;

import java.util.List;
import java.util.Map;

/**
 * Picks the most permissive of a component's declared licenses, given a configured rank map
 * (lower rank = more permissive) keyed by {@link LicenseNormalizer} canonical labels. Kept separate
 * from any I/O so the picking logic itself — not the DB-backed rank storage — is what's tested.
 */
public final class LicensePermissiveness {
    private LicensePermissiveness() {
    }

    /** The raw license string (exactly as declared) among {@code rawLicenses} whose canonicalized
     *  form has the lowest configured rank — or {@code null} if there's only one license to begin
     *  with (nothing to pick over), the list is empty, or none of the declared licenses have a
     *  configured rank at all. A license with no configured rank is simply never picked, rather
     *  than being treated as either the most or least permissive by default. */
    public static String mostPermissive(List<String> rawLicenses, Map<String, Integer> ranksByCanonical) {
        if (rawLicenses == null || rawLicenses.size() < 2 || ranksByCanonical == null) return null;
        String best = null;
        int bestRank = Integer.MAX_VALUE;
        for (String raw : rawLicenses) {
            Integer rank = ranksByCanonical.get(LicenseNormalizer.canonicalize(raw));
            if (rank != null && rank < bestRank) {
                bestRank = rank;
                best = raw;
            }
        }
        return best;
    }
}
