package com.redkite.core.service;

import java.util.List;

/**
 * Default permissiveness ordering (most permissive first) for the licenses {@link
 * LicenseNormalizer} commonly produces. Purely a starting point: RedKite's /config page lets any
 * of these be reordered, and lets a license not listed here be added — this is only the seed data
 * used the first time the ranking table is populated.
 *
 * <p>Deliberately a judgment call — is EPL more or less permissive than MPL? Reasonable people
 * differ — configurability is the point of this feature, not this specific ordering.
 */
public final class LicensePermissivenessDefaults {
    private LicensePermissivenessDefaults() {
    }

    public static final List<String> DEFAULT_ORDER = List.of(
            "Public Domain, per Creative Commons CC0",
            "MIT-0",
            "MIT",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "EDL-1.0",
            "ASL-2.0",
            "MPL-2.0",
            "EPL-1.0",
            "CDDL-1.1",
            "EPL-2.0",
            "LGPL-2.1-or-later",
            "LGPL-2.1-only",
            "LGPL-3.0",
            "LGPL",
            "GPL-2.0 WITH Classpath-exception",
            "GPL-2.0-only"
    );
}
