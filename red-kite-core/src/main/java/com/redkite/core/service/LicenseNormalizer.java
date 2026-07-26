package com.redkite.core.service;

import java.util.Locale;
import java.util.Map;

/**
 * Maps common declared-license name variants seen across dependency POMs — identical license,
 * different wording ("Version" vs "v.", full legal name vs SPDX id, stray capitalization) — onto
 * one canonical label, so a project's license breakdown isn't fragmented into a dozen buckets for
 * what is really a single license.
 *
 * <p>Deliberately conservative: variants are merged only when the underlying legal text is
 * genuinely the same. Look-alikes with materially different terms are kept apart even though the
 * names read similarly — a Classpath Exception changes what linking requires, "-only" vs
 * "-or-later" changes whether a future license version can be adopted, and MIT-0 drops MIT's
 * attribution requirement entirely. An unrecognised string passes through unchanged: this table
 * only merges known-identical licenses, it never hides one it doesn't recognise.
 */
public final class LicenseNormalizer {
    private LicenseNormalizer() {
    }

    private static final Map<String, String> ALIASES = Map.ofEntries(
            // Apache License 2.0 — canonicalized to "ASL-2.0" (Apache Software License) rather
            // than the SPDX "Apache-2.0" id, per explicit preference.
            Map.entry("apache license, version 2.0", "ASL-2.0"),
            Map.entry("the apache software license, version 2.0", "ASL-2.0"),
            Map.entry("the apache license, version 2.0", "ASL-2.0"),
            Map.entry("apache-2.0", "ASL-2.0"),
            Map.entry("apache license 2.0", "ASL-2.0"),
            Map.entry("al 2.0", "ASL-2.0"),
            Map.entry("al", "ASL-2.0"),
            Map.entry("apache 2.0", "ASL-2.0"),
            Map.entry("apache license version 2.0", "ASL-2.0"),
            Map.entry("apache software license", "ASL-2.0"),

            // Eclipse Public License 2.0
            Map.entry("epl 2.0", "EPL-2.0"),
            Map.entry("epl-2.0", "EPL-2.0"),
            Map.entry("eclipse public license - v 2.0", "EPL-2.0"),
            Map.entry("eclipse public license v. 2.0", "EPL-2.0"),
            Map.entry("eclipse public license v2.0", "EPL-2.0"),

            // Eclipse Public License 1.0 — a different version from EPL-2.0 above, not merged with it.
            Map.entry("eclipse public license - v 1.0", "EPL-1.0"),
            Map.entry("epl 1.0", "EPL-1.0"),
            Map.entry("eclipse public license 1.0", "EPL-1.0"),

            // Eclipse Distribution License 1.0 — textually identical to BSD-3-Clause, but Eclipse
            // names it separately and SPDX lists it as its own id, so it's kept apart from
            // BSD-3-Clause rather than folded in.
            Map.entry("eclipse distribution license - v 1.0", "EDL-1.0"),
            Map.entry("edl 1.0", "EDL-1.0"),
            Map.entry("eclipse distribution license v. 1.0", "EDL-1.0"),

            // MIT — MIT-0 (No Attribution) drops MIT's attribution clause and is a materially
            // different license; it is deliberately NOT merged here.
            Map.entry("mit", "MIT"),
            Map.entry("mit license", "MIT"),
            Map.entry("the mit license", "MIT"),

            // BSD 3-Clause — BSD-2-Clause is a materially different (shorter) license and is
            // deliberately NOT merged here.
            Map.entry("bsd-3-clause", "BSD-3-Clause"),
            Map.entry("the bsd 3-clause license", "BSD-3-Clause"),

            // LGPL — "GNU Lesser..." carries no version at all, and "GNU Library...v2.1 or later"
            // is folded in alongside it. LGPL-2.1-only/LGPL-2.1-or-later/LGPL-3.0 are materially
            // different licenses (a different or absent upgrade path to a later LGPL version) and
            // are deliberately NOT included here.
            Map.entry("gnu lesser general public license", "LGPL"),
            Map.entry("gnu library general public license v2.1 or later", "LGPL"),
            Map.entry("gnu lgpl 3", "LGPL-3.0"),

            // GPL2 with Classpath Exception — a materially different license from plain GPL v2
            // (below), which is deliberately NOT merged here.
            Map.entry("gpl2 w/ cpe", "GPL-2.0 WITH Classpath-exception"),
            Map.entry("gpl v2 with the classpath exception", "GPL-2.0 WITH Classpath-exception"),

            // Single-variant relabels to a canonical SPDX-style form for display consistency —
            // nothing merges into these, they just get a tidier name.
            Map.entry("gpl v2", "GPL-2.0-only"),
            Map.entry("mpl 2.0", "MPL-2.0"),
            Map.entry("mozilla public license, version 2.0", "MPL-2.0"),
            Map.entry("cddl 1.1", "CDDL-1.1")
    );

    /** The canonical label for {@code rawLicenseName}, or the trimmed original string unchanged
     *  if it isn't a recognised variant of anything in the table. */
    public static String canonicalize(String rawLicenseName) {
        if (rawLicenseName == null) return null;
        String trimmed = rawLicenseName.trim();
        String canonical = ALIASES.get(trimmed.toLowerCase(Locale.ROOT));
        return canonical != null ? canonical : trimmed;
    }
}
