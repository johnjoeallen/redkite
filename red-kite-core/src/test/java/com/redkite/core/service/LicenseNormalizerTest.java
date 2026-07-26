package com.redkite.core.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class LicenseNormalizerTest {

    @Test
    void apacheVariantsAllCanonicalizeToAsl() {
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("Apache License, Version 2.0"));
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("The Apache Software License, Version 2.0"));
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("The Apache License, Version 2.0"));
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("Apache-2.0"));
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("Apache License 2.0"));
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("AL 2.0"));
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("Apache 2.0"));
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("Apache License Version 2.0"));
        // Case-insensitive: differs only by capitalization from an already-listed variant.
        assertEquals("ASL-2.0", LicenseNormalizer.canonicalize("Apache License, version 2.0"));
    }

    @Test
    void eplVersionsAreNotConflated() {
        assertEquals("EPL-2.0", LicenseNormalizer.canonicalize("EPL 2.0"));
        assertEquals("EPL-2.0", LicenseNormalizer.canonicalize("EPL-2.0"));
        assertEquals("EPL-2.0", LicenseNormalizer.canonicalize("Eclipse Public License - v 2.0"));
        assertEquals("EPL-2.0", LicenseNormalizer.canonicalize("Eclipse Public License v. 2.0"));
        assertEquals("EPL-2.0", LicenseNormalizer.canonicalize("Eclipse Public License v2.0"));
        assertEquals("EPL-1.0", LicenseNormalizer.canonicalize("Eclipse Public License - v 1.0"));
        assertEquals("EPL-1.0", LicenseNormalizer.canonicalize("EPL 1.0"));
        assertEquals("EPL-1.0", LicenseNormalizer.canonicalize("Eclipse Public License 1.0"));
    }

    @Test
    void edlIsKeptSeparateFromBsd3Clause() {
        assertEquals("EDL-1.0", LicenseNormalizer.canonicalize("Eclipse Distribution License - v 1.0"));
        assertEquals("EDL-1.0", LicenseNormalizer.canonicalize("EDL 1.0"));
        assertEquals("EDL-1.0", LicenseNormalizer.canonicalize("Eclipse Distribution License v. 1.0"));
        // Passes through unchanged — never merged with EDL-1.0 despite identical underlying text.
        assertEquals("BSD-3-Clause", LicenseNormalizer.canonicalize("BSD-3-Clause"));
    }

    @Test
    void mitAndMitZeroAreNotConflated() {
        assertEquals("MIT", LicenseNormalizer.canonicalize("MIT"));
        assertEquals("MIT", LicenseNormalizer.canonicalize("MIT License"));
        assertEquals("MIT", LicenseNormalizer.canonicalize("The MIT License"));
        // MIT-0 (No Attribution) is a materially different license — passes through unchanged.
        assertEquals("MIT-0", LicenseNormalizer.canonicalize("MIT-0"));
    }

    @Test
    void bsd3ClauseAndBsd2ClauseAreNotConflated() {
        assertEquals("BSD-3-Clause", LicenseNormalizer.canonicalize("BSD-3-Clause"));
        assertEquals("BSD-3-Clause", LicenseNormalizer.canonicalize("The BSD 3-Clause License"));
        // BSD-2-Clause is a materially different (shorter) license — passes through unchanged.
        assertEquals("BSD-2-Clause", LicenseNormalizer.canonicalize("BSD-2-Clause"));
    }

    @Test
    void lgplLesserAndLibraryFoldTogetherButNotOtherVersions() {
        assertEquals("LGPL", LicenseNormalizer.canonicalize("GNU Lesser General Public License"));
        assertEquals("LGPL", LicenseNormalizer.canonicalize("GNU Library General Public License v2.1 or later"));
        // "-only" vs "-or-later" vs "3.0" are materially different licenses — never merged into LGPL.
        assertEquals("LGPL-2.1-only", LicenseNormalizer.canonicalize("LGPL-2.1-only"));
        assertEquals("LGPL-2.1-or-later", LicenseNormalizer.canonicalize("LGPL-2.1-or-later"));
        assertEquals("LGPL-3.0", LicenseNormalizer.canonicalize("GNU LGPL 3"));
    }

    @Test
    void gplWithClasspathExceptionIsNotConflatedWithPlainGpl() {
        assertEquals("GPL-2.0-only", LicenseNormalizer.canonicalize("GPL v2"));
        assertEquals("GPL-2.0 WITH Classpath-exception", LicenseNormalizer.canonicalize("GPL2 w/ CPE"));
        assertEquals("GPL-2.0 WITH Classpath-exception", LicenseNormalizer.canonicalize("GPL v2 with the Classpath exception"));
    }

    @Test
    void mplVariantsCanonicalizeTheSame() {
        assertEquals("MPL-2.0", LicenseNormalizer.canonicalize("MPL 2.0"));
        assertEquals("MPL-2.0", LicenseNormalizer.canonicalize("Mozilla Public License, Version 2.0"));
    }

    @Test
    void cddlIsRelabeledButNotMergedWithDualLicenseVariant() {
        assertEquals("CDDL-1.1", LicenseNormalizer.canonicalize("CDDL 1.1"));
        // The GPLv2-classpath dual-license combo string is a distinct thing, left untouched.
        assertEquals("CDDL/GPLv2+CE", LicenseNormalizer.canonicalize("CDDL/GPLv2+CE"));
    }

    @Test
    void unrecognisedStringPassesThroughUnchangedButTrimmed() {
        assertEquals("Some Totally Unknown License", LicenseNormalizer.canonicalize("  Some Totally Unknown License  "));
    }

    @Test
    void nullPassesThroughAsNull() {
        assertNull(LicenseNormalizer.canonicalize(null));
    }
}
