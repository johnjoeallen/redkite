package com.redkite.maven;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScanExcludesTest {
    @Test
    void excludesTheFolderAndEverythingBelowIt(@TempDir Path root) {
        ScanExcludes e = ScanExcludes.of(java.util.Arrays.asList(" ", null, "/test/projects/", "./sample", "."));
        assertEquals(List.of("test/projects", "sample"), e.entries());
        assertTrue(e.excludes(root, root.resolve("test/projects/fx/pom.xml")));
        assertTrue(e.excludes(root, Path.of("test/projects")));
        assertTrue(e.excludes(root, Path.of("sample/pom.xml")));
    }

    @Test
    void matchesWholePathSegmentsOnly(@TempDir Path root) {
        ScanExcludes e = ScanExcludes.of(List.of("test"));
        assertFalse(e.excludes(root, Path.of("testing/pom.xml")));
        assertFalse(e.excludes(root, Path.of("src/test/pom.xml")));
        assertTrue(e.excludes(root, Path.of("test/pom.xml")));
    }

    @Test
    void nullOrEmptyExcludesNothing() {
        assertTrue(ScanExcludes.of(null).isEmpty());
        assertTrue(ScanExcludes.of(List.of()).isEmpty());
        assertFalse(ScanExcludes.none().excludes(Path.of("/r"), Path.of("a/pom.xml")));
    }

    @Test
    void readsExcludesFromThePluginConfigurationInThePom(@TempDir Path root) throws Exception {
        java.nio.file.Files.writeString(root.resolve("pom.xml"), "<project><build><pluginManagement><plugins>"
                + "<plugin><groupId>other</groupId><artifactId>other-plugin</artifactId>"
                + "<configuration><excludes><exclude>nope</exclude></excludes></configuration></plugin>"
                + "<plugin><groupId>net.dublinux.redkite</groupId><artifactId>red-kite-maven-plugin</artifactId>"
                + "<configuration><excludes><exclude>test/projects</exclude><exclude>samples/</exclude></excludes>"
                + "</configuration></plugin></plugins></pluginManagement></build></project>");
        assertEquals(List.of("test/projects", "samples"), ScanExcludes.fromPom(root).entries());
        assertTrue(ScanExcludes.fromPom(root.resolve("missing")).isEmpty());
    }
}
