package com.redkite.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Rewriting POM versions into properties, pins and upgrades. */
class PomPatcherTest {
    // ---------------------------------------------------------------- patchPomXml

    private static String patch(String pom, Map<String, String> updates) throws Exception {
        return PomPatcher.patchPomXml(pom, updates);
    }

    private static String squash(String xml) {
        return xml.replaceAll(">\\s+<", "><").trim();
    }

    @Test
    void literalVersionsBecomePropertiesAndUpgradesApply() throws Exception {
        String out = squash(patch("""
                <project><artifactId>app</artifactId>
                  <dependencies>
                    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>b</artifactId><version>2.0</version></dependency>
                  </dependencies>
                </project>""", Map.of("g:a", "1.5")));

        assertTrue(out.contains("<properties><a.version>1.5</a.version><b.version>2.0</b.version></properties><dependencies>"), out);
        assertTrue(out.contains("<artifactId>a</artifactId><version>${a.version}</version>"), out);
        assertTrue(out.contains("<artifactId>b</artifactId><version>${b.version}</version>"), out);
    }

    @Test
    void existingPropertyReferencesAreUpdatedInPlace() throws Exception {
        String out = squash(patch("""
                <project>
                  <properties><lib.version>1.0</lib.version><keep>x</keep></properties>
                  <dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${lib.version}</version></dependency></dependencies>
                </project>""", Map.of("g:a", "2.0")));

        assertTrue(out.contains("<properties><lib.version>2.0</lib.version><keep>x</keep></properties>"), out);
        assertTrue(out.contains("<version>${lib.version}</version>"), out);
    }

    @Test
    void sharedPropertyWithDifferentTargetsIsSplit() throws Exception {
        String out = squash(patch("""
                <project>
                  <properties><shared.version>1.0</shared.version></properties>
                  <dependencies>
                    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${shared.version}</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>b</artifactId><version>${shared.version}</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>c</artifactId><version>${shared.version}</version></dependency>
                  </dependencies>
                </project>""", Map.of("g:a", "2.0", "g:b", "3.0", "g:c", "2.0")));

        assertTrue(out.contains("<shared.version>2.0</shared.version>"), out);
        assertTrue(out.contains("<b.version>3.0</b.version>"), out);
        assertTrue(out.contains("<artifactId>b</artifactId><version>${b.version}</version>"), out);
        assertTrue(out.contains("<artifactId>c</artifactId><version>${shared.version}</version>"), out);
    }

    @Test
    void managedDependencyGetsAnExplicitVersionOnlyWhenUpgraded() throws Exception {
        String pom = """
                <project>
                  <dependencies>
                    <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
                    <dependency><groupId>g</groupId><artifactId>b</artifactId></dependency>
                  </dependencies>
                </project>""";
        String out = squash(patch(pom, Map.of("g:a", "4.0")));
        assertTrue(out.contains("<artifactId>a</artifactId><version>4.0</version></dependency>"), out);
        assertTrue(out.contains("<artifactId>b</artifactId></dependency>"), out);
        assertFalse(out.contains("<properties>"), out);
    }

    @Test
    void pinningAManagedDependencyWritesAPinnedProperty() throws Exception {
        String out = squash(PomPatcher.patchPomXml("""
                <project><build/>
                  <dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId></dependency></dependencies>
                </project>""", Map.of("g:a", "4.0"), Set.of("g:a"), Set.of()));

        assertTrue(out.contains("<!-- redkite:user-pin version=\"4.0\""), out);
        assertTrue(out.contains("--><a.version>4.0</a.version>"), out);
        assertTrue(out.contains("<artifactId>a</artifactId><version>${a.version}</version>"), out);
    }

    @Test
    void pinAndUnpinExistingProperties() throws Exception {
        String pom = """
                <project>
                  <properties>
                    <!-- redkite:user-pin version="1.0" — old -->
                    <a.version>1.0</a.version>
                    <b.version>2.0</b.version>
                  </properties>
                  <dependencies>
                    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${a.version}</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>b</artifactId><version>${b.version}</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>c</artifactId><version>${missing.version}</version></dependency>
                  </dependencies>
                </project>""";

        String unpinned = squash(PomPatcher.patchPomXml(pom, Map.of(), Set.of("g:b", "g:c"), Set.of("g:a")));
        assertFalse(unpinned.contains("user-pin version=\"1.0\""), unpinned);
        assertTrue(unpinned.contains("<!-- redkite:user-pin version=\"2.0\" — user pinned"), unpinned);

        String repinned = squash(PomPatcher.patchPomXml(pom, Map.of("g:a", "1.1"), Set.of("g:a"), Set.of()));
        assertTrue(repinned.contains("<!-- redkite:user-pin version=\"1.1\" — user pinned"), repinned);
        assertEquals(1, repinned.split("redkite:user-pin", -1).length - 1, "the existing marker is updated, not duplicated");
    }

    @Test
    void pinningALiteralVersion() throws Exception {
        String out = squash(PomPatcher.patchPomXml("""
                <project><dependencies>
                  <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
                </dependencies></project>""", Map.of(), Set.of("g:a"), Set.of()));
        assertTrue(out.contains("<!-- redkite:user-pin version=\"1.0\""), out);
        assertTrue(out.contains("<a.version>1.0</a.version>"), out);
    }

    @Test
    void parentVersionStaysLiteral() throws Exception {
        String pom = """
                <project>
                  <parent><groupId>p</groupId><artifactId>parent</artifactId><version>${parent.version}</version></parent>
                  <properties><parent.version>1</parent.version></properties>
                </project>""";
        String out = squash(patch(pom, Map.of("p:parent", "2")));
        assertTrue(out.contains("<parent><groupId>p</groupId><artifactId>parent</artifactId><version>2</version></parent>"), out);
        assertTrue(squash(patch(pom, Map.of())).contains("<version>${parent.version}</version>"));
    }

    @Test
    void pluginsWithoutGroupIdUseTheDefaultPluginGroup() throws Exception {
        String out = squash(patch("""
                <project><build><plugins>
                  <plugin><groupId></groupId><artifactId>maven-compiler-plugin</artifactId><version>3.10</version></plugin>
                </plugins></build></project>""", Map.of("org.apache.maven.plugins:maven-compiler-plugin", "3.11")));
        assertTrue(out.contains("<maven-compiler-plugin.version>3.11</maven-compiler-plugin.version>"), out);
        assertTrue(out.indexOf("<properties>") < out.indexOf("<build>"), "properties go before build");
    }

    @Test
    void redkitePinsKeepLiteralVersionsAndAreUpdatedWithTheirMarker() throws Exception {
        String pom = """
                <project><dependencyManagement><dependencies>
                  <!-- redkite:dependency-management pin groupId="g" artifactId="a" version="1.0" reason="x" -->
                  <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
                  <!-- redkite:dependency-management pin groupId="g" artifactId="b" version="1.0" reason="x" -->
                  <dependency><groupId>g</groupId><artifactId>b</artifactId><version>1.0</version></dependency>
                  <!-- redkite:user-pin groupId="g" artifactId="c" -->
                  <dependency><groupId>g</groupId><artifactId>c</artifactId></dependency>
                </dependencies></dependencyManagement></project>""";
        String out = squash(patch(pom, Map.of("g:a", "2.0", "g:b", "1.0", "g:c", "5")));
        assertTrue(out.contains("artifactId=\"a\" version=\"2.0\""), out);
        assertTrue(out.contains("<artifactId>a</artifactId><version>2.0</version>"), out);
        assertTrue(out.contains("artifactId=\"b\" version=\"1.0\""), out);
        assertTrue(out.contains("<artifactId>c</artifactId></dependency>"), "a pin without a version is left alone");
        assertFalse(out.contains("<properties>"), out);
    }

    @Test
    void orphanedVersionPropertiesAreDroppedUnlessInUse() throws Exception {
        String pom = """
                <project>
                  <properties>
                    <!-- redkite:user-pin version="1" — x -->
                    <orphan.version>1</orphan.version>
                    <active.version>2</active.version>
                    <used.version>3</used.version>
                    <maven.compiler.release>17</maven.compiler.release>
                  </properties>
                  <dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${used.version}</version></dependency></dependencies>
                </project>""";
        String out = squash(PomPatcher.patchPomXml(pom, Map.of(), Set.of(), Set.of(), Set.of("active.version")));
        assertFalse(out.contains("orphan.version"), out);
        assertFalse(out.contains("redkite:user-pin"), "the orphan's pin marker goes with it");
        assertTrue(out.contains("<active.version>2</active.version>"), out);
        assertTrue(out.contains("<used.version>3</used.version>"), out);
        assertTrue(out.contains("<maven.compiler.release>17</maven.compiler.release>"), out);

        String aggregator = squash(patch(pom.replace("<project>", "<project><packaging>pom</packaging>"), Map.of()));
        assertTrue(aggregator.contains("<orphan.version>1</orphan.version>"), "parent POMs keep properties for their children");
    }

    @Test
    void reservedPropertyNamesAreNotShadowed() throws Exception {
        String pom = """
                <project><dependencies>
                  <dependency><groupId>com.x</groupId><artifactId>a</artifactId><version>1</version></dependency>
                  <dependency><groupId>com.y</groupId><artifactId>b</artifactId><version>1</version></dependency>
                </dependencies></project>""";
        String out = squash(PomPatcher.patchPomXml(pom, Map.of(), Set.of(), Set.of(), Set.of(),
                Set.of("a.version", "b.version", "com.y.b.version")));
        assertTrue(out.contains("<com.x.a.version>1</com.x.a.version>"), out);
        assertTrue(out.contains("<com.y.b.version>1</com.y.b.version>"), out);
    }

    @Test
    void sameArtifactIdInTwoGroupsGetsDistinctProperties() throws Exception {
        String out = squash(patch("""
                <project><dependencies>
                  <dependency><groupId>one</groupId><artifactId>core</artifactId><version>1</version></dependency>
                  <dependency><groupId>two</groupId><artifactId>core</artifactId><version>2</version></dependency>
                </dependencies></project>""", Map.of()));
        assertTrue(out.contains("<core.version>1</core.version>"), out);
        assertTrue(out.contains("<two.core.version>2</two.core.version>"), out);
    }

    @Test
    void incompleteDeclarationsAreLeftAlone() throws Exception {
        String out = squash(patch("""
                <project>
                  <dependencies>
                    <dependency><artifactId>no-group</artifactId><version>1</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>blank</artifactId><version> </version></dependency>
                  </dependencies>
                </project>""", Map.of("g:blank", "2")));
        assertTrue(out.contains("<artifactId>no-group</artifactId><version>1</version>"), out);
        assertTrue(out.contains("<artifactId>blank</artifactId><version/>") || out.contains("<version> </version>")
                || out.contains("<version></version>"), out);
        assertTrue(squash(patch("<project/>", Map.of())).endsWith("<project/>"));
    }

    @Test
    void propertiesAreCreatedAtTheTopLevelEvenWhenDependenciesOnlyExistInAProfile() throws Exception {
        String pom = "<project><modelVersion>4.0.0</modelVersion><profiles><profile><id>p</id><dependencies>"
                + "<dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency>"
                + "</dependencies></profile></profiles></project>";
        String patched = PomPatcher.patchPomXml(pom, Map.of("g:a", "2"));
        assertTrue(patched.contains("<properties>"), patched);
        assertTrue(patched.contains("<a.version>2</a.version>"), patched);
        assertTrue(patched.indexOf("</profiles>") < patched.indexOf("<properties>"), "appended directly under <project>: " + patched);
        assertTrue(patched.contains("<version>${a.version}</version>"), patched);
    }

    @Test
    void cornerCasesInDeclarationsAndRedkitePins() throws Exception {
        String pom = """
                <project>
                  <dependencyManagement><dependencies>
                    <!-- redkite:dependency-management pin groupId="g" artifactId="pinned" version="1" -->
                    <dependency><groupId>g</groupId><artifactId>pinned</artifactId><version>1</version></dependency>
                    <!-- redkite:dependency-management pin groupId="g" artifactId="versionless" -->
                    <dependency><groupId>g</groupId><artifactId>versionless</artifactId></dependency>
                    <!-- redkite:dependency-management pin artifactId="no-group" -->
                    <dependency><artifactId>no-group</artifactId><version>1</version></dependency>
                  </dependencies></dependencyManagement>
                  <dependencies>
                    <dependency><groupId>g</groupId><artifactId>blank</artifactId><version> </version></dependency>
                    <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
                    <dependency><groupId>g</groupId><artifactId>prop</artifactId><version>${inherited.version}</version></dependency>
                  </dependencies>
                </project>
                """;
        Map<String, String> updates = new java.util.LinkedHashMap<>();
        updates.put("g:pinned", "1");
        updates.put("g:versionless", "2");
        updates.put("g:blank", "3");
        updates.put("g:managed", "4");
        String patched = PomPatcher.patchPomXml(pom, updates, Set.of("g:prop"), Set.of("g:managed"));
        assertTrue(patched.contains("<artifactId>pinned</artifactId>\n        <version>1</version>"), "an unchanged pin is left as is: " + patched);
        assertTrue(patched.contains("<artifactId>versionless</artifactId>\n      </dependency>"), patched);
        assertTrue(patched.contains("<artifactId>blank</artifactId>\n      <version/>"), "a blank version is left alone: " + patched);
        assertTrue(patched.contains("<managed.version>4</managed.version>"), "an unpinned managed dependency still gets a property: " + patched);
        assertFalse(patched.contains("redkite:user-pin version=\"4\""), patched);
        assertFalse(patched.contains("redkite:user-pin"), "a property this POM doesn't declare has nothing to mark: " + patched);
        assertTrue(patched.contains("<version>${inherited.version}</version>"), patched);
    }
}
