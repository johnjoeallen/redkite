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

/** Text lookups over stored POM XML. */
class PomXmlTest {
    // ---------------------------------------------------------------- POM text helpers

    @Test
    void depManagementVersionLookupResolvesLocalProperties() {
        String pom = """
                <project><properties><lib.version>2.5</lib.version></properties>
                <dependencyManagement><dependencies>
                  <dependency><groupId>g</groupId><artifactId>other</artifactId><version>1</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>lib</artifactId><version>${lib.version}</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>lit</artifactId><version> 3.0 </version></dependency>
                  <dependency><groupId>g</groupId><artifactId>unknown</artifactId><version>${nope}</version></dependency>
                  <dependency><groupId>g</groupId><artifactId>nover</artifactId></dependency>
                </dependencies></dependencyManagement></project>""";
        assertEquals("2.5", PomXml.extractDepMgmtVersion(pom, "g", "lib"));
        assertEquals("3.0", PomXml.extractDepMgmtVersion(pom, "g", "lit"));
        assertNull(PomXml.extractDepMgmtVersion(pom, "g", "unknown"));
        assertNull(PomXml.extractDepMgmtVersion(pom, "g", "nover"));
        assertNull(PomXml.extractDepMgmtVersion(pom, "g", "absent"));
        assertNull(PomXml.extractDepMgmtVersion("<project/>", "g", "lib"));
        assertNull(PomXml.extractDepMgmtVersion("<dependencyManagement><dependency>", "g", "lib"));
        assertNull(PomXml.extractDepMgmtVersion("</dependencyManagement><dependencyManagement>", "g", "lib"));

        assertEquals("1", PomXml.resolvePomPropertyRef("<properties><p>1</p></properties>", "1"));
        assertNull(PomXml.resolvePomPropertyRef("<properties><p>1</p></properties>", null));
        assertNull(PomXml.resolvePomPropertyRef("<project/>", "${p}"));
        assertNull(PomXml.resolvePomPropertyRef("<properties><p>1</properties>", "${p}"));
        assertEquals("${p", PomXml.resolvePomPropertyRef("<properties/>", "${p"));
    }

    @Test
    void moduleLabelsAndArtifactIds() {
        Map<String, String> poms = new LinkedHashMap<>();
        poms.put("pom.xml", "<project><parent><artifactId>p</artifactId></parent><artifactId>root</artifactId></project>");
        poms.put("sub/pom.xml", "<project><parent><artifactId>root</artifactId></parent></project>");
        poms.put("other.xml", "<project><artifactId>unterminated");
        assertEquals(Map.of("pom.xml", "root", "sub/pom.xml", "sub", "other.xml", "other.xml"),
                PomXml.buildModuleArtifactIds(poms));
        assertEquals("(root)", PomXml.modulePathLabel("pom.xml"));
        assertEquals("(root)", PomXml.modulePathLabel("(root)"));
        assertEquals("a/b", PomXml.modulePathLabel("a/b/pom.xml"));
        assertNull(PomXml.extractArtifactId("<project/>"));
    }

    @Test
    void rootPomIsTheShallowestPom() {
        assertEquals("root", PomXml.rootPomXml(Map.of("pom.xml", "root", "a/pom.xml", "a")));
        Map<String, String> nested = new LinkedHashMap<>();
        nested.put("x/y/pom.xml", "deep");
        nested.put("x/pom.xml", "shallow");
        nested.put("notes.txt", "no");
        assertEquals("shallow", PomXml.rootPomXml(nested));
        assertEquals("", PomXml.rootPomXml(Map.of("readme", "x")));
    }

    @Test
    void lookupsFindTagsAtTheVeryStartOfTheText() {
        assertEquals("1", PomXml.extractDepMgmtVersion(
                "<dependencyManagement><dependency><groupId>g</groupId><artifactId>a</artifactId>"
                        + "<version>1</version></dependency></dependencyManagement>", "g", "a"));
        assertEquals("1", PomXml.resolvePomPropertyRef("<properties><p>1</p></properties>", "${p}"));
        assertEquals("x", PomXml.extractArtifactId("<artifactId>x</artifactId>"));
    }

    @Test
    void rootPomKeepsTheFirstOfEquallyShallowPoms() {
        Map<String, String> poms = new LinkedHashMap<>();
        poms.put("a/pom.xml", "first");
        poms.put("b/pom.xml", "second");
        assertEquals("first", PomXml.rootPomXml(poms));
    }

    @Test
    void selectRootPomKeyPrefersFewestDirectoriesThenShortestPath() {
        assertEquals("pom.xml", PomXml.selectRootPomKey(Map.of("a/pom.xml", "", "pom.xml", ""), "/w"));

        Map<String, String> poms = new LinkedHashMap<>();
        poms.put("notes.txt", "");
        poms.put("a/b/pom.xml", "");
        poms.put("long-name/pom.xml", "");
        poms.put("ab/pom.xml", "");
        poms.put("abc/pom.xml", "");
        poms.put("xy/pom.xml", "");
        assertEquals("ab/pom.xml", PomXml.selectRootPomKey(poms, "/w"));
        Map<String, String> depthBeatsLength = new LinkedHashMap<>();
        depthBeatsLength.put("a/b/pom.xml", "");
        depthBeatsLength.put("long-name/pom.xml", "");
        assertEquals("long-name/pom.xml", PomXml.selectRootPomKey(depthBeatsLength, "/w"));

        Map<String, String> noPoms = new LinkedHashMap<>();
        noPoms.put("x.txt", "");
        noPoms.put("y.txt", "");
        assertEquals("x.txt", PomXml.selectRootPomKey(noPoms, "/w"));
        assertNull(PomXml.selectRootPomKey(Map.of(), "/w"));
    }

    @Test
    void fileReadsReturnContentOrAFallback(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("pom.xml");
        Files.writeString(file, "<project/>");
        assertEquals("<project/>", PomXml.readFileQuietly(file));
        assertEquals("", PomXml.readFileQuietly(dir.resolve("missing.xml")));
        assertEquals("<project/>", PomXml.readIfExists(file));
        assertNull(PomXml.readIfExists(dir.resolve("missing.xml")));
        assertNull(PomXml.readIfExists(dir));
    }
}
