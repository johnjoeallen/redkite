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
}
