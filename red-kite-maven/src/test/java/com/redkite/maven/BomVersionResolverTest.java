package com.redkite.maven;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class BomVersionResolverTest {

    @Test
    void resolvesBomMembersAtDifferentPatchVersions() {
        // Shaped exactly like the real Jackson 2.22.1 BOM: jackson-core/jackson-databind managed
        // via a property chain that bottoms out at 2.22.1, jackson-annotations managed literally
        // at 2.22 — no patch digit. The two must resolve independently, never broadcast to match.
        String bomXml = "<project><properties>"
                + "<jackson.version>2.22.1</jackson.version>"
                + "<jackson.version.core>${jackson.version}</jackson.version.core>"
                + "<jackson.version.annotations>2.22</jackson.version.annotations>"
                + "</properties><dependencyManagement><dependencies>"
                + "<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-core</artifactId>"
                + "<version>${jackson.version.core}</version></dependency>"
                + "<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-annotations</artifactId>"
                + "<version>${jackson.version.annotations}</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        FakePomSource source = new FakePomSource().with("com.fasterxml.jackson", "jackson-bom", "2.22.1", bomXml);
        BomVersionResolver resolver = new BomVersionResolver(source);

        Map<String, ManagedVersionResolver.ManagedVersion> members =
                resolver.resolveBomMembers("com.fasterxml.jackson", "jackson-bom", "2.22.1");

        assertEquals("2.22.1", members.get("com.fasterxml.jackson.core:jackson-core").version());
        assertEquals("2.22", members.get("com.fasterxml.jackson.core:jackson-annotations").version());
    }

    @Test
    void bomImportingAnotherBomContributesTheNestedBomsMembersToo() {
        String nestedBomXml = "<project><dependencyManagement><dependencies>"
                + "<dependency><groupId>org.example</groupId><artifactId>nested-lib</artifactId>"
                + "<version>3.1.0</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        String outerBomXml = "<project><dependencyManagement><dependencies>"
                + "<dependency><groupId>org.example</groupId><artifactId>nested-bom</artifactId>"
                + "<version>1.0.0</version><type>pom</type><scope>import</scope></dependency>"
                + "<dependency><groupId>org.example</groupId><artifactId>own-lib</artifactId>"
                + "<version>2.0.0</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        FakePomSource source = new FakePomSource()
                .with("org.example", "outer-bom", "1.0.0", outerBomXml)
                .with("org.example", "nested-bom", "1.0.0", nestedBomXml);
        BomVersionResolver resolver = new BomVersionResolver(source);

        Map<String, ManagedVersionResolver.ManagedVersion> members =
                resolver.resolveBomMembers("org.example", "outer-bom", "1.0.0");

        assertEquals("2.0.0", members.get("org.example:own-lib").version());
        assertEquals("3.1.0", members.get("org.example:nested-lib").version(),
                "A member managed only by the nested (imported) BOM must still be resolved");
    }

    @Test
    void resolveProjectDeclaredReadsTheRootPomsOwnManagement() throws Exception {
        String rootPomXml = "<project><groupId>com.example</groupId><artifactId>app</artifactId>"
                + "<version>1.0.0</version><dependencyManagement><dependencies>"
                + "<dependency><groupId>org.example</groupId><artifactId>lib</artifactId>"
                + "<version>1.2.3</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        BomVersionResolver resolver = new BomVersionResolver(new FakePomSource());

        Map<String, ManagedVersionResolver.ManagedVersion> declared =
                resolver.resolveProjectDeclared(Path.of("pom.xml"), rootPomXml);

        assertEquals("1.2.3", declared.get("org.example:lib").version());
    }

    @Test
    void resolveProjectDeclaredStripsRedkitesOwnPriorPinsBeforeParsing() throws Exception {
        // A RedKite-tagged pin is prior RedKite output, not project intent — it must not be read
        // back as if the project itself declared it.
        String rootPomXml = "<project><groupId>com.example</groupId><artifactId>app</artifactId>"
                + "<version>1.0.0</version><dependencyManagement><dependencies>"
                + "<!-- redkite:dependency-management pin groupId=\"org.example\" artifactId=\"lib\" version=\"9.9.9\" reason=\"x\" -->"
                + "<dependency><groupId>org.example</groupId><artifactId>lib</artifactId>"
                + "<version>9.9.9</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        BomVersionResolver resolver = new BomVersionResolver(new FakePomSource());

        Map<String, ManagedVersionResolver.ManagedVersion> declared =
                resolver.resolveProjectDeclared(Path.of("pom.xml"), rootPomXml);

        assertNull(declared.get("org.example:lib"), "A RedKite-applied pin must not be read back as project intent");
    }
}
