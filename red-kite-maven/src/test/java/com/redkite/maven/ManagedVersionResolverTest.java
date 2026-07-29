package com.redkite.maven;

import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.VersionSource;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ManagedVersionResolverTest {

    private static PomModel module(String parentGroupId, String parentArtifactId, String parentVersion,
                                    Map<String, String> properties, List<PomModel.PomDependency> dependencyManagement) {
        return new PomModel(Path.of("pom.xml"), "com.example", "app", "1.0.0", "jar",
                properties, List.of(), dependencyManagement, parentGroupId, parentArtifactId, parentVersion,
                List.of(), List.of(), List.of());
    }

    private static PomModel.PomDependency bomImport(String groupId, String artifactId, String version) {
        return new PomModel.PomDependency(groupId, artifactId, version, DependencyScope.COMPILE, false, VersionSource.BOM_MANAGED, null, true);
    }

    private static String pomXml(String depMgmtXml) {
        return "<project><dependencyManagement><dependencies>" + depMgmtXml + "</dependencies></dependencyManagement></project>";
    }

    private static String managedDep(String groupId, String artifactId, String version) {
        return "<dependency><groupId>" + groupId + "</groupId><artifactId>" + artifactId + "</artifactId>"
                + "<version>" + version + "</version></dependency>";
    }

    @Test
    void parentManagedDependencyIsFound() {
        FakePomSource source = new FakePomSource().with("org.example", "parent-pom", "1.0.0",
                pomXml(managedDep("org.example", "lib", "1.2.3")));
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module("org.example", "parent-pom", "1.0.0", Map.of(), List.of());
        Map<String, ManagedVersionResolver.ManagedVersion> result = resolver.resolve(mod);

        ManagedVersionResolver.ManagedVersion v = result.get("org.example:lib");
        assertNotNull(v);
        assertEquals("1.2.3", v.version());
        assertEquals("org.example:parent-pom:1.0.0", v.controllerCoordinate());
        assertFalse(v.bomImport());
    }

    @Test
    void importedBomManagedDependencyIsFound() {
        FakePomSource source = new FakePomSource().with("org.example", "some-bom", "2.0.0",
                pomXml(managedDep("org.example", "lib", "2.0.0")));
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module(null, null, null, Map.of(),
                List.of(bomImport("org.example", "some-bom", "2.0.0")));
        Map<String, ManagedVersionResolver.ManagedVersion> result = resolver.resolve(mod);

        ManagedVersionResolver.ManagedVersion v = result.get("org.example:lib");
        assertNotNull(v);
        assertEquals("2.0.0", v.version());
        assertEquals("org.example:some-bom:2.0.0", v.controllerCoordinate());
        assertTrue(v.bomImport());
    }

    @Test
    void firstDeclaredBomWinsWhenTwoBomsManageTheSameCoordinate() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "bom-one", "1.0.0", pomXml(managedDep("org.example", "lib", "1.0.0")))
                .with("org.example", "bom-two", "1.0.0", pomXml(managedDep("org.example", "lib", "9.9.9")));
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module(null, null, null, Map.of(), List.of(
                bomImport("org.example", "bom-one", "1.0.0"),
                bomImport("org.example", "bom-two", "1.0.0")));
        Map<String, ManagedVersionResolver.ManagedVersion> result = resolver.resolve(mod);

        assertEquals("1.0.0", result.get("org.example:lib").version(), "First-declared import must win");
        assertEquals("org.example:bom-one:1.0.0", result.get("org.example:lib").controllerCoordinate());
    }

    @Test
    void ownBomImportWinsOverParentManagement() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "some-bom", "2.0.0", pomXml(managedDep("org.example", "lib", "2.0.0")))
                .with("org.example", "parent-pom", "1.0.0", pomXml(managedDep("org.example", "lib", "9.9.9")));
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module("org.example", "parent-pom", "1.0.0", Map.of(),
                List.of(bomImport("org.example", "some-bom", "2.0.0")));
        Map<String, ManagedVersionResolver.ManagedVersion> result = resolver.resolve(mod);

        assertEquals("2.0.0", result.get("org.example:lib").version(), "Own BOM import outranks the parent's management");
        assertTrue(result.get("org.example:lib").bomImport());
    }

    @Test
    void childPropertyOverrideAppliesInsideParentManagedEntry() {
        // The parent manages "lib" via its OWN ${shared.version} (defined as 1.0.0 in the parent's
        // own <properties>) — but the starting module overrides that same property name, and the
        // override must win everywhere, including inside the parent's managed entry.
        String parentXml = "<project><properties><shared.version>1.0.0</shared.version></properties>"
                + "<dependencyManagement><dependencies>"
                + "<dependency><groupId>org.example</groupId><artifactId>lib</artifactId>"
                + "<version>${shared.version}</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        FakePomSource source = new FakePomSource().with("org.example", "parent-pom", "1.0.0", parentXml);
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module("org.example", "parent-pom", "1.0.0",
                Map.of("shared.version", "9.9.9"), List.of());
        Map<String, ManagedVersionResolver.ManagedVersion> result = resolver.resolve(mod);

        assertEquals("9.9.9", result.get("org.example:lib").version(),
                "The module's own property override must win over the parent's own definition of the same name");
    }

    @Test
    void unreachableParentStopsThatBranchWithoutThrowing() {
        FakePomSource source = new FakePomSource(); // nothing registered — every fetch misses
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module("org.example", "unreachable-parent", "1.0.0", Map.of(), List.of());
        Map<String, ManagedVersionResolver.ManagedVersion> result = resolver.resolve(mod);

        assertTrue(result.isEmpty());
    }

    @Test
    void propertyThatIsItselfAPropertyReferenceIsChased() {
        // Shaped exactly like the real Jackson 2.22.1 BOM: jackson.version.core is defined as
        // "${jackson.version}", not a literal — a naive single lookup would resolve jackson-core's
        // managed version to the literal string "${jackson.version}" instead of "2.22.1".
        String bomXml = "<project><properties>"
                + "<jackson.version>2.22.1</jackson.version>"
                + "<jackson.version.core>${jackson.version}</jackson.version.core>"
                + "</properties><dependencyManagement><dependencies>"
                + "<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-core</artifactId>"
                + "<version>${jackson.version.core}</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        FakePomSource source = new FakePomSource().with("com.fasterxml.jackson", "jackson-bom", "2.22.1", bomXml);
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module(null, null, null, Map.of(),
                List.of(bomImport("com.fasterxml.jackson", "jackson-bom", "2.22.1")));
        Map<String, ManagedVersionResolver.ManagedVersion> result = resolver.resolve(mod);

        assertEquals("2.22.1", result.get("com.fasterxml.jackson.core:jackson-core").version());
    }

    @Test
    void cyclicPropertyReferenceResolvesToNothingRatherThanLooping() {
        String bomXml = "<project><properties>"
                + "<a.version>${b.version}</a.version>"
                + "<b.version>${a.version}</b.version>"
                + "</properties><dependencyManagement><dependencies>"
                + "<dependency><groupId>org.example</groupId><artifactId>lib</artifactId>"
                + "<version>${a.version}</version></dependency>"
                + "</dependencies></dependencyManagement></project>";
        FakePomSource source = new FakePomSource().with("org.example", "some-bom", "1.0.0", bomXml);
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module(null, null, null, Map.of(),
                List.of(bomImport("org.example", "some-bom", "1.0.0")));
        Map<String, ManagedVersionResolver.ManagedVersion> result = resolver.resolve(mod);

        assertNull(result.get("org.example:lib"));
    }

    @Test
    void confirmedAbsentBomIsReportedAsUnresolvedNotSilentlySkipped() {
        FakePomSource source = new FakePomSource(); // nothing registered — a clean "not found"
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module(null, null, null, Map.of(),
                List.of(bomImport("org.example", "missing-bom", "1.0.0")));
        ManagedVersionResolver.ResolutionOutcome outcome = resolver.resolveWithDiagnostics(mod);

        assertTrue(outcome.managed().isEmpty());
        assertEquals(1, outcome.unresolved().size());
        ManagedVersionResolver.UnresolvedReference ref = outcome.unresolved().get(0);
        assertEquals("org.example", ref.groupId());
        assertEquals("missing-bom", ref.artifactId());
        assertEquals("not found", ref.detail());
    }

    @Test
    void transportErrorFetchingABomIsReportedWithRepositoryDetail() {
        FakePomSource source = new FakePomSource()
                .withError("org.example", "flaky-bom", "1.0.0", "https://repo.example/maven2", "connection refused");
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module(null, null, null, Map.of(),
                List.of(bomImport("org.example", "flaky-bom", "1.0.0")));
        ManagedVersionResolver.ResolutionOutcome outcome = resolver.resolveWithDiagnostics(mod);

        assertEquals(1, outcome.unresolved().size());
        String detail = outcome.unresolved().get(0).detail();
        assertTrue(detail.contains("https://repo.example/maven2"), detail);
        assertTrue(detail.contains("connection refused"), detail);
    }
}
