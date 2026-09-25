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

    @Test
    void declaredPropertiesIncludesNamesFromTheParentChainAndImportedBoms() {
        // Shaped like a Spring Boot parent: it declares jackson-bom.version in its own <properties>
        // to control an internal BOM import the module never sees directly (the module doesn't
        // depend on anything from that BOM, so nothing here resolves it as a *managed version* —
        // but the property name itself is still "owned" by the parent and must be reported, since
        // a caller reusing it locally would silently redefine what the parent's own import means).
        String parentXml = "<project><properties>"
                + "<jackson-bom.version>3.0.0</jackson-bom.version>"
                + "</properties><dependencyManagement><dependencies>"
                + "<dependency><groupId>tools.jackson</groupId><artifactId>jackson-bom</artifactId>"
                + "<version>${jackson-bom.version}</version><type>pom</type><scope>import</scope></dependency>"
                + "</dependencies></dependencyManagement></project>";
        FakePomSource source = new FakePomSource().with("org.example", "some-parent", "1.0.0", parentXml);
        ManagedVersionResolver resolver = new ManagedVersionResolver(source);

        PomModel mod = module("org.example", "some-parent", "1.0.0", Map.of("app.own.version", "1.2.3"), List.of());
        ManagedVersionResolver.ResolutionOutcome outcome = resolver.resolveWithDiagnostics(mod);

        assertTrue(outcome.declaredProperties().contains("jackson-bom.version"),
                "Parent-declared property names must be reported even when nothing local resolves through them");
        assertTrue(outcome.declaredProperties().contains("app.own.version"),
                "The starting module's own properties are included too");
    }

    @Test
    void unparsableParentPomIsReportedAndStopsThatBranch() {
        FakePomSource source = new FakePomSource().with("org.example", "parent-pom", "1.0.0", "<project>");
        ManagedVersionResolver.ResolutionOutcome outcome = new ManagedVersionResolver(source)
                .resolveWithDiagnostics(module("org.example", "parent-pom", "1.0.0", Map.of(), List.of()));
        assertEquals(Map.of(), outcome.managed());
        assertEquals(1, outcome.unresolved().size());
        assertTrue(outcome.unresolved().get(0).detail().startsWith("unparsable POM: "), outcome.unresolved().toString());
    }

    @Test
    void incompleteEntriesAreIgnoredAndProjectCoordinatesComeFromTheParent() {
        // The fetched parent declares no groupId/version of its own: ${project.version} resolves via its parent.
        FakePomSource source = new FakePomSource()
                .with("org.example", "parent-pom", "1.0.0", """
                        <project>
                          <parent><groupId>org.example</groupId><artifactId>grandparent</artifactId><version>7.0</version></parent>
                          <artifactId>parent-pom</artifactId>
                          <properties><!-- a comment --><lib.version>${project.version}</lib.version></properties>
                          <dependencyManagement><dependencies>
                            <dependency><artifactId>no-group</artifactId><version>1</version></dependency>
                            <dependency><groupId>org.example</groupId><version>1</version></dependency>
                            <dependency><groupId>org.example</groupId><artifactId>no-version</artifactId></dependency>
                            <dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>${lib.version}</version></dependency>
                            <dependency><groupId>org.example</groupId><artifactId>pom-not-imported</artifactId><version>2</version><type>pom</type></dependency>
                          </dependencies></dependencyManagement>
                        </project>
                        """)
                .with("org.example", "grandparent", "7.0", "<project><dependencyManagement/></project>");
        Map<String, ManagedVersionResolver.ManagedVersion> result = new ManagedVersionResolver(source)
                .resolve(module("org.example", "parent-pom", "1.0.0", Map.of(), List.of()));
        assertEquals("7.0", result.get("org.example:lib").version());
        assertEquals("lib.version", result.get("org.example:lib").propertyName());
        assertFalse(result.get("org.example:pom-not-imported").bomImport());
        assertEquals(java.util.Set.of("org.example:lib", "org.example:pom-not-imported"), result.keySet());
    }

    @Test
    void overlyLongPropertyChainsAndParentChainsAreCutOff() {
        // A property chain longer than the resolver will follow.
        StringBuilder props = new StringBuilder();
        for (int i = 0; i < 12; i++) props.append("<p").append(i).append(">${p").append(i + 1).append("}</p").append(i).append(">");
        props.append("<p12>1.0</p12>");
        FakePomSource chain = new FakePomSource().with("org.example", "parent-pom", "1.0.0",
                "<project><properties>" + props + "</properties><dependencyManagement><dependencies>"
                        + managedDep("org.example", "deep", "${p0}") + managedDep("org.example", "shallow", "${p11}")
                        + "</dependencies></dependencyManagement></project>");
        Map<String, ManagedVersionResolver.ManagedVersion> result = new ManagedVersionResolver(chain)
                .resolve(module("org.example", "parent-pom", "1.0.0", Map.of(), List.of()));
        assertNull(result.get("org.example:deep"));
        assertEquals("1.0", result.get("org.example:shallow").version());

        // A parent chain deeper than the resolver will walk.
        FakePomSource parents = new FakePomSource();
        for (int i = 0; i < 14; i++) {
            parents.with("org.example", "p" + i, "1", "<project><parent><groupId>org.example</groupId><artifactId>p" + (i + 1)
                    + "</artifactId><version>1</version></parent><dependencyManagement><dependencies>"
                    + managedDep("org.example", "from-p" + i, "1") + "</dependencies></dependencyManagement></project>");
        }
        Map<String, ManagedVersionResolver.ManagedVersion> deep = new ManagedVersionResolver(parents)
                .resolve(module("org.example", "p0", "1", Map.of(), List.of()));
        assertTrue(deep.containsKey("org.example:from-p0"));
        assertFalse(deep.containsKey("org.example:from-p13"), deep.keySet().toString());
    }

    @Test
    void projectAndParentCoordinatesAreAvailableAsProperties() {
        FakePomSource source = new FakePomSource().with("org.example", "parent-pom", "1.0.0", """
                <project>
                  <parent><groupId>org.gp</groupId><artifactId>gp</artifactId><version>7.0</version></parent>
                  <groupId>org.own</groupId><artifactId>parent-pom</artifactId><version>2.0</version>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>org.example</groupId><artifactId>own-version</artifactId><version>${project.version}</version></dependency>
                    <dependency><groupId>org.example</groupId><artifactId>parent-version</artifactId><version>${project.parent.version}</version></dependency>
                    <dependency><groupId>org.example</groupId><artifactId>own-group</artifactId><version>${project.groupId}</version></dependency>
                    <dependency><groupId>org.example</groupId><artifactId>parent-group</artifactId><version>${project.parent.groupId}</version></dependency>
                  </dependencies></dependencyManagement>
                </project>
                """);
        Map<String, ManagedVersionResolver.ManagedVersion> result = new ManagedVersionResolver(source)
                .resolve(module("org.example", "parent-pom", "1.0.0", Map.of(), List.of()));
        assertEquals("2.0", result.get("org.example:own-version").version());
        assertEquals("7.0", result.get("org.example:parent-version").version());
        assertEquals("org.own", result.get("org.example:own-group").version());
        assertEquals("org.gp", result.get("org.example:parent-group").version());
    }
}
