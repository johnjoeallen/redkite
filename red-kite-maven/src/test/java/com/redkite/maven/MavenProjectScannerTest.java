package com.redkite.maven;

import com.redkite.core.domain.DependencyEdge;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanInput;
import com.redkite.core.domain.VersionSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MavenProjectScannerTest {
    private static final String ROOT_POM = """
            <project>
              <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>${boot.version}</version>
              </parent>
              <groupId>com.example</groupId>
              <artifactId>root</artifactId>
              <version>1</version>
              <packaging>pom</packaging>
              <properties>
                <boot.version>3.2.0</boot.version>
                <jacoco.version>0.8.12</jacoco.version>
              </properties>
              <modules><module>app</module><module>lib</module><module>tool</module></modules>
              <dependencyManagement>
                <dependencies>
                  <dependency><groupId>org.managed</groupId><artifactId>only-managed</artifactId><version>7.0</version></dependency>
                  <dependency><groupId>com.example</groupId><artifactId>root</artifactId><version>1</version></dependency>
                </dependencies>
              </dependencyManagement>
              <build>
                <pluginManagement>
                  <plugins>
                    <plugin><artifactId>maven-compiler-plugin</artifactId><version>3.11.0</version></plugin>
                  </plugins>
                </pluginManagement>
                <plugins>
                  <plugin><groupId>org.jacoco</groupId><artifactId>jacoco-maven-plugin</artifactId><version>${jacoco.version}</version></plugin>
                  <plugin><groupId>org.codehaus.mojo</groupId><artifactId>no-version-plugin</artifactId></plugin>
                  <plugin><groupId>org.codehaus.mojo</groupId></plugin>
                </plugins>
              </build>
            </project>
            """;

    private static final String APP_POM = """
            <project>
              <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1</version></parent>
              <artifactId>app</artifactId>
              <properties><a.version>1.2</a.version></properties>
              <dependencies>
                <dependency><groupId>com.example</groupId><artifactId>lib</artifactId><version>${project.version}</version></dependency>
                <dependency><groupId>com.example</groupId><artifactId>app</artifactId><version>1</version></dependency>
                <dependency><groupId>org.a</groupId><artifactId>direct</artifactId><version>${a.version}</version></dependency>
                <dependency><groupId>org.b</groupId><artifactId>bomdep</artifactId></dependency>
                <dependency><groupId>org.c</groupId><artifactId>snap</artifactId><version>1.0-SNAPSHOT</version><scope>test</scope><optional>true</optional></dependency>
                <dependency><groupId>org.d</groupId><artifactId>same-as-parent</artifactId><version>1</version><scope>provided</scope></dependency>
                <dependency><groupId>org.e</groupId><artifactId>odd-scope</artifactId><version>2</version><scope>system</scope></dependency>
                <dependency><groupId>org.f</groupId><artifactId>unresolved-prop</artifactId><version>${missing.prop}</version><scope>runtime</scope></dependency>
              </dependencies>
              <dependencyManagement>
                <dependencies>
                  <dependency><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency>
                  <dependency><groupId>org.t</groupId><artifactId>trans</artifactId><version>${project.version}</version></dependency>
                  <dependency><groupId>org.u</groupId><artifactId>unused</artifactId><version>1.0</version></dependency>
                  <dependency><groupId>org.a</groupId><artifactId>direct</artifactId><version>1.2</version></dependency>
                  <dependency><groupId>com.example</groupId><artifactId>app</artifactId><version>1</version></dependency>
                </dependencies>
              </dependencyManagement>
            </project>
            """;

    private static final String APP_TREE = """
            [INFO] Scanning for projects...
            [INFO] com.example:app:jar:1
            [INFO] +- com.example:lib:jar:1:compile
            [INFO] |  \\- org.x:underlib:jar:1.0:compile
            [INFO] +- org.a:direct:jar:1.5:compile
            [INFO] |  \\- org.t:trans:jar:1:runtime
            [INFO] |     \\- org.b:bomdep:jar:2.0:compile
            [INFO] +- org.c:snap:jar:1.0-SNAPSHOT:test
            [INFO] |  \\- org.o:old:jar:1.0:compile (omitted for conflict with 2.0)
            [INFO] +- org.m:mediated:jar:3.1:compile
            [INFO] +- org.p:parentmanaged:jar:5.0:compile
            [INFO] +- org.q:mismatch:jar:2.0:compile
            [WARNING] +- org.w:warned:jar:1.0:compile
            [ERROR] +- org.r:errored:jar:1.0:compile
            [INFO] +- org.s:classified:jar:linux:4.0:runtime
            [INFO] +- broken:line
            [INFO] \\- com.example:app:jar:1:compile
            """;

    private static final String LIB_POM = """
            <project>
              <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1</version></parent>
              <artifactId>lib</artifactId>
              <dependencies>
                <dependency><groupId>org.a</groupId><artifactId>direct</artifactId><version>1.2</version></dependency>
              </dependencies>
            </project>
            """;

    private static final String TOOL_POM = """
            <project>
              <parent><groupId>org.ext</groupId><artifactId>ext-parent</artifactId><version>${nope}</version></parent>
              <artifactId>tool</artifactId>
            </project>
            """;

    /** The app module's BOM import, in the file-based remote repository. */
    private static final String BOM_POM = """
            <project>
              <groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version>
              <dependencyManagement><dependencies>
                <dependency><groupId>org.m</groupId><artifactId>mediated</artifactId><version>3.1</version></dependency>
                <dependency><groupId>org.q</groupId><artifactId>mismatch</artifactId><version>1.0</version></dependency>
              </dependencies></dependencyManagement>
            </project>
            """;

    /** The app module's parent as the remote repository sees it. */
    private static final String REMOTE_ROOT_POM = """
            <project>
              <groupId>com.example</groupId><artifactId>root</artifactId><version>1</version>
              <properties><pm.version>5.0</pm.version></properties>
              <dependencyManagement><dependencies>
                <dependency><groupId>org.p</groupId><artifactId>parentmanaged</artifactId><version>${pm.version}</version></dependency>
              </dependencies></dependencyManagement>
            </project>
            """;

    @TempDir
    Path tempDir;

    private FakeMaven mvn;
    private Path project;
    private String originalHome;

    @BeforeEach
    void setUp() throws Exception {
        originalHome = System.getProperty("user.home");
        System.setProperty("user.home", Files.createDirectories(tempDir.resolve("home")).toString());
        mvn = FakeMaven.install(tempDir.resolve("fake-mvn"));
        project = Files.createDirectories(tempDir.resolve("project"));

        Path repo = tempDir.resolve("remote-repo");
        write(repo.resolve("org/bom/bom/1.0/bom-1.0.pom"), BOM_POM);
        write(repo.resolve("com/example/root/1/root-1.pom"), REMOTE_ROOT_POM);
        write(project.resolve(".m2/settings.xml"), """
                <settings><mirrors><mirror><id>files</id><mirrorOf>*</mirrorOf><url>%s</url></mirror></mirrors></settings>
                """.formatted(repo.toUri()));
    }

    @AfterEach
    void tearDown() {
        mvn.close();
        System.setProperty("user.home", originalHome);
    }

    private static void write(Path path, String content) throws Exception {
        Files.createDirectories(path.getParent());
        Files.writeString(path, content);
    }

    private void writeReactor() throws Exception {
        write(project.resolve("pom.xml"), ROOT_POM);
        write(project.resolve("app/pom.xml"), APP_POM);
        write(project.resolve("lib/pom.xml"), LIB_POM);
        write(project.resolve("tool/pom.xml"), TOOL_POM);
        mvn.output("dependency:tree", "app", APP_TREE)
                .output("dependency:tree", "lib", "[INFO] Building lib\n[ERROR] Failed to collect dependencies\n[ERROR]\n[ERROR] [Help 1] http://help\n[ERROR]    \n")
                .exit("dependency:tree", "lib", 1)
                .output("dependency:tree", "tool", "[INFO] org.ext:tool:jar:1\n");
    }

    private static List<ScanComponent> find(ScanInput input, String groupId, String artifactId) {
        return input.components().stream()
                .filter(c -> c.coordinate().groupId().equals(groupId) && c.coordinate().artifactId().equals(artifactId))
                .toList();
    }

    private static ScanComponent one(ScanInput input, String groupId, String artifactId) {
        List<ScanComponent> matches = find(input, groupId, artifactId);
        assertEquals(1, matches.size(), groupId + ":" + artifactId + " => " + matches);
        return matches.get(0);
    }

    private static ScanComponent in(ScanInput input, String groupId, String artifactId, String sourceFile) {
        return find(input, groupId, artifactId).stream()
                .filter(c -> c.sourceFilePath().equals(sourceFile))
                .findFirst().orElseThrow(() -> new AssertionError(groupId + ":" + artifactId + " in " + sourceFile));
    }

    @Test
    void scansAMultiModuleReactor() throws Exception {
        writeReactor();
        List<String> progress = new ArrayList<>();
        List<String> lines = new ArrayList<>();

        ScanInput input = new MavenProjectScanner(true).scan(project, progress::add, lines::add);

        assertEquals("project", input.projectName());
        assertEquals(project.toAbsolutePath().normalize().toString(), input.projectRootPath());
        assertEquals("(not a git repository)", input.currentBranch());
        assertFalse(input.workingTreeClean());
        assertTrue(input.allowMajorUpgrades());
        assertEquals(List.of("app/pom.xml", "lib/pom.xml", "pom.xml", "tool/pom.xml"),
                List.copyOf(input.fileHashes().keySet()));
        input.fileHashes().values().forEach(h -> assertTrue(h.matches("[0-9a-f]{64}"), h));

        // Project modules never appear as components.
        assertTrue(find(input, "com.example", "lib").isEmpty());
        assertTrue(find(input, "com.example", "app").isEmpty());
        assertTrue(find(input, "com.example", "root").isEmpty());

        // Direct dependency: the tree's resolved version wins over the POM's property value.
        ScanComponent direct = in(input, "org.a", "direct", "app/pom.xml");
        assertEquals("1.5", direct.version());
        assertEquals(VersionSource.PROPERTY, direct.versionSource());
        assertEquals("pom.xml#a.version", direct.owningVersionControlPoint());
        assertTrue(direct.direct());
        assertEquals("/project/dependencies/dependency[org.a:direct]", direct.declarationPath());

        // Declared without a version: resolved from its transitive tree entry.
        ScanComponent bomdep = one(input, "org.b", "bomdep");
        assertEquals("2.0", bomdep.version());
        assertEquals(VersionSource.UNKNOWN, bomdep.versionSource());

        ScanComponent snap = one(input, "org.c", "snap");
        assertTrue(snap.snapshot());
        assertEquals(DependencyScope.TEST, snap.scope());

        assertEquals("pom.xml#parent", one(input, "org.d", "same-as-parent").owningVersionControlPoint());
        assertEquals(DependencyScope.PROVIDED, one(input, "org.d", "same-as-parent").scope());
        assertEquals(DependencyScope.UNKNOWN, one(input, "org.e", "odd-scope").scope());
        assertEquals("pom.xml#dependency", one(input, "org.e", "odd-scope").owningVersionControlPoint());
        ScanComponent unresolved = one(input, "org.f", "unresolved-prop");
        assertEquals("unknown", unresolved.version());
        assertEquals(DependencyScope.RUNTIME, unresolved.scope());

        // Transitive under a project module is kept, attached to the module slot.
        ScanComponent underlib = one(input, "org.x", "underlib");
        assertFalse(underlib.direct());
        assertEquals("app/pom.xml#dependencyTree", underlib.owningVersionControlPoint());

        // A transitive controlled by the module's own dependencyManagement is corrected.
        ScanComponent trans = one(input, "org.t", "trans");
        assertTrue(trans.direct());
        assertEquals(VersionSource.PROPERTY, trans.versionSource());
        assertEquals("/project/dependencyManagement/dependencies/dependency[org.t:trans]", trans.declarationPath());
        assertEquals(DependencyScope.RUNTIME, trans.scope());

        // Managed but unused: still surfaced.
        ScanComponent unused = one(input, "org.u", "unused");
        assertEquals(VersionSource.BOM_MANAGED, unused.versionSource());
        assertEquals("pom.xml#dependencyManagement", unused.owningVersionControlPoint());
        ScanComponent bom = one(input, "org.bom", "bom");
        assertEquals("/project/dependencyManagement/dependencies/dependency[import:org.bom:bom]", bom.declarationPath());

        // Omitted conflict losers and malformed lines never become components.
        assertTrue(find(input, "org.o", "old").isEmpty());
        assertTrue(find(input, "broken", "line").isEmpty());
        assertEquals("1.0", one(input, "org.w", "warned").version());
        assertEquals("1.0", one(input, "org.r", "errored").version());
        assertEquals("4.0", one(input, "org.s", "classified").version());

        // Provenance from the imported BOM and from the parent POM in the remote repository.
        ScanComponent mediated = one(input, "org.m", "mediated");
        assertEquals(VersionSource.PLATFORM_MANAGED, mediated.versionSource());
        assertEquals("org.bom:bom:1.0#literal", mediated.owningVersionControlPoint());
        ScanComponent parentManaged = one(input, "org.p", "parentmanaged");
        assertEquals(VersionSource.PARENT_MANAGED, parentManaged.versionSource());
        assertEquals("com.example:root:1#pm.version", parentManaged.owningVersionControlPoint());
        assertEquals(VersionSource.UNKNOWN, one(input, "org.q", "mismatch").versionSource(),
                "a managed version that disagrees with the tree is not claimed");

        // Root aggregator: plugins, managed plugins, managed deps and the external parent.
        ScanComponent jacoco = one(input, "org.jacoco", "jacoco-maven-plugin");
        assertEquals("0.8.12", jacoco.version());
        assertEquals(DependencyScope.PLUGIN_BUILD, jacoco.scope());
        assertEquals("/project/build/plugins/plugin[org.jacoco:jacoco-maven-plugin]", jacoco.declarationPath());
        ScanComponent compiler = one(input, "org.apache.maven.plugins", "maven-compiler-plugin");
        assertEquals("/project/build/pluginManagement/plugins/plugin[org.apache.maven.plugins:maven-compiler-plugin]",
                compiler.declarationPath());
        assertTrue(find(input, "org.codehaus.mojo", "no-version-plugin").isEmpty());
        assertEquals("7.0", one(input, "org.managed", "only-managed").version());

        ScanComponent bootParent = one(input, "org.springframework.boot", "spring-boot-starter-parent");
        assertEquals("3.2.0", bootParent.version());
        assertEquals(VersionSource.PROPERTY, bootParent.versionSource());
        assertEquals("/project/parent", bootParent.declarationPath());
        assertEquals("pom.xml#parent", bootParent.owningVersionControlPoint());
        assertEquals("unknown", one(input, "org.ext", "ext-parent").version(),
                "an unresolvable parent property never leaks the raw ${...} text");

        // lib's dependency:tree failed: the errors are reported, [Help] and bare lines dropped.
        assertEquals(List.of(
                "[INFO] +- broken:line",
                "[BUILD_FAILED] dependency:tree failed (exit 1) for lib/pom.xml",
                "Failed to collect dependencies"), input.treeParseWarnings());

        // Edges: module -> direct, and direct -> transitive.
        List<DependencyEdge> edges = input.dependencyEdges();
        assertTrue(edges.stream().anyMatch(e -> e.fromComponentId().equals("module:app/pom.xml")
                && e.toComponentId().equals(String.valueOf(direct.id())) && e.direct()));
        assertTrue(edges.stream().anyMatch(e -> e.fromComponentId().equals("module:app/pom.xml")
                && e.toComponentId().equals(String.valueOf(underlib.id())) && !e.direct()));
        assertTrue(edges.stream().anyMatch(e -> e.fromComponentId().equals(String.valueOf(trans.id()))
                && e.toComponentId().equals(String.valueOf(bomdep.id()))));

        // Only non-aggregator modules run dependency:tree; progress and output are reported.
        assertEquals(3, mvn.calls().size());
        mvn.calls().forEach(c -> assertTrue(c.startsWith("-s "), "project-local settings are passed: " + c));
        assertTrue(progress.contains("Running dependency:tree for app/pom.xml…"));
        assertTrue(progress.get(progress.size() - 1).startsWith("Dependency scan complete"));
        assertTrue(lines.contains("[INFO] +- org.a:direct:jar:1.5:compile"));
        assertTrue(Files.readString(ValidationRunner.redkiteWorkDir(project.toAbsolutePath()).resolve("build.log"))
                .contains("dependency:tree (app/pom.xml)"));

        List<Long> ids = input.components().stream().map(ScanComponent::id).toList();
        assertEquals(ids.size(), ids.stream().distinct().count(), "component ids are unique");
    }

    @Test
    void singleModuleProjectInAGitRepository() throws Exception {
        write(project.resolve("pom.xml"), """
                <project>
                  <groupId>com.example</groupId><artifactId>single</artifactId><version>2</version>
                  <dependencies>
                    <dependency><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
                  </dependencies>
                  <build><plugins>
                    <plugin><groupId>org.a</groupId><artifactId>a</artifactId><version>9</version></plugin>
                  </plugins></build>
                </project>
                """);
        mvn.output("dependency:tree", """
                [INFO] com.example:single:jar:2
                [INFO] \\- org.a:a:jar:1.0:compile
                [INFO]    \\- org.z:z:jar:1.0-SNAPSHOT:compile
                """);
        git("init", "-q", "-b", "trunk");
        git("-c", "user.name=t", "-c", "user.email=t@example.com", "add", "-A");
        git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init");

        ScanInput input = new MavenProjectScanner().scan(project);

        assertEquals("trunk", input.currentBranch());
        assertTrue(input.currentHeadCommit().matches("[0-9a-f]{40}"), input.currentHeadCommit());
        assertFalse(input.allowMajorUpgrades());
        // .redkite/work/build.log was written into the tree during the scan, but the status
        // is read before that: the tree is clean.
        assertTrue(input.workingTreeClean());
        ScanComponent a = one(input, "org.a", "a");
        assertEquals(DependencyScope.COMPILE, a.scope());
        assertTrue(one(input, "org.z", "z").snapshot());
        assertTrue(input.treeParseWarnings().isEmpty());
    }

    @Test
    void emptyProjectGetsAPlaceholderComponent() throws Exception {
        write(project.resolve("pom.xml"), "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>");

        ScanInput input = new MavenProjectScanner().scan(project);

        assertEquals(1, input.components().size());
        ScanComponent placeholder = input.components().get(0);
        assertEquals("unknown", placeholder.coordinate().groupId());
        assertEquals(DependencyScope.UNKNOWN, placeholder.scope());
        assertFalse(placeholder.direct());
    }

    @Test
    void brokenGitMetadataIsTreatedAsNotARepository() throws Exception {
        write(project.resolve("pom.xml"), "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>");
        Files.createDirectories(project.resolve(".git")); // not a real repository

        ScanInput input = new MavenProjectScanner().scan(project);

        assertEquals("(not a git repository)", input.currentHeadCommit());
    }

    @Test
    void unrunnableMavenLeavesOnlyPomDeclaredComponents() throws Exception {
        write(project.resolve("pom.xml"), """
                <project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
                  <dependencies><dependency><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies>
                </project>
                """);
        System.setProperty(MavenExecutable.PROPERTY, tempDir.resolve("missing-mvn").toString());

        ScanInput input = new MavenProjectScanner().scan(project);

        assertEquals("1.0", one(input, "org.a", "a").version());
        assertTrue(input.dependencyEdges().isEmpty());
        assertTrue(input.treeParseWarnings().isEmpty());
    }

    @Test
    void malformedPomFailsTheScan() throws Exception {
        write(project.resolve("pom.xml"), "<project>");
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> new MavenProjectScanner().scan(project));
        assertEquals("Failed to scan Maven project", e.getMessage());
    }

    @Test
    void parsePomXmlReadsCoordinatesAndDefaultsFromParent() throws Exception {
        PomModel model = new MavenProjectScanner().parsePomXml("""
                <project>
                  <parent><groupId>p.g</groupId><artifactId>p</artifactId><version>9</version></parent>
                  <artifactId>child</artifactId>
                  <packaging>war</packaging>
                  <properties><x>1</x></properties>
                  <modules><module> m1 </module><module>  </module></modules>
                  <dependencies>
                    <dependency><groupId>${project.groupId}</groupId><artifactId>d</artifactId><version>${project.parent.version}</version></dependency>
                    <dependency><groupId>o</groupId><artifactId>e</artifactId><version>${project.packaging}</version></dependency>
                    <dependency><groupId>o</groupId><artifactId>f</artifactId><version>${project.artifactId}</version></dependency>
                    <dependency><groupId>o</groupId><artifactId>h</artifactId><version>${project.parent.groupId}</version></dependency>
                    <dependency><groupId>o</groupId><artifactId>i</artifactId><version>${x}</version></dependency>
                  </dependencies>
                  <dependencyManagement/>
                  <build><pluginManagement/></build>
                </project>
                """, Path.of("child/pom.xml"));

        assertEquals("p.g", model.groupId());
        assertEquals("9", model.version());
        assertEquals("war", model.packaging());
        assertEquals(List.of("m1"), model.modules());
        assertTrue(model.isAggregator());
        assertEquals(List.of("9", "war", "child", "p.g", "1"),
                model.dependencies().stream().map(PomModel.PomDependency::version).toList());
        assertTrue(model.dependencyManagement().isEmpty());
        assertTrue(model.managedPlugins().isEmpty());
        assertTrue(model.buildPlugins().isEmpty());
        assertEquals(Path.of("child/pom.xml"), model.path());
    }

    @Test
    void parsePomXmlWithoutParentOrCoordinates() throws Exception {
        PomModel model = new MavenProjectScanner().parsePomXml("<project><build/></project>", null);
        assertNull(model.groupId());
        assertNull(model.version());
        assertFalse(model.isAggregator());
        assertFalse(model.properties().containsKey("project.groupId"));
    }

    private void git(String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of("git", "-C", project.toString()));
        command.addAll(List.of(args));
        Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        assertEquals(0, p.waitFor(), out);
    }
}
