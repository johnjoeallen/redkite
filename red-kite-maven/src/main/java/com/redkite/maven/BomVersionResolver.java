package com.redkite.maven;

import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.VersionSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Answers two related "what does dependencyManagement actually say" questions by reusing
 * {@link ManagedVersionResolver} — general-purpose, no artifact- or ecosystem-specific logic:
 *
 * <ul>
 *   <li>{@link #resolveProjectDeclared} — what a project's own root POM manages, per artifact,
 *       including everything reachable through its parent chain and imported BOMs.</li>
 *   <li>{@link #resolveBomMembers} — what importing a SPECIFIC BOM coordinate/version would
 *       manage, per member artifact, as if a real build imported it — used to verify a candidate
 *       BOM release before proposing or applying a version bump to it.</li>
 * </ul>
 */
public final class BomVersionResolver {
    private final ManagedVersionResolver resolver;
    private final MavenProjectScanner scanner = new MavenProjectScanner();
    private final RemediationApplier remediationApplier = new RemediationApplier();

    public BomVersionResolver(PomSource source) {
        this.resolver = new ManagedVersionResolver(source);
    }

    /** Everything the project's own root POM manages per artifact, including everything reachable
     *  through its parent chain and imported BOMs. RedKite's own previously-applied pins are
     *  stripped first — they're RedKite's prior output, not project intent. */
    public Map<String, ManagedVersionResolver.ManagedVersion> resolveProjectDeclared(Path rootPomPath, String rootPomXml) throws Exception {
        if (rootPomXml == null || rootPomXml.isBlank()) return Map.of();
        String cleaned = remediationApplier.stripRedkiteRemediations(rootPomXml);
        return resolver.resolve(scanner.parsePomXml(cleaned, rootPomPath));
    }

    /** Every property name declared anywhere across the project's own root POM, its parent chain,
     *  and its imported BOMs — used to keep a newly-introduced property (e.g. normalising a literal
     *  dependency version into {@code ${artifactId.version}}) from shadowing a name an ancestor
     *  already owns for its own purposes. A Spring Boot parent, for example, defines properties
     *  like {@code jackson-bom.version} to control its own internal BOM imports; a locally-created
     *  property with that exact name silently redefines it for everything the parent manages
     *  through it, not just the dependency the local property was meant for. */
    public java.util.Set<String> resolveProjectDeclaredPropertyNames(Path rootPomPath, String rootPomXml) throws Exception {
        if (rootPomXml == null || rootPomXml.isBlank()) return java.util.Set.of();
        String cleaned = remediationApplier.stripRedkiteRemediations(rootPomXml);
        return resolver.resolveWithDiagnostics(scanner.parsePomXml(cleaned, rootPomPath)).declaredProperties();
    }

    /** What importing {@code groupId:artifactId:version} as a BOM would manage, per member
     *  artifact, recursively (nested imports, property-chained versions) — as if a real build
     *  imported it. */
    public Map<String, ManagedVersionResolver.ManagedVersion> resolveBomMembers(String groupId, String artifactId, String version) {
        PomModel synthetic = new PomModel(Path.of(artifactId + "-" + version + ".pom"),
                "redkite", "bom-probe", "0", "pom",
                Map.of(), List.of(),
                List.of(new PomModel.PomDependency(groupId, artifactId, version, DependencyScope.COMPILE,
                        false, VersionSource.BOM_MANAGED, null, /*bomImport=*/true)),
                null, null, null, List.of(), List.of(), List.of());
        return resolver.resolve(synthetic);
    }
}
