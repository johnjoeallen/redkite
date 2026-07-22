package com.redkite.maven;

import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.VersionSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record PomModel(
        Path path,
        String groupId,
        String artifactId,
        String version,
        String packaging,
        Map<String, String> properties,
        List<PomDependency> dependencies,
        List<PomDependency> dependencyManagement,
        String parentGroupId,
        String parentArtifactId,
        String parentVersion,
        List<String> modules,
        List<PomDependency> buildPlugins,
        List<PomDependency> managedPlugins) {

    public boolean isAggregator() {
        return !modules.isEmpty();
    }

    public record PomDependency(
            String groupId,
            String artifactId,
            String version,
            DependencyScope scope,
            boolean optional,
            VersionSource versionSource,
            String propertyName,
            /** {@code <type>pom</type><scope>import</scope>} — a BOM import, not a version
             *  override for {@code groupId:artifactId} itself. Only ever true for entries read
             *  from {@code <dependencyManagement>}; always false elsewhere. */
            boolean bomImport) {

        public PomDependency(String groupId, String artifactId, String version, DependencyScope scope,
                              boolean optional, VersionSource versionSource, String propertyName) {
            this(groupId, artifactId, version, scope, optional, versionSource, propertyName, false);
        }
    }
}
