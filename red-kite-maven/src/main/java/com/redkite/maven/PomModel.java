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
        List<String> modules) {

    public boolean isAggregator() {
        return !modules.isEmpty() || "pom".equalsIgnoreCase(packaging);
    }

    public record PomDependency(
            String groupId,
            String artifactId,
            String version,
            DependencyScope scope,
            boolean optional,
            VersionSource versionSource,
            String propertyName) {
    }
}
