package com.redkite.core.domain;

import java.io.Serializable;
import java.util.Map;

public record ScanComponent(
        long id,
        ComponentCoordinate coordinate,
        String version,
        DependencyScope scope,
        boolean direct,
        VersionSource versionSource,
        String sourceFilePath,
        String declarationPath,
        Map<String, String> properties,
        boolean snapshot,
        String owningVersionControlPoint,
        String modulePath) implements Serializable {
}
