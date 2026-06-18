package com.redkite.metadata;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.VersionMetadata;

public interface VersionMetadataProvider {
    VersionMetadata latestVersion(ComponentCoordinate coordinate);

    default VersionMetadata latestVersion(ComponentCoordinate coordinate, String currentVersion) {
        return latestVersion(coordinate);
    }
}
