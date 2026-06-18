package com.redkite.core.domain;

import java.io.Serializable;

public record SnapshotDependencyRisk(
        long componentId,
        String message,
        String recommendation,
        String severity) implements Serializable {
}
