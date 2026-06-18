package com.redkite.core.domain;

import java.io.Serializable;

public record DependencyEdge(String fromComponentId, String toComponentId, DependencyScope scope, boolean direct) implements Serializable {
}
