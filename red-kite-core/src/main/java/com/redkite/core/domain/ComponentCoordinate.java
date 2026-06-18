package com.redkite.core.domain;

import java.io.Serializable;

public record ComponentCoordinate(String groupId, String artifactId) implements Serializable {
}
