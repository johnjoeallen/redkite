package com.redkite.core.domain;

import java.io.Serializable;

public record ComponentVersion(String version, VersionSource source) implements Serializable {
}
