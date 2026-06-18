package com.redkite.core.domain;

import java.io.Serializable;

public record UpgradePlanItem(long recommendationId, PlannedFileChange fileChange) implements Serializable {
}
