package com.redkite.core.domain;

/** How strongly RedKite believes an inferred relationship ({@link ReleaseFamily},
 *  {@link CompatibilityRelationship}) reflects a genuine upstream fact, as opposed to a
 *  project-local, deterministic one ({@link ControlSet}, which doesn't need this scale — it's
 *  always exactly what the POM says). Only {@link #AUTHORITATIVE} or {@link #HIGH} should ever
 *  drive an automatic coordinated change; anything lower must be surfaced as a recommendation
 *  requiring review. */
public enum GroupingConfidence {
    AUTHORITATIVE,
    HIGH,
    MEDIUM,
    LOW,
    SUGGESTED
}
