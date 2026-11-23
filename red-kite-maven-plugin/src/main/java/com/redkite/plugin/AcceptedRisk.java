package com.redkite.plugin;

/**
 * A vulnerability the project has decided to live with, configured under {@code <acceptedRisks>} in the
 * plugin configuration. It stops being accepted after {@link #until}, so it cannot be forgotten.
 */
public class AcceptedRisk {
    /** GHSA or CVE identifier of the advisory. Required. */
    String advisory;
    /** {@code groupId:artifactId} or {@code groupId:artifactId:version}. Optional; without it the advisory is
     *  accepted on every dependency, and with a version it stops applying when that version changes. */
    String coordinate;
    /** Why the risk is acceptable. Optional, shown in the report. */
    String reason;
    /** Last day (ISO {@code yyyy-MM-dd}, inclusive) on which the risk is accepted. Required. */
    String until;

    public AcceptedRisk() {}

    AcceptedRisk(String advisory, String coordinate, String reason, String until) {
        this.advisory = advisory;
        this.coordinate = coordinate;
        this.reason = reason;
        this.until = until;
    }

    @Override
    public String toString() {
        return advisory + (coordinate == null || coordinate.isBlank() ? "" : " on " + coordinate);
    }
}
