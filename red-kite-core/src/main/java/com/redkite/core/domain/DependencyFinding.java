package com.redkite.core.domain;

/**
 * One reason a dependency needs attention. A {@link ScanComponent} may carry several of these —
 * unlike {@link RemediationStatus}'s flat booleans, findings are a list, not a set of mutually
 * exclusive flags.
 *
 * @param severity only meaningful for {@link DependencyFindingReason#CVE}; {@code null} otherwise.
 */
public record DependencyFinding(
        long componentId,
        DependencyFindingReason reason,
        String description,
        AdvisorySeverity severity) {

    public DependencyFinding(long componentId, DependencyFindingReason reason, String description) {
        this(componentId, reason, description, null);
    }
}
