package com.redkite.core.domain;

import java.util.List;

/**
 * One concrete, proposed way to update a dependency (or a group of dependencies sharing one
 * {@link ControlSet}) — the generalization of "upgrade recommendation" this replaces as the
 * editable unit. Several {@link DependencyFinding}s may resolve to one candidate update (see
 * {@link #findingsAddressed()}); one finding may also have several competing candidate updates —
 * {@link com.redkite.core.service.CandidateUpdateResolver} always groups by shared control set,
 * but callers comparing strategies for a single finding (e.g. "override locally" vs. "update the
 * parent" vs. "pin and ignore") construct the alternative candidates themselves.
 *
 * <p>Deliberately doesn't yet carry compatibility warnings, CVEs fixed/introduced, policy effects,
 * or a build/runtime risk score — those need, respectively, populated
 * {@link CompatibilityRelationship} data, a real cross-reference against vulnerability findings,
 * a policy-rule concept that doesn't exist yet, and a risk model. Adding empty placeholder fields
 * for them now would claim a completeness this doesn't have; they belong here once each has a
 * real algorithm behind it.
 *
 * @param conflictsWithUserPin whether this update would touch a coordinate the user has
 *      explicitly pinned — a real, computable signal (given the caller's known pinned
 *      coordinates), unlike the fields this deliberately omits.
 * @param introducesDowngrade  whether any resulting movement lowers a version.
 * @param overridesPlatform    whether this candidate shadows a parent's or an imported BOM's own
 *      management with a local override, rather than cooperating with it (e.g. by changing a
 *      property the platform's own managed entry already references).
 */
public record CandidateUpdate(
        UpdateAction action,
        /** Human-readable description of the one thing that would actually be edited — a
         *  property name, a dependencyManagement entry, a direct dependency's version. */
        String editableDeclaration,
        String oldValue,
        String proposedValue,
        String reason,
        List<DependencyFinding> findingsAddressed,
        ProposedChangeSet resultingChanges,
        RecommendationConfidence confidence,
        boolean autoApplySafe,
        boolean conflictsWithUserPin,
        boolean introducesDowngrade,
        boolean overridesPlatform) {
}
