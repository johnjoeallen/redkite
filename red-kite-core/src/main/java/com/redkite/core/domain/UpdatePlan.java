package com.redkite.core.domain;

import java.util.List;

/**
 * Alternative {@link CandidateUpdate} strategies for addressing the same finding(s) — lets a
 * caller compare options (e.g. "override locally" vs. "change the shared property" vs. "pin and
 * revisit later") rather than treating the first computable fix as the only one. See
 * {@link com.redkite.core.service.UpdatePlanBuilder} for what alternatives are actually
 * constructible today; not every strategy the design brief describes has a real algorithm behind
 * it yet (an "update the parent to a newer release" or "import a newer BOM" option needs
 * cross-referencing external version metadata for the parent/BOM coordinate itself, which isn't
 * wired up here).
 */
public record UpdatePlan(List<DependencyFinding> findingsAddressed, List<CandidateUpdate> candidates) {
}
