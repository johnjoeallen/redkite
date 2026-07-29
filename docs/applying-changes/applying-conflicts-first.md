# Applying Conflicts First

If you have both a dependency-conflict fix and a general version update selected at the same time, apply the conflict fix first, in its own apply, before applying the general update.

A conflict fix pins a dependency to a specific resolved version across every module that touches it. Applying an unrelated update first can shift what "resolved" means for that dependency throughout the tree, which can invalidate the conflict fix you were about to apply next — you'd then need to re-check convergence after the fact rather than trusting the fix as computed.

This ordering isn't enforced by RedKite — it's a recommendation. See [Dependency Conflicts](../recommendations/dependency-conflicts.md) for how conflict fixes are computed in the first place.
