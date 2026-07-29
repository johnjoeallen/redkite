# Rollback

If post-apply validation fails (see [Validation Process](validation-process.md)), RedKite reverts every POM file it wrote for that apply back to its exact pre-apply content — not just the file where the failure was attributed, every file touched by that apply, including every module's `pom.xml` in a multi-module project.

This is why RedKite always computes the full set of changes in memory first, and only writes to disk once it knows exactly which files it's about to touch — the same in-memory set is what gets written back verbatim on a rollback.

If the project was already failing before you applied anything (the pre-validate baseline), that's noted in the failure message, and the same revert logic still runs — RedKite doesn't leave a partially-applied change in place just because the project wasn't clean to begin with.

See [Failed POMs](failed-poms.md) for the diagnostic artifact RedKite leaves behind alongside the rollback.
