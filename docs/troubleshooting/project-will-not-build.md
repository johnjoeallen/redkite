# Project Will Not Build

Build validation runs `mvn clean install -DskipTests -Denforcer.skip=true` against your project. If a change RedKite is about to apply (or just applied) makes the build fail, here's what to check.

## Read the failure signature first

RedKite extracts a short failure signature from the build output — the first `[ERROR]` line if there is one, otherwise the first line mentioning an exception, otherwise the last portion of the raw output. This is shown directly in the failure alert, and is usually enough to tell you whether the problem is a real compile/test failure, a dependency that couldn't be resolved, or something else.

## Check `pom.failed`

When a build fails during validation, RedKite writes a snapshot of the POM it just tried — a sibling file named `pom.failed`, next to the `pom.xml` it validated. This captures exactly what was being built at the moment of failure, which is useful if you want to reproduce the failure yourself by running Maven directly against that snapshot. Each new failure overwrites the previous `pom.failed` for that module. See [Failed POMs](../applying-changes/failed-poms.md).

## If it happened during Apply

A failure during the post-apply validation step causes RedKite to revert every file it changed for that batch back to what they were before — see [Rollback](../applying-changes/rollback.md). If the failure was attributable to a specific dependency coordinate (RedKite recognizes "could not resolve/find artifact" messages), the UI also offers to reset that dependency's selector back to its previous value.

A failure during the *pre-apply baseline* check (confirming the project builds before RedKite touches anything) doesn't block the apply — it's only logged. If your project doesn't build cleanly to begin with, fix that first; validation results after that point won't be reliable.
