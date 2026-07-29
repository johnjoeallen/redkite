# Validation Failures

This page covers what happens generically when validation fails during an apply, regardless of which specific check failed — see [Project Will Not Build](project-will-not-build.md) and [Spring Boot Will Not Start](spring-boot-will-not-start.md) for the failure reasons themselves.

## What you'll see

The apply UI shows an alert naming which validation phase failed, together with the extracted failure signature — the most informative line or two RedKite could find in the captured build/startup output. See [Validation Process](../applying-changes/validation-process.md) for the full pre-validate/write/post-validate sequence this is part of.

## What RedKite does automatically

- **Reverts the change.** Every file touched by the batch is restored to what it was before, across every module — not just the one that failed. See [Rollback](../applying-changes/rollback.md).
- **Snapshots the failing POM.** A `pom.failed` file is written next to the POM that was being validated, so you can inspect or reproduce the exact failure. See [Failed POMs](../applying-changes/failed-poms.md).
- **Offers to reset the selector.** If the failure output names a specific dependency coordinate that couldn't be resolved, the UI offers to put that dependency's version selector back to what it was before you changed it.

## What doesn't block an apply

A failure during the *pre-apply baseline* check — confirming the project builds before RedKite changes anything — is logged but doesn't stop the apply from proceeding. If your project doesn't build cleanly on its own, treat baseline failures as a signal to fix that first; a real post-apply failure and a pre-existing broken build can otherwise be hard to tell apart.
