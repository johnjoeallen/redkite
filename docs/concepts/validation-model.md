# Validation Model

RedKite treats "the project still builds" as a fact to verify, not assume, both before and after it changes anything.

## Baseline, then apply, then re-check

Applying a batch of changes runs through four phases:

1. **Pre-validate.** Before touching any file, RedKite validates the project exactly as it stands — a baseline. This confirms the project already builds (and, for Spring Boot projects, already starts) before RedKite's changes are even in the picture.
2. **Apply.** Every modified POM in the batch is written to disk together.
3. **Post-validate.** RedKite validates again, now with the changes in place, using the same build (and startup, if applicable) check.
4. **Keep or revert.** If post-validation passes, the changes stay. If it fails, every file touched by the batch — not just the one that seems responsible — is restored to what it was before.

The baseline check is informational rather than a hard gate: if your project doesn't build cleanly to begin with, the apply still proceeds (there's nothing meaningful for RedKite to compare against otherwise), but a failure is only ever attributed to a specific dependency when the baseline had passed — attributing a failure that was already there before RedKite touched anything would be misleading.

See [Validation Process](../applying-changes/validation-process.md) and [Rollback](../applying-changes/rollback.md) for what this looks like in the UI, and [Failed POMs](../applying-changes/failed-poms.md) for the diagnostic snapshot left behind on failure.

## Why this shape

Computing whether a change is *worth* applying — is this the smallest fix, does it clear a CVE, does it converge a conflict — is a static analysis RedKite can do with confidence. Whether the change actually *works*, though, depends on your project's own build in ways no static analysis can fully predict: plugin behavior, test wiring, runtime configuration. Running the real build (and, where applicable, a real startup) is the only way to be sure, so RedKite always does it rather than trusting its own recommendation blindly.
