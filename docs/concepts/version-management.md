# Version Management

RedKite compares versions with a tolerant, mostly-semantic comparator rather than requiring strict `MAJOR.MINOR.PATCH` formatting.

## Comparing two versions

Both version strings are normalized (hyphens treated the same as dots) and split into tokens, compared token by token: each pair of tokens is compared numerically when both are numbers, and falls back to a plain string comparison otherwise. This means a version like `1.0.0.Final` or `1.0.0-RC1` compares sensibly against `1.0.0` without needing special-case handling — the non-numeric trailing token just breaks the tie lexically once every numeric token has matched. A version with fewer tokens than the one it's compared against is padded with zeros.

## "Same release line"

Several places in RedKite — reconciling a computed conflict-fix winner against a project's own declared version, deciding whether an update is "Update available" vs. "Major update available" — need to ask whether two versions are on the same release line. RedKite defines this as matching on the first two dot/hyphen-separated tokens (`major.minor`) — so `1.5.25` and `1.5.38` are the same release line, but `1.5.x` and `1.6.x` are not, even though both share a major version.
