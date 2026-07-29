# Direct Dependencies

A direct dependency is one your project's own POM declares explicitly, in its own `<dependencies>` block (as opposed to being pulled in transitively by something else). RedKite marks each dependency's origin — **declared** (direct) or **transitive** — and this distinction affects what RedKite is willing to recommend:

- A direct dependency with a newer version available is always eligible for an update recommendation.
- A transitive dependency only gets an update recommendation when there's a concrete reason to move it — a fixable CVE, an active convergence conflict, or an existing pin. A transitive dependency with nothing forcing it to move is left alone by default, even if a newer version exists. See [Transitive Dependencies](transitive-dependencies.md) and [Minimum Upgrade Policy](../recommendations/minimum-upgrade-policy.md).

A direct dependency declared with a literal, hardcoded `<version>` (rather than a `${property}` reference) is itself flagged — see [Version Updates](../recommendations/version-updates.md) for why, and how RedKite normalizes it when applying a change.
