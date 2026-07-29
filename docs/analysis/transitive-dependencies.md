# Transitive Dependencies

A transitive dependency is one your project pulls in indirectly — declared by a direct dependency, a parent POM, or an imported BOM, not by your own project's `<dependencies>` block.

RedKite deliberately does **not** recommend updating a transitive dependency just because a newer version exists. A transitive dependency needs a concrete reason to move:

- a fixable CVE (see [Vulnerability Fixes](../recommendations/vulnerability-fixes.md) and [Transitive CVE Fixes](../recommendations/transitive-cve-fixes.md))
- an active dependency-convergence conflict (see [Dependency Conflicts](../recommendations/dependency-conflicts.md))
- an existing `dependencyManagement` pin for that coordinate

Without one of those, a transitive dependency with a newer release available is treated as clean — it still shows an informational "Update available" (or "Major update available") note so you know one exists, but it isn't counted as a finding needing attention. See [Minimum Upgrade Policy](../recommendations/minimum-upgrade-policy.md) for the reasoning.

## Child dependency vulnerabilities

Even when a dependency itself is clean, something it pulls in transitively might not be. Each dependency's card shows an "In dependencies" summary — a count of CVEs by severity found among its own transitive subtree, deduplicated so a dependency reachable through more than one path is only counted once. Hovering a severity count shows exactly which child dependency and advisory it refers to.
