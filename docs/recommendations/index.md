# Recommendations

RedKite recommends a change for a dependency when there's a concrete reason to — not simply because a newer version exists. This section covers each of those reasons:

- [Version Updates](version-updates.md) — plain, non-CVE updates for direct dependencies
- [Vulnerability Fixes](vulnerability-fixes.md) — the three-tier CVE resolution
- [Transitive CVE Fixes](transitive-cve-fixes.md) — how vulnerability fixes apply to dependencies you don't declare directly
- [Dependency Conflicts](dependency-conflicts.md) — convergence conflicts across modules
- [Duplicate Dependencies](duplicate-dependencies.md) — enabling the Maven Enforcer rules RedKite's conflict detection relies on

Two related pages describe planned, not-yet-built behavior:

- [Parent and Ancestor Updates](parent-and-ancestor-updates.md)
- [Minimum Upgrade Policy](minimum-upgrade-policy.md)
