# Why RedKite

There's no shortage of tools that look at your dependencies. RedKite's specific niche — local, build-validated, minimal-change remediation for Maven — is easiest to explain by contrast with two tools people usually already know: **Dependabot** and **Black Duck**. This isn't a feature-by-feature comparison (their feature sets are both broader than RedKite's in some directions); it's about a few real differences in approach that shape how each tool actually behaves day to day.

## vs. Dependabot

Dependabot is GitHub-native: it runs in GitHub's own infrastructure, opens a pull request per update (or per configured group), and leans on your existing CI to tell you whether that PR is safe. That's a good fit if your workflow already centers on PR review and you want updates to show up as normal, reviewable diffs.

RedKite works differently because it isn't trying to fit into that flow — it's a local tool with no GitHub dependency at all:

- **It runs the real build itself, before proposing anything's final.** Rather than opening a PR and waiting for your CI to catch a problem, RedKite validates by actually running `mvn clean install` (and, for Spring Boot projects, a real startup check) both before and after applying a change — see [Validation Model](validation-model.md). If validation fails, the change is rolled back automatically, on your machine, before you'd ever see a broken PR.
- **It resolves coordinated release families (BOMs) per artifact, not as one broadcast version.** A BOM often manages different members of the same family at different exact versions — see [Dependency Conflicts](../recommendations/dependency-conflicts.md) for the real Jackson example that motivated this. Getting this wrong produces a pin for a version that doesn't actually exist.
- **It writes directly to your POMs; it doesn't open a PR.** This is a genuine tradeoff, not a strict improvement — Dependabot's PR gives you review and CI-gating for free as part of your existing process; RedKite's local-apply model trades that for a tighter validate-before-you-commit loop, on the assumption that you'll review the resulting diff yourself before committing it, the same way you'd review any local change.

## vs. Black Duck

Black Duck (and tools like it) is enterprise software composition analysis: deep binary and snippet-level scanning, SBOM generation, license/IP risk auditing, and policy gates enforced centrally across many teams. It's built to answer "what's actually in our software, and does any of it violate policy" at an organizational scale — typically via a central server and a commercial license.

RedKite isn't trying to be that. It resolves license information the same way it resolves everything else — from declared POM metadata, walking the parent chain when needed (see [License Scanning](../analysis/license-scanning.md)) — not through binary composition analysis. There's no central server, no account, no policy engine spanning multiple teams. It's a single-developer, single-project tool you point at a Maven build and get an answer from immediately, not a compliance platform you roll out organization-wide.

## Philosophy: the smallest change that actually fixes it

This is the sharpest philosophical difference, and it shows up most clearly in how RedKite resolves a CVE.

Given a vulnerable dependency, RedKite doesn't reach for "the latest version" by default — it searches in three tiers, in order, stopping at the first one that works: the **smallest available upgrade** that clears the vulnerability entirely; if none exists, the **largest available version below where the vulnerability was introduced** (a downgrade); and only if neither fully resolves it, a **best-effort** candidate at the lowest achievable severity. See [Vulnerability Fixes](../recommendations/vulnerability-fixes.md). Every candidate at every tier is verified live against OSV.dev before being suggested, specifically so the fix doesn't turn out to carry an unrelated CVE of its own.

The reasoning: a version bump is a source of risk in its own right, independent of whether it fixes the CVE it was chosen for. A smaller jump means less unrelated code changed, less chance of an incompatible behavior change, and an easier change to reason about in review. "Always take latest" optimizes for staying current; RedKite's default optimizes for the smallest change that resolves the actual problem in front of you — which is also why a downgrade is on the table at all: a tool that only ever moves forward can't offer that option, even when it's the smaller, safer change.

This same instinct — smallest justified change, not "latest because you're touching it anyway" — is why RedKite doesn't recommend updating a transitive dependency just because a newer version exists (see [Transitive Dependencies](../analysis/transitive-dependencies.md)), and why non-CVE updates to direct dependencies stay within the current major version line rather than crossing it automatically (see [Version Updates](../recommendations/version-updates.md)). A configurable dial for exactly how minimal a fix should be — smallest-possible only, vs. latest-within-line, vs. latest-including-major — is planned but not built yet; see [Minimum Upgrade Policy](../recommendations/minimum-upgrade-policy.md).
