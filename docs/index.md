# RedKite

RedKite is a local Maven dependency analyser and update assistant. It analyses Maven projects, including multi-module builds, identifies available updates, vulnerabilities, and dependency conflicts, and lets you apply selected changes from a browser interface.

!!! note
    RedKite never modifies a project during analysis. Changes are made only after you select recommendations and click **Apply selected** — see [Applying Changes](applying-changes/index.md).

Everything runs on your own machine — no source code or dependency data leaves it except the version and vulnerability lookups RedKite makes on your behalf. See [Local-First Design](concepts/local-first-design.md).

[Get started :material-arrow-right:](getting-started/index.md){ .md-button .md-button--primary }
[View on GitHub :fontawesome-brands-github:](https://github.com/johnjoeallen/redkite){ .md-button }

## What it does

- Analyses Maven projects, including multi-module builds (dependencies, dependency management, and build plugins)
- Shows declared (direct) and transitive dependencies with scope and version source
- Highlights SNAPSHOT dependencies as unverified risks
- Fetches and caches version metadata from Maven Central
- Fetches and caches vulnerability data from OSV.dev
- Resolves and displays each dependency's declared license, with a project-wide breakdown and configurable permissiveness ranking
- Recommends updates grouped by module with per-component version selectors
- Resolves known CVEs in three tiers — an upgrade that clears the vulnerability, a downgrade below where it was introduced if no upgrade fixes it, or a best-effort suggestion at the lowest achievable severity if neither fully resolves it
- Detects dependency-management convergence conflicts across modules and proposes pins or exclusions to fix them
- Applies selected changes directly to the POMs on disk, validating the build before and after
- Keeps all data on the developer machine

## Where to start

<div class="grid cards" markdown>

- :material-rocket-launch:{ .lg .middle } **New to RedKite?**

    ---

    Install it and analyse your first project in a few minutes.

    [:octicons-arrow-right-24: Getting Started](getting-started/index.md)

- :material-source-branch:{ .lg .middle } **Curious how it got here?**

    ---

    The project's history, traced through its own git log.

    [:octicons-arrow-right-24: Evolution](development/evolution.md)

</div>
