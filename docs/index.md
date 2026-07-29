---
title: Home
layout: home
nav_order: 1
---

# RedKite

RedKite is a local Maven dependency analyser and upgrade assistant. It analyses a Maven project, builds a dependency inventory, checks Maven Central for newer versions, records vulnerability findings from OSV.dev, and lets you select upgrades in the browser and generate a ready-to-apply updated POM.

Everything runs on your own machine — no source code or dependency data leaves it except the version/vulnerability lookups RedKite makes on your behalf.

[Quick Start](quick-start){: .btn .btn-primary } [View on GitHub](https://github.com/johnjoeallen/redkite){: .btn }

## What it does

- Analyses Maven multi-module projects (dependencies, dependency management, and build plugins)
- Shows declared (direct) and transitive dependencies with scope and version source
- Highlights SNAPSHOT dependencies as unverified risks
- Fetches and caches version metadata from Maven Central
- Fetches and caches vulnerability data from OSV.dev
- Recommends upgrades grouped by module with per-component version selectors
- Resolves known CVEs in three tiers — an upgrade that clears the vulnerability, a downgrade below where it was introduced if no upgrade fixes it, or a best-effort suggestion at the lowest achievable severity if neither fully resolves it
- Applies selected upgrades directly to the POMs on disk, validating the build before and after
- Keeps all data on the developer machine

This site is a work in progress — the [Quick Start](quick-start) guide is the first page up; more of the manual will follow.
