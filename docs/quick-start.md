---
title: Quick Start
nav_order: 2
---

# Quick Start
{: .no_toc }

Get RedKite running and analyse your first project in a few minutes.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Requirements

- Java 17 or later ([download](https://adoptium.net))
- Maven 3.9+, available on `PATH` (RedKite shells out to it for dependency-tree resolution)

## 1. Install

Download the latest `red-kite-<version>.zip` from the [releases page](https://github.com/johnjoeallen/redkite/releases), then unzip it:

```bash
unzip red-kite-<version>.zip -d red-kite
cd red-kite
```

## 2. Start the server

```bash
./red-kite.sh
```

On Windows:

```bat
red-kite.bat
```

The server starts on port `6502` and stores its database under `~/.redkite`. Open the UI at:

```
http://localhost:6502
```

{: .note }
Need a different port, or to point RedKite at a different database? See [Configuration](#configuration) below.

## 3. Analyse a project

On the home page, type the full path to a Maven project and click **Analyse**. A progress overlay shows while the analysis runs; the browser navigates to the analysis when it completes.

You can also click **Analyse** next to any previously-analysed project on the home page, or from inside an existing analysis, to re-scan it.

Each project also gets its own page showing a summary of the latest analysis, an **Analysis history** of every past run, and the resolved `settings.xml` path and Maven repositories RedKite is using.

## 4. Review findings

The analysis view lists every dependency, grouped by module, with:

- a severity badge summarising known CVEs on that dependency
- **Findings** / **Clean** / **All** tabs, and filter chips for CVE status, conflicts, and origin (direct vs. transitive)
- a version selector for anything with a concrete recommendation — a CVE fix, a resolved convergence conflict, or (for direct dependencies) a plain available update

## 5. Apply upgrades

Adjust target versions in the dropdowns and click **Apply selected**. RedKite runs a bracketed validation sequence:

1. Builds the project in its current state (`mvn clean install -DskipTests`)
2. Writes all POM changes to disk
3. Builds again to confirm the changes produce a working build

If post-apply validation fails, RedKite reverts every POM change and reports the failure, attributing it to a specific dependency where possible. If the project was already failing before you applied anything, that's noted too, and the same revert logic still runs. Once apply succeeds, RedKite automatically triggers a fresh analysis so you can see whether anything further needs attention.

{: .note }
Apply conflict fixes (dependency-management pins and exclusions) before applying general upgrades. Conflicts pin a dependency to a specific resolved version across modules, so applying an unrelated upgrade first can shift what "resolved" means and invalidate the conflict fix.

## Configuration

Pass JVM system properties to override defaults:

```bash
java -Dredkite.port=8080 -jar red-kite.jar
```

| Property | Default |
|---|---|
| `redkite.port` | `6502` |
| `redkite.db.url` | `jdbc:h2:~/.redkite/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE` |
| `redkite.db.user` | `sa` |
| `redkite.db.password` | *(empty)* |
| `redkite.prefs.file` | `~/.redkite/preferences.properties` |
| `redkite.osv.url` | `https://api.osv.dev` |
| `redkite.version.lookback` | `10` — how many older releases the version-selector dropdown offers below the current version |

Some projects need a Spring profile or other environment-specific configuration to build or start (used for the `spring-boot:run` startup check during apply). Set these per project on the **Build validation** panel on each project's page:

- **Extra mvn arguments** — e.g. `-Pdev -Dspring.profiles.active=dev`
- **Extra environment variables** — e.g. `SPRING_PROFILES_ACTIVE=dev,DB_HOST=localhost`

The gear icon in the top nav opens `/config`, where vulnerability and version metadata cache TTLs can be changed at runtime — no restart needed either way.

## Known limitations

- Maven projects only — no Gradle or npm
- Local repositories only
- No Docker or license scanning

## Next steps

- [View the project on GitHub](https://github.com/johnjoeallen/redkite)
- More of the manual is on its way — this page will link out to it as it's written.
