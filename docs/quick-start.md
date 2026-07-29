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

RedKite is a local Maven dependency analyser and update assistant. It analyses Maven projects — including multi-module builds — identifies available updates, vulnerabilities, and dependency conflicts, and lets you apply selected changes from a browser interface.

{: .note }
RedKite never modifies a project during analysis. Changes are made only after you select recommendations and click **Apply selected** — see [Apply changes](#apply-changes).

## Requirements

- Java 17 or later ([download](https://adoptium.net))
- Maven 3.9 or later

Both `java` and `mvn` must be available on the system `PATH` — RedKite shells out to Maven for dependency-tree resolution and build validation. Verify both before installing:

```bash
java -version
mvn -version
```

## 1. Download and run

Download the latest `red-kite-<version>.zip` from the [releases page](https://github.com/johnjoeallen/redkite/releases), then extract it.

On Linux or macOS:

```bash
unzip red-kite-<version>.zip -d red-kite
cd red-kite
./red-kite.sh
```

On Windows, extract the archive and run:

```bat
red-kite.bat
```

RedKite starts on port `6502` and stores its database under `~/.redkite`. Open the UI at:

```
http://localhost:6502
```

{: .note }
Need a different port, or to point RedKite at a different database? See [Configuration](#configuration) below.

## 2. Analyse a project

From the RedKite home page:

1. Enter the full path to the Maven project.
2. Click **Analyse**. A progress overlay shows while the analysis runs.
3. The browser navigates to the project's dashboard when it completes.

You can also click **Analyse** next to any previously-analysed project on the home page, or from inside an existing analysis, to re-scan it.

Each project's dashboard shows a summary of the latest analysis, an **Analysis history** of every past run, and the resolved `settings.xml` path and Maven repositories RedKite is using.

RedKite's analysis covers:

- direct dependencies
- transitive dependencies
- dependency-management entries
- build plugins
- available version updates
- known vulnerabilities (from OSV.dev)
- duplicate and conflicting dependency versions across modules

## 3. Review findings

The analysis view lists every dependency, grouped by module, with:

- a severity badge summarising known CVEs on that dependency
- **Findings** / **Clean** / **All** tabs, and filter chips for CVE status, conflicts, and origin (direct vs. transitive)
- a version selector for anything with a concrete recommendation — a CVE fix, a resolved convergence conflict, or (for direct dependencies) a plain available update

## Project build validation

RedKite validates a project before and after applying changes — it builds the project, and for Spring Boot projects, also starts it via `spring-boot:run`. Any extra Maven arguments or environment variables the project needs to build or start are entered once per project, on the project dashboard's **Build validation** panel, and reused for every apply.

Two fields are available there:

**Extra mvn arguments** — whitespace-separated arguments appended to every validation `mvn` call (both the build and the `spring-boot:run` check). For example, to select a Spring Boot profile:

```text
-Dspring-boot.run.profiles=redkite
```

To activate a Maven profile:

```text
-Predkite
```

Both can be combined:

```text
-Predkite -Dspring-boot.run.profiles=redkite
```

**Extra environment variables** — comma-separated `KEY=VALUE` pairs set on the spawned validation processes:

```text
SPRING_PROFILES_ACTIVE=redkite,DB_HOST=localhost
```

Click **Save** after entering the project's configuration — it's stored per project and applies to the next apply, no restart needed.

### Spring Boot projects

For RedKite to apply changes successfully to a Spring Boot project, the application must be able to build and start directly through Maven using the configuration entered on the project dashboard.

The configured profile doesn't have to be named `local` — any suitable profile works, such as `dev`, `test`, `desktop`, or a profile created specifically for this purpose, e.g. `redkite`. A dedicated `redkite` profile can be designed specifically for dependency validation, and should require as little external infrastructure as practical. A suitable profile might:

- use embedded databases
- connect to lightweight local services
- disable optional external integrations
- replace remote systems with local alternatives
- use safe development credentials
- avoid production-only infrastructure

The goal isn't to reproduce the full production environment — the application only needs to start reliably enough for RedKite to verify that dependency changes haven't broken it. Docker shouldn't be required for this: RedKite starts the project directly through Maven, so any services it needs should either be available locally, or disabled/replaced by the selected profile.

For example, a Maven profile and a Spring Boot profile used together:

```bash
mvn spring-boot:run \
  -Predkite \
  -Dspring-boot.run.profiles=redkite
```

{: .note }
Before applying changes to a Spring Boot project for the first time, verify the configured commands work outside RedKite — run the build (`mvn clean install -DskipTests -Predkite -Dspring-boot.run.profiles=redkite`) and the startup check (`mvn spring-boot:run -Predkite -Dspring-boot.run.profiles=redkite`) yourself first. Once both succeed on their own, RedKite can use the same configuration to validate dependency updates and conflict resolutions.

### Detecting duplicate/conflicting dependencies

RedKite's conflict detection is built around Maven Enforcer's `dependencyConvergence` and `requireUpperBoundDeps` rules. To get the most out of it in a multi-module project, enable both:

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <executions>
        <execution>
            <id>enforce-dependency-rules</id>
            <goals>
                <goal>enforce</goal>
            </goals>
            <configuration>
                <rules>
                    <dependencyConvergence/>
                    <requireUpperBoundDeps/>
                </rules>
            </configuration>
        </execution>
    </executions>
</plugin>
```

When RedKite resolves a duplicate or conflicting dependency version, the updated project must build successfully, and — for a Spring Boot project — start successfully through `spring-boot:run`. Both checks use the Maven arguments and environment variables configured in **Build validation**.

## Apply changes

From an analysis page:

1. Review the recommended dependency changes.
2. Select the changes to apply — apply conflict fixes (dependency-management pins and exclusions) before general upgrades, since applying an unrelated upgrade first can shift what "resolved" means for a conflict and invalidate the fix.
3. Click **Apply selected**.

RedKite then runs a bracketed validation sequence, using the Maven arguments and environment variables configured in **Build validation** for both passes:

1. Validates the project in its current state (`mvn clean install -DskipTests`, plus the Spring Boot startup check where applicable)
2. Writes the selected POM changes to disk
3. Validates the updated project the same way
4. Keeps the changes only if that second validation succeeds

If post-apply validation fails, RedKite reverts every POM change, reports the failure (attributing it to a specific dependency where possible), and saves the failed POM separately for investigation. If the project was already failing before you applied anything, that's noted too, and the same revert logic still runs. Once apply succeeds, RedKite automatically triggers a fresh analysis so you can see whether anything further needs attention.

General upgrades stay property-backed: a literal `<version>` tag is normalized to a `${artifactId.version}` property reference, and RedKite updates the property value. Dependency-management pins are reserved for conflict fixes and transitive overrides, and always use an explicit, hardcoded version rather than a property reference.

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

The gear icon in the top nav opens `/config`, where vulnerability and version metadata cache TTLs can be changed at runtime — no restart needed.

## Known limitations

- Maven projects only — no Gradle or npm
- Local repositories only
- No Docker or license scanning

## Next steps

- [View the project on GitHub](https://github.com/johnjoeallen/redkite)
- More of the manual is on its way — this page will link out to it as it's written.
