# RedKite

RedKite is a local Maven dependency reporting and upgrade-plan assistant for checked-out Java repositories.

It scans local working copies, builds a dependency inventory, checks cached or fetched Maven version metadata, records vulnerability findings when available, and lets you create local upgrade plans without pushing branches or opening pull requests.

## What It Does

- scans local Maven repositories
- shows direct and transitive dependencies
- highlights SNAPSHOT dependencies as unverified risks
- caches Maven version metadata and vulnerability metadata
- creates upgrade plans from selected recommendations
- applies approved plans locally with the CLI
- keeps all Git and file mutations on the developer machine

## Requirements

- Java 17 or later ([download](https://adoptium.net))

## Install

Download the latest `red-kite-<version>.zip` from the [releases page](../../releases), then unzip it:

```bash
unzip red-kite-<version>.zip -d red-kite
cd red-kite
```

## Start The Server

```bash
./red-kite.sh
```

On Windows:

```bat
red-kite.bat
```

The server starts on port `6502` and stores its database in a `data/` subdirectory next to the JAR. Open the UI at:

```text
http://localhost:6502
```

## Scan A Repository

With the server running, open a second terminal and point the scan client at a local Maven repository:

```bash
./red-kite.sh scan /path/to/repo
```

Omit the path to scan the current directory:

```bash
./red-kite.sh scan
```

## Apply An Upgrade Plan

After reviewing recommendations in the UI and creating a plan, apply it locally:

```bash
./red-kite.sh apply-plan <planId>
```

The CLI creates a local branch and edits the Maven files. Changes are left uncommitted and nothing is pushed.

## UI

From the UI at `http://localhost:6502` you can:

- browse projects and scans
- inspect dependency inventory
- review upgrade recommendations
- select recommendations for an upgrade plan
- fetch the generated plan for local application

## CLI Flow

1. Start the server with `./red-kite.sh`.
2. Run `./red-kite.sh scan .` against a local Maven repository.
3. Review the scan in the UI.
4. Select one or more recommendations and create an upgrade plan.
5. Run `./red-kite.sh apply-plan <planId>` to apply it locally.
6. Confirm the branch name and file changes when prompted.

## Configuration

Pass JVM system properties to override defaults:

```bash
java -Dredkite.port=8080 -jar red-kite.jar
```

| Property | Default |
|---|---|
| `redkite.port` | `6502` |
| `redkite.db.url` | `jdbc:h2:./data/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE` |
| `redkite.db.user` | `sa` |
| `redkite.db.password` | _(empty)_ |

## Build From Source

Requires Maven 3.9+ and Java 17.

```bash
mvn package -DskipTests
```

The fat JAR is produced at `red-kite-server/target/red-kite-<version>.jar`.

## Known Limitations

- Maven projects only.
- Local repositories only.
- No remote Git hosting integration.
- No branch pushes or pull requests.
- No Gradle, npm, Docker, or license scanning.
