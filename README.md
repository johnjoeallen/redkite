# RedKite

RedKite is a local Maven dependency reporting and upgrade-plan assistant for checked-out Java repositories.

It scans local working copies, builds a dependency inventory, checks cached or fetched Maven version metadata, records vulnerability findings when available, and lets you create local upgrade plans without pushing branches or opening pull requests.

## What It Does

- scans local Maven repositories
- shows direct and transitive dependencies
- highlights SNAPSHOT dependencies as unverified risks
- caches Maven version metadata and vulnerability metadata in PostgreSQL
- creates upgrade plans from selected recommendations
- applies approved plans locally with the CLI
- keeps all Git and file mutations on the developer machine

## Requirements

- Java 17
- Docker and Docker Compose
- PostgreSQL 16 or compatible

## Start The Server

Start the full local stack on port `6502`:

```bash
./scripts/red-kite.sh start
```

The server is available at:

```text
http://localhost:6502
```

## Scan A Repository

Run a scan against a local checked-out Maven repository:

```bash
./scripts/red-kite.sh scan /path/to/repo
```

If you omit the path, the current directory is scanned.

## Open The Database

Open a `psql` session against the local PostgreSQL container:

```bash
./scripts/red-kite.sh db
```

## Stop The Stack

```bash
./scripts/red-kite.sh stop
```

## UI

Open the local UI in a browser:

```text
http://localhost:6502/
```

From the UI you can:

- browse projects and scans
- inspect dependency inventory
- review upgrade recommendations
- select recommendations for an upgrade plan
- fetch the generated plan for local application

## CLI Flow

Typical flow:

1. Start `red-kite-server`.
2. Run `red-kite scan .` against a local Maven repository.
3. Review the scan in the UI.
4. Select one or more recommendations.
5. Create an upgrade plan.
6. Run `red-kite apply-plan <planId>`.
7. Confirm the local branch and file changes.
8. Let the CLI create the branch and apply the Maven file edits.

The CLI leaves changes uncommitted by default and does not push anything.

## Configuration

Database settings:

- `redkite.db.url`
- `redkite.db.user`
- `redkite.db.password`

Port:

- `redkite.port`

Default server port:

- `6502`

## Build

Compile everything with Java 17:

```bash
rm -rf /tmp/redkite-classes
mkdir -p /tmp/redkite-classes
javac --release 17 -d /tmp/redkite-classes $(find red-kite-core/src/main/java red-kite-git/src/main/java red-kite-maven/src/main/java red-kite-metadata/src/main/java red-kite-server/src/main/java red-kite-scan/src/main/java -name '*.java')
```

## Known Limitations

- Maven projects only.
- Local repositories only.
- PostgreSQL-backed persistence.
- No remote Git hosting integration.
- No branch pushes.
- No pull requests.
- No Gradle, npm, Docker, or license scanning.

## GitHub Description

Use this short description for the GitHub repository:

> Local Maven dependency reporting and upgrade planning for checked-out Java repositories, with PostgreSQL-backed scans and local-only plan application.
