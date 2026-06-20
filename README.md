# RedKite

RedKite is a local Maven dependency reporting and upgrade-plan assistant for checked-out Java repositories.

It scans local working copies, builds a dependency inventory, checks cached or fetched Maven version metadata, records vulnerability findings when available, and lets you create local upgrade plans without pushing branches or opening pull requests.

## What It Does

- scans local Maven repositories
- shows direct and transitive dependencies
- highlights SNAPSHOT dependencies as unverified risks
- caches Maven version metadata and vulnerability metadata
- generates updated POM previews for selected upgrades
- keeps all data on the developer machine

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

## Apply Upgrades

After reviewing recommendations in the UI, select target versions using the dropdowns and click **Apply**. A popup appears with the updated POM content. Copy it and paste it into the file on disk.

## UI

From the UI at `http://localhost:6502` you can:

- browse projects and scans
- inspect dependency inventory
- review upgrade recommendations
- choose target versions and generate an updated POM preview
- copy the patched POM content to apply it locally

## Workflow

1. Start the server with `./red-kite.sh`.
2. Run `./red-kite.sh scan .` against a local Maven repository.
3. Review the scan in the UI.
4. Use the module dropdown to select a POM, adjust target versions, and click **Apply**.
5. Copy the updated POM from the popup and save it to disk.

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
