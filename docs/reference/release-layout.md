# Release Layout

RedKite is built as a multi-module Maven reactor:

| Module | Contents |
|---|---|
| `red-kite-core` | Pure domain model and shared logic (no dependency on the other modules) |
| `red-kite-maven` | Maven-facing logic: dependency-tree scanning, POM parsing, managed-version resolution, build/startup validation |
| `red-kite-metadata` | External data sources — Maven Central version lookups, OSV.dev vulnerability lookups |
| `red-kite-server` | The embedded HTTP server, web UI, and database layer; depends on the other three |

## The distributable

`red-kite-server` is packaged as a single shaded (fat) jar containing every module and their dependencies, with `com.redkite.server.RedKiteServerMain` as its entry point. Building from source with `mvn package -DskipTests` produces it at `red-kite-server/target/red-kite-<version>.jar` — see [Building from Source](../development/building-from-source.md).

A packaged release is a zip containing:

- `red-kite.jar` — the fat jar
- `red-kite.sh` / `red-kite.bat` — launcher scripts for Linux/macOS and Windows

Download and unzip it, then run the launcher script for your platform — see [Installation](../getting-started/installation.md).
