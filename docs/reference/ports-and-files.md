# Ports and Files

## Port

RedKite listens on port `6502` by default — configurable via [`redkite.port`](system-properties.md).

## Data directory

By default, RedKite stores everything under `~/.redkite/`:

| File | Contents |
|---|---|
| `redkite.mv.db`, `redkite.trace.db` | The H2 database — see [Database](database.md) |
| `preferences.properties` | Local UI preferences (theme, etc.) |
| `redkite.properties` | [System properties](system-properties.md), persisted — copied here from the release's bundled `red-kite.properties.default` on first run |

`--drop-db` (see [Command Line](command-line.md)) deletes the two database files.

## Files read from your project

| File | Contents |
|---|---|
| `.redkite/config.yml` | Extra Maven arguments, profile, Spring profile, and environment variables for build validation — see [Build Validation](../projects/build-validation.md). Written by you, not RedKite; entirely optional. |

## Files written inside your projects

| File | When | Contents |
|---|---|---|
| `pom.failed` | A validation build/startup fails during an apply | A snapshot of the exact POM that was being validated at the moment of failure, sibling to the real `pom.xml`. Overwritten by the next failure. See [Failed POMs](../applying-changes/failed-poms.md). |

RedKite never leaves any other file behind in a project it analyses — outside of an apply you explicitly triggered, the only files it writes are the POMs you selected changes for.
