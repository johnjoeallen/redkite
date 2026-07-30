# Application Settings

RedKite is configured at startup, before it's reachable, so there's no UI page for these — either through a config file at `~/.redkite/redkite.properties`, or through JVM system properties (`-D` flags), which always take precedence over the file.

| Property | Default | Purpose |
|---|---|---|
| `redkite.port` | `6502` | HTTP port the server listens on |
| `redkite.db.url` | `jdbc:h2:~/.redkite/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE` | H2 database JDBC URL |
| `redkite.db.user` | `sa` | Database user |
| `redkite.db.password` | *(empty)* | Database password |
| `redkite.maven.repositories` | *(unset)* | Comma-separated list of repository URLs for metadata lookups, bypassing `settings.xml` discovery entirely — see [Maven Settings](maven-settings.md) |
| `redkite.osv.url` | `https://api.osv.dev` | Base URL for OSV vulnerability queries |

Example, as a `-D` flag:

```bash
java -Dredkite.port=8080 -jar redkite.jar
```

## The config file

`red-kite.sh` and `red-kite.bat` copy a bundled `red-kite.properties.default` (sitting alongside `red-kite.jar` in the release) to `~/.redkite/redkite.properties` the first time they're run, if that file doesn't already exist. Edit any of the properties above there and restart the server — no need to remember `-D` flags on every launch. A `-D` flag still overrides whatever the file says, so it's safe to use one to try a value without touching the file.

If you're running the jar directly rather than through the launcher scripts, the file isn't created automatically — copy it yourself, or use `-D` flags instead.

## Database location

By default, RedKite stores its H2 database under `~/.redkite/` (`redkite.mv.db`, `redkite.trace.db`). Running the jar with `--drop-db` deletes these files and exits, without starting the server — useful for a clean-slate reset.

## Theme

The light/dark theme toggle in the UI is a local preference, not part of `rk_config` — it's stored separately and doesn't need a restart to take effect.
