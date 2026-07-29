# Application Settings

RedKite is configured at startup through JVM system properties (`-D` flags) — there's no UI page for these, since they govern the server itself before it's reachable.

| Property | Default | Purpose |
|---|---|---|
| `redkite.port` | `6502` | HTTP port the server listens on |
| `redkite.db.url` | `jdbc:h2:~/.redkite/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE` | H2 database JDBC URL |
| `redkite.db.user` | `sa` | Database user |
| `redkite.db.password` | *(empty)* | Database password |
| `redkite.maven.repositories` | *(unset)* | Comma-separated list of repository URLs for metadata lookups, bypassing `settings.xml` discovery entirely — see [Maven Settings](maven-settings.md) |
| `redkite.osv.url` | `https://api.osv.dev` | Base URL for OSV vulnerability queries |

Example:

```bash
java -Dredkite.port=8080 -jar redkite.jar
```

## Database location

By default, RedKite stores its H2 database under `~/.redkite/` (`redkite.mv.db`, `redkite.trace.db`). Running the jar with `--drop-db` deletes these files and exits, without starting the server — useful for a clean-slate reset.

## Theme

The light/dark theme toggle in the UI is a local preference, not part of `rk_config` — it's stored separately and doesn't need a restart to take effect.
