# Database

RedKite stores all of its state in a local H2 database (see [Ports and Files](ports-and-files.md) for the file location).

| Table | Purpose |
|---|---|
| `projects` | Registered projects — id, name, root path, and per-project build validation settings |
| `scans` | One row per analysis run, holding the raw scan input and computed report |
| `metadata_cache_entries` | Per-component version/vulnerability/license metadata, tied to a specific scan and component |
| `source_poms` | Verbatim original POM XML captured at scan time, per file |
| `generated_poms` | RedKite-generated/patched POM XML, per file |
| `provider_rate_limit_state` | Rate-limiting/cooldown tracking per external metadata provider |
| `enforcer_results` | Maven Enforcer convergence check results and findings, per scan |
| `rk_version_cache` | Cached Maven Central (and other repository) version lookups — see [Cache Settings](../configuration/cache-settings.md) |
| `rk_vuln_cache` | Cached OSV.dev vulnerability responses |
| `rk_license_cache` | Cached POM-declared license lookups |
| `rk_license_rank` | License permissiveness ranking, used to pick which declared license "wins" for a component |
| `rk_config` | Runtime-configurable settings (cache TTLs, etc.) |
| `rk_schema_version` | Schema migration version marker |

There's no supported way to query this database directly through the UI — it's an implementation detail, not an API. If you need to inspect it directly for troubleshooting, it's a standard H2 file database and can be opened with the H2 console.
