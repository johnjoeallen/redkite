# Cache Settings

RedKite caches network lookups (Maven Central metadata, OSV vulnerability data, POM-declared licenses) so repeated analyses don't re-fetch the same data. Each cache has a time-to-live (TTL), configurable from the `/config` page in the UI, stored in the database so a change takes effect on the next lookup without a restart.

| Setting | Default | Covers |
|---|---|---|
| Vulnerability cache | 24 hours | OSV.dev advisory lookups |
| Version cache (Maven Central) | 24 hours | Latest-version metadata from Maven Central |
| Version cache (local/internal repos) | 1 hour | Latest-version metadata from non-Central repositories |
| Version cache (not found) | 6 hours | A confirmed "artifact/version doesn't exist" result |
| Version cache (errors) | 15 minutes | A failed lookup (network/transport error) — kept short so a transient outage doesn't get treated as a long-lived fact |
| License cache | 30 days | POM-declared license lookups, which change far less often than version data |

The config page offers a set of common TTL choices (15 min – 24 hours); a value outside that set — set some other way — is shown as a custom duration.

## Clearing the cache

Each scan report page has a **Clear cache** action that wipes the version, vulnerability, and license caches (both the in-memory copies and their database-backed tables) — see [Clearing the Cache](../troubleshooting/clearing-the-cache.md) for when you'd want to do this.
