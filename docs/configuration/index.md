# Configuration

RedKite's configuration lives in three places:

- **Application settings** — JVM system properties, settable persistently via a config file or per-launch with a `-D` flag. See [Application Settings](application-settings.md).
- **Per-project settings** — a `.redkite/config.yml` file checked into each project itself. See [Project Settings](project-settings.md).
- **Cache TTLs** — stored in the database, editable from the `/config` page in the UI. See [Cache Settings](cache-settings.md).
- **License permissiveness ranking** — also stored in the database and editable from the `/config` page. See [License Scanning](../analysis/license-scanning.md#permissiveness-ranking).

For how RedKite locates and invokes Maven itself, see [Maven Settings](maven-settings.md).
