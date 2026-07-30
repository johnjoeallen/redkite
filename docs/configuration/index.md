# Configuration

RedKite's configuration lives in three places:

- **Application settings** — JVM system properties set at server startup (port, database location). See [Application Settings](application-settings.md).
- **Per-project settings** — set through each project's own page in the UI. See [Project Settings](project-settings.md).
- **Cache TTLs** — stored in the database, editable from the `/config` page in the UI. See [Cache Settings](cache-settings.md).
- **License permissiveness ranking** — also stored in the database and editable from the `/config` page. See [License Scanning](../analysis/license-scanning.md#permissiveness-ranking).

There is no separate `config.rk` file today — see [Future config.rk](future-config-file.md) for where that's headed. For how RedKite locates and invokes Maven itself, see [Maven Settings](maven-settings.md).
