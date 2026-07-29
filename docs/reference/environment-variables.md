# Environment Variables

RedKite's own process doesn't read any environment variables directly — all of its configuration is through [system properties](system-properties.md) set at launch.

The one place environment variables come into play is indirect: if your Maven `settings.xml` uses an `${env.VAR}` placeholder (typically for repository credentials), RedKite resolves that placeholder from its own process environment when reading that settings file — the same way Maven itself would. If the referenced variable isn't set in the environment RedKite is running in, the credential is silently dropped rather than causing a startup failure; see [Repository Resolution](../troubleshooting/repository-resolution.md).

This is separate from a project's own configured validation environment variables, which are stored in RedKite's database and only apply to the Maven processes RedKite spawns for that project's build validation — see [Environment Variables (project setting)](../projects/environment-variables.md).
