# Maven Settings

RedKite invokes the Maven binary already installed on your system (`mvn`, or `mvn.cmd` on Windows) — it does not bundle its own copy. This is what `mvn -version` needs to succeed for, per [Requirements](../getting-started/requirements.md).

## Where it looks for `settings.xml`

For a given project, RedKite resolves `settings.xml` in this order:

1. `<project root>/.m2/settings.xml`
2. A `-s`/`--settings` path declared in the project's `<project root>/.mvn/maven.config`
3. `~/.m2/settings.xml`
4. Otherwise, none — Maven's own built-in defaults apply

If a project-local settings file is used (options 1 or 2), RedKite passes it explicitly via `-s` on every Maven invocation it runs for that project, so validation builds see exactly the same settings a developer running `mvn` from that project root would.

## Repository resolution for metadata lookups

Separately from running builds, RedKite needs to know which repositories to query when looking up version metadata and POMs (for update recommendations, license data, and BOM resolution). It derives this from the resolved `settings.xml`: active-profile `<repositories>` entries, plus mirrors (`mirrorOf` covering `central`, `*`, or `external:*`), with Maven Central added automatically unless it's already covered by a mirror. Server credentials are matched by mirror ID, with `${env.VAR}` placeholders in `settings.xml` resolved from the environment RedKite itself is running in.

Lookups try anonymously first and only retry with the configured credentials if the server responds `401`.

To bypass this discovery entirely — for example, in a locked-down environment — start RedKite with `-Dredkite.maven.repositories=` set to a comma-separated list of repository URLs; see [Application Settings](application-settings.md).

## Local repository

Before making any network call, RedKite checks your local Maven repository (`~/.m2/repository`) for an already-downloaded copy of a POM — a project that's been built locally at least once will have much of RedKite's metadata resolution satisfied without any network access at all.
