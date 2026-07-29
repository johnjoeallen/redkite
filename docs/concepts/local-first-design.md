# Local-First Design

RedKite runs entirely on your own machine. There's no account to create, no cloud service it depends on, and no telemetry — the only outbound network calls it makes are the ones you'd expect from Maven itself: fetching dependency metadata from your configured Maven repositories, and querying OSV.dev for vulnerability data.

## What "adding a project" actually is

A project in RedKite is a local filesystem path — RedKite requires it to already exist on disk and contain a `pom.xml`. There's no option to add a project by git URL; RedKite never clones a repository on your behalf. See [Adding a Project](../projects/adding-a-project.md).

## Where your data lives

Everything RedKite knows — registered projects, scan history, cached metadata — is stored in a local H2 database file on your machine. See [Database](../reference/database.md) for the schema, and [Ports and Files](../reference/ports-and-files.md) for where it's stored on disk.

## Why this matters

RedKite reads and, when you choose to apply a change, writes files in projects that may contain proprietary code or reference internal/private Maven repositories. Keeping everything local means none of that ever needs to leave your machine for RedKite to do its job.
