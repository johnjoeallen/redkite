# Repository Resolution

When RedKite can't resolve a dependency's metadata or POM, the problem is usually in how it discovered your repositories — see [Maven Settings](../configuration/maven-settings.md) for the discovery order (project-local `settings.xml`, then `~/.m2/settings.xml`, mirrors, and Maven Central as a fallback).

## How RedKite tells "doesn't exist" from "couldn't check"

For each repository it tries, RedKite distinguishes three outcomes: found, confirmed not found (HTTP 404), or a fetch error (any other status, timeout, or connection failure). If *any* configured repository confirms an artifact genuinely doesn't exist, that verdict wins over an inconclusive error from another repository — so an unreachable internal mirror won't be mistaken for "this version doesn't exist" when the real answer is available elsewhere, and conversely a real 404 from your authoritative repository isn't hidden by a flaky secondary one.

## Authentication

A repository that responds `401 Unauthorized` is retried once with credentials matched from `settings.xml` by mirror ID. If a credential in `settings.xml` uses an `${env.VAR}` placeholder and that environment variable isn't set (or is empty) in the environment RedKite is running in, the credential is silently dropped — the request proceeds without it and will likely still return `401`. Check that the referenced environment variable is actually set wherever the RedKite process runs, not just in your normal shell.

## Bypassing discovery entirely

If your `settings.xml` setup is complex enough to fight, `-Dredkite.maven.repositories=<comma-separated URLs>` at startup skips discovery and uses exactly the list you give it — see [Application Settings](../configuration/application-settings.md).
