# Clearing the Cache

RedKite caches version metadata, vulnerability data, and license lookups — see [Cache Settings](../configuration/cache-settings.md) for the TTLs. Most of the time these caches are exactly what you want: they keep repeated analyses fast and avoid hammering Maven Central or OSV.dev. Occasionally, though, the cached answer is stale enough to be actively misleading.

## When to clear it

- **A fix or newer version was just published upstream**, but RedKite still reports the old "latest" version or "no fix available" — the positive-result cache (up to 24 hours) hasn't expired yet.
- **A dependency that genuinely doesn't exist got fixed upstream** (rare, but possible for a freshly-published artifact that briefly 404'd) — the negative-result cache holds a "not found" answer for up to 6 hours.
- **A transient network problem got cached as an error** — this one clears itself fastest (15 minutes), so it's rarely worth clearing manually, but it's the first thing to suspect if a single dependency's data looks wrong right after a network blip.

## How

Each scan report page has a **Clear cache** action. It wipes all three caches — version metadata, vulnerabilities, and licenses — both in memory and in the database, for every project, not just the one you're viewing. There's no UI option to clear just one project's cached entries or just one cache type.

After clearing, the next analysis re-fetches everything it needs live, so expect it to take longer than usual.
