# OSV Data

RedKite gets vulnerability data from [OSV.dev](https://osv.dev), Google's open-source vulnerability database. OSV aggregates advisories from multiple sources, including GitHub Security Advisories, so a single query covers more than just a raw NVD/CVE feed.

## What gets queried

For each `groupId:artifactId` RedKite encounters, it queries OSV's Maven ecosystem endpoint once for *every* advisory ever published against that package — not one query per version. RedKite then evaluates each advisory's affected-version ranges itself against whichever version it's actually checking. This means checking a component at several different versions (for example, while searching for a fix candidate) costs one network round trip, not one per version tried.

## Caching

Results are cached in two layers:

- **In-memory**, for the lifetime of the current process — both the raw per-package advisory list and the computed findings for a specific `package@version`.
- **Database-backed** (`rk_config`-configurable TTL, 24 hours by default), so a restart doesn't force every project back out to OSV immediately.

A failed OSV query is never cached as "no known vulnerabilities" — only a genuine, successful response is persisted, so a transient network problem doesn't hide a real CVE until the cache TTL happens to expire.

You can force a full refresh from the [cache settings](../configuration/cache-settings.md) page.
