# Parent and Ancestor Updates

!!! warning "Status: Planned"
    This page describes a capability that does not exist yet. Today, RedKite's fix for a vulnerable or conflicting dependency is always a direct pin on that dependency's own coordinates — see [Transitive CVE Fixes](transitive-cve-fixes.md) and [Dependency Conflicts](dependency-conflicts.md) for what actually happens right now.

## The idea

Sometimes the "correct" fix for a transitive dependency isn't a pin on that dependency at all — it's an update to whatever actually controls its version: the direct dependency that pulled it in, an imported BOM, or the project's parent POM. Moving to a newer release of the direct dependency, BOM, or parent might resolve the vulnerability (or the conflict) without needing a standalone override, and keeps the project's dependency graph closer to a version combination its upstream maintainers actually tested together.

## What this would add

- Recommending an ancestor update (direct dependency, BOM import, or parent POM bump) as an alternative to a direct pin, when doing so would resolve the same finding
- Surfacing which option — pin vs. ancestor update — is likely to touch fewer other dependencies
- Falling back to today's direct-pin behavior whenever no ancestor update actually resolves the finding

## Related

- [Transitive CVE Fixes](transitive-cve-fixes.md)
- [Dependency Conflicts](dependency-conflicts.md)
- [Planned Features](../roadmap/planned-features.md)
