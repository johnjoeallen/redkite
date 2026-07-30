# License Scanning

Every dependency's declared license is resolved and shown alongside its version and vulnerability status — for both direct and transitive dependencies.

## How a license is resolved

RedKite reads the `<licenses>` block from the dependency's own POM. If that POM doesn't declare one, RedKite walks up its `<parent>` chain (up to 10 levels) looking for a declaration there — the same general idea as [parent/BOM version resolution](../concepts/parent-bom-and-ancestor.md), though this walk is simpler: it only follows `<parent>`, not imported BOMs or `${property}` references. If nothing in the reachable chain declares a license, the dependency is shown with no license — RedKite doesn't currently distinguish "genuinely has no declared license" from "couldn't fetch a POM to check."

A dependency that declares more than one license (dual-licensing) keeps all of them — nothing is collapsed at resolution time.

## Canonicalizing license names

Raw declared strings vary wildly ("The Apache Software License, Version 2.0", "Apache 2.0", "Apache License, Version 2.0" all mean the same thing). RedKite maps known raw strings to a short canonical name via a fixed lookup table, plus one pattern rule for "Apache License, Version N" in general. An unrecognized raw string is shown as-is rather than guessed at.

This canonicalization is deliberately conservative about what it treats as equivalent — a few examples:

- `GPL-2.0 WITH Classpath-exception` is never merged with plain `GPL-2.0-only`, since the exception meaningfully changes what the license permits
- `LGPL-2.1-only`, `LGPL-2.1-or-later`, and `LGPL-3.0` are kept distinct from each other and from a bare "LGPL"
- `MIT-0` is kept distinct from `MIT`
- `BSD-2-Clause` is kept distinct from `BSD-3-Clause`

A dependency card shows the canonical short name as its badge, with the original raw declared string available in a tooltip whenever it differs from the canonical name.

## Permissiveness ranking

Canonical license names are ranked from most to least permissive — RedKite ships with a sensible default order (roughly: public-domain-style licenses, then MIT/BSD-family, then Apache/Mozilla/Eclipse-family, then the LGPL/GPL family), editable from the `/config` page alongside the [cache TTL settings](../configuration/cache-settings.md). An unranked canonical name is never treated as more or less permissive than anything — it's just not considered for the "most permissive" pick below.

## The "most permissive" badge

When a dependency has more than one declared license, RedKite highlights whichever one ranks most permissively, using the table above. A dependency with only a single declared license is still eligible for this highlight — it's trivially "the most permissive of one" — so scanning a page of cards shows at a glance which dependencies carry a known-permissive license at all, not just which ones had a real choice between licenses.

## Counting

The license breakdown panel counts each dependency under exactly one bucket — its single license, or its most-permissive one if it declared several — never once per declared license. This keeps a dual-licensed dependency from inflating every license bucket it happens to touch, and matches the same representative pick used by the per-card filter chips below.

## Where it shows up

License information has its own always-visible panel on the analysis page — it doesn't depend on Maven Enforcer being configured, unlike the [conflict/convergence](../recommendations/dependency-conflicts.md) panel. Each license in the breakdown is a clickable filter chip: clicking one filters the same Findings/Clean/All dependency list the other filter chips (reason, origin) already use.

## Caching

License lookups are cached like version and vulnerability data — 30 days by default, configurable from the same `/config` page. See [Cache Settings](../configuration/cache-settings.md).
