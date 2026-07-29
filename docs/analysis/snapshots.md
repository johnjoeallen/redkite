# Snapshots

RedKite highlights `SNAPSHOT` dependencies as unverified risks. A SNAPSHOT version isn't a fixed, immutable release — its actual content can change between builds without the version number changing — so RedKite treats any component resolved at a SNAPSHOT version as needing attention regardless of whether it has a known CVE or an available update, and excludes it from the normal update-recommendation path (there's no stable "latest" to recommend for something that's still moving).

A SNAPSHOT dependency shows up under **Findings** with its own reason, separate from CVE or update-related reasons, so it doesn't get lost among (or conflated with) genuine vulnerability findings.
