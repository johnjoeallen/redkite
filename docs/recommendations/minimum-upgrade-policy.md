# Minimum Upgrade Policy

!!! warning "Status: Planned"
    This page describes a capability that does not exist yet. Today, RedKite always recommends its single best candidate version for a given finding — see [Version Updates](version-updates.md) and [Vulnerability Fixes](vulnerability-fixes.md) for how that candidate is actually chosen right now. There is no configurable policy controlling how far a recommendation is allowed to move.

## The idea

Different projects want different tolerances for how far an automatic recommendation should reach. A team that only wants the smallest possible change needed to clear a finding has different needs from a team that's happy to take the latest release within the current major line whenever one's available. A configurable minimum-upgrade policy would let a project choose, for example:

- **Smallest fix only** — the minimum version bump that resolves the finding, nothing more
- **Latest within the current line** — today's default behavior, described in [Version Updates](version-updates.md)
- **Latest including major bumps** — opt in to crossing a major version boundary automatically, which RedKite does not currently do under any configuration

## Related

- [Version Updates](version-updates.md)
- [Vulnerability Fixes](vulnerability-fixes.md)
- [Planned Features](../roadmap/planned-features.md)
