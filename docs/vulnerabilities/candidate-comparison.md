# Candidate Comparison

!!! warning "Status: Planned"
    This page describes a capability that does not exist yet. Today, RedKite picks a fix candidate using the three-tier order described in [Vulnerability Fixes](../recommendations/vulnerability-fixes.md) — the first tier that produces a verified candidate wins, without weighing that candidate against other properties a version might have.

## The idea

Not every version that clears a CVE is an equally good choice. A future candidate-comparison step would let RedKite weigh multiple qualifying candidates against each other on more than "does it fix the finding," for example:

- how far the candidate is from the current version (smaller changes carry less risk)
- whether the candidate is itself affected by other, unrelated advisories (see [CVE Ranking](cve-ranking.md))
- how the candidate interacts with the [minimum upgrade policy](../recommendations/minimum-upgrade-policy.md), once that exists

## Related

- [Vulnerability Fixes](../recommendations/vulnerability-fixes.md)
- [CVE Ranking](cve-ranking.md)
- [Planned Features](../roadmap/planned-features.md)
