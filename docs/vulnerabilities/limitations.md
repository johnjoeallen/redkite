# Limitations

- **Maven ecosystem only.** RedKite queries OSV.dev's Maven ecosystem specifically — vulnerability data for other ecosystems (npm, PyPI, Docker base images, and so on) isn't checked, consistent with RedKite only analysing Maven projects (see [Concepts](../concepts/index.md)).
- **OSV's coverage, not RedKite's own.** RedKite doesn't run its own advisory feed or maintain its own CVE database — it's only as complete and up to date as OSV.dev itself.
- **No plugin CVE checking.** Vulnerability checking is built around dependencies. Maven plugins are inventoried (see [Plugins](../analysis/plugins.md)) but not checked against OSV.
- **Bounded candidate search.** When looking for a fix, RedKite checks a bounded number of candidate versions per component rather than every published release — see [Vulnerability Fixes](../recommendations/vulnerability-fixes.md). An extremely old dependency with very many releases between it and a fix could, in principle, exceed that bound.
- **No cross-finding ranking yet.** When fixing one CVE could affect another dependency's own findings, RedKite doesn't yet compare the net effect — see [CVE Ranking](cve-ranking.md) and [Candidate Comparison](candidate-comparison.md).
