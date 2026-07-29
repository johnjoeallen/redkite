# Dependency Inventory

The analysis view lists every dependency RedKite found, grouped by module (for multi-module projects), with:

- coordinates (`groupId:artifactId`) and resolved version
- scope (`compile`, `runtime`, `provided`, `test`, etc.)
- version source — whether the version came from a literal `<version>` tag, a property reference, dependency management, or Maven's own mediation of a transitive dependency
- a severity badge summarising known CVEs on that dependency itself
- a secondary "In dependencies" indicator when something it pulls in transitively has a known CVE, even if the dependency itself is clean
- its declared license(s), if any were found

**Findings** / **Clean** / **All** tabs filter the list to what needs attention versus everything; filter chips narrow further by CVE status, conflict status, and origin (direct vs. transitive). A module selector (for multi-module projects) scopes the whole view to one module at a time.

See [Recommendations](../recommendations/index.md) for exactly what makes a dependency count as a "finding" rather than "clean".
