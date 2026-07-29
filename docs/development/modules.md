# Modules

```
red-kite/
├── red-kite-core/          Pure domain model and classification logic
├── red-kite-maven/         Maven subprocess invocation and POM manipulation
├── red-kite-metadata/      External metadata fetching (Maven Central, OSV.dev)
└── red-kite-server/        HTTP server, scan orchestration, UI rendering, storage
```

Dependencies flow one direction only: `red-kite-server` depends on the other three; `red-kite-maven` and `red-kite-metadata` depend on `red-kite-core`; `red-kite-core` depends on nothing else in the project. This is why general-purpose logic (like version comparison) belongs in `red-kite-core` — it's the only module every other module can see.

## `red-kite-core`

Domain records and stateless classifiers, no I/O.

| Class | Purpose |
|---|---|
| `ScanComponent` | A single dependency node: coordinates, version, scope, directness, version source |
| `ScanInput` | Full project snapshot: all components, edges, POM contents, git metadata |
| `ScanReport` | Analysis result: components enriched with metadata, recommendations, vulnerability findings |
| `TransitiveConflictFinding` | One enforcer conflict: coordinates, resolved version, conflicting versions, raw path text |
| `VulnerabilityFinding` | One OSV advisory: ID, severity, CVEs, affected/fixed/introduced versions |
| `UpgradeRecommendation` | Upgrade target and reason for one component |
| `RemediationStatus` / `RemediationClassifier` | Classification of what action a component needs |
| `AdvisoryClassifier` | Picks the highest severity across a list of findings |
| `SemanticVersionComparator` | Version comparison and "same release line" logic — see [Version Management](../concepts/version-management.md) |

## `red-kite-maven`

All Maven subprocess invocation and POM file manipulation.

| Class | Purpose |
|---|---|
| `MavenProjectScanner` | Walks the POM tree, invokes `dependency:tree`, builds a `ScanInput` |
| `ConflictOutputParser` | Parses enforcer raw stdout into conflict findings |
| `EnforcerRunner` | Runs `mvn enforcer:enforce` (or `mvn verify -DskipTests` as a fallback) |
| `EnforcerDetector` | Detects whether `maven-enforcer-plugin` is configured in a project |
| `TempPomAnalyzer` | Builds stripped temp POM trees for pristine/phase-2 enforcer runs |
| `RemediationApplier` | Inserts dependency-management pins and exclusions into POM XML |
| `ValidationRunner` | Runs the build (and, where applicable, startup) validation described in [Validation Model](../concepts/validation-model.md) |
| `PomModel` | In-memory representation of a parsed POM |
| `MavenSettingsReader` | Reads `settings.xml` for repository URLs and credentials |
| `ManagedVersionResolver` / `BomVersionResolver` / `FamilyVersionAligner` | Parent/BOM-aware managed-version resolution — see [Parent, BOM, and Ancestor](../concepts/parent-bom-and-ancestor.md) and [Dependency Conflicts](../recommendations/dependency-conflicts.md) |
| `PomFetcher` / `PomAvailabilityChecker` | Fetches and caches external POMs, distinguishing a confirmed-absent artifact from a transport error |

## `red-kite-metadata`

External data providers, each with in-memory and database-backed caching.

| Class | Purpose |
|---|---|
| `HttpVersionMetadataProvider` | Fetches version metadata from Maven Central (and other configured repositories) |
| `HttpVulnerabilityProvider` | Queries OSV.dev and caches responses |
| `CacheTtlConfig` | Reads a cache TTL override from `rk_config`, falling back to the compiled-in default |

## `red-kite-server`

A single main class, `RedKiteServerMain`, containing HTTP routing, scan job orchestration, all H2 persistence (a `Store` inner class), and all HTML rendering. It's intentionally not split further — see [Architecture](architecture.md) for why the project avoids a web framework in the first place.
