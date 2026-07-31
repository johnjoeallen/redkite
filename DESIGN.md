# RedKite — Design Document

## Overview

RedKite is a self-contained Maven dependency analysis tool. It runs as a local HTTP server, analyses local Maven projects by invoking Maven subprocesses, fetches version metadata and vulnerability data from external services, and presents an interactive remediation UI. There is no framework dependency — the server uses the JDK built-in `com.sun.net.httpserver.HttpServer`, H2 for persistence, and Thymeleaf for page shell templating.

---

## Module Structure

```
red-kite/
├── red-kite-core/          Pure domain model and classification logic
├── red-kite-maven/         Maven subprocess invocation and POM manipulation
├── red-kite-metadata/      External metadata fetching (Maven Central, OSV)
└── red-kite-server/        HTTP server, scan orchestration, UI rendering, storage
```

### `red-kite-core`

Domain records and stateless classifiers. No I/O. All records implement `Serializable` for H2 persistence.

| Class | Purpose |
|---|---|
| `ScanComponent` | A single dependency node: coordinates, version, scope, directness, version source |
| `ScanInput` | Full project snapshot: all components, edges, POM contents, git metadata |
| `ScanReport` | Analysis result: components enriched with metadata, recommendations, vulnerability findings |
| `TransitiveConflictFinding` | One enforcer conflict: coordinates, resolved version, conflicting versions, raw path text |
| `VulnerabilityFinding` | One OSV advisory: ID, severity, CVEs, affected version, fixed version, introduced version (lower bound of the range containing the affected version — used to search for a downgrade fix) |
| `UpgradeRecommendation` | Upgrade target and reason for one component — reason distinguishes an upgrade fix, a downgrade fix, or a best-effort lowest-severity suggestion |
| `RemediationStatus` | Classification of what action a component needs |
| `RemediationClassifier` | Stateless classifier: produces `RemediationStatus` from component + findings |
| `AdvisoryClassifier` | Picks highest severity across a list of `VulnerabilityFinding` |

### `red-kite-maven`

All Maven subprocess invocation and POM file manipulation.

| Class | Purpose |
|---|---|
| `MavenProjectScanner` | Walks POM tree, invokes `dependency:tree`, builds `ScanInput` |
| `ConflictOutputParser` | Parses enforcer raw stdout into `List<TransitiveConflictFinding>` |
| `EnforcerRunner` | Runs `mvn enforcer:enforce` or falls back to `mvn verify -DskipTests` |
| `EnforcerDetector` | Detects whether `maven-enforcer-plugin` is configured in the project |
| `TempPomAnalyzer` | Creates stripped temp POM trees for pristine / phase-2 enforcer runs |
| `RemediationApplier` | Inserts dep-management pins and exclusions into POM XML with marker comments, via DOM parse + serialise (well-formed output, two-space indent); inserted pins use a hardcoded `<version>`, but project entries managed via `${property}` get the property value updated instead (family semantics preserved) |
| `ValidationRunner` | Runs `mvn clean install -Denforcer.skip=true` (`-DskipTests` by default, see `ValidationOptions.skipTests`; or `clean verify`/`clean test` — see `ValidationOptions.mode`; `--no-transfer-progress` unless `ValidationOptions.fullLogs`) and, in `Mode.RUN`, optionally `spring-boot:run` to validate a project build |
| `PomModel` | In-memory representation of a parsed POM |
| `MavenSettingsReader` | Reads `~/.m2/settings.xml` for repository URLs and credentials |
| `ProjectConfigFile` | Reads a project's own `.redkite/config.yml` — see Apply Changes Flow below |

### `red-kite-metadata`

External data providers with two-level caching (in-memory + H2).

| Class | Purpose |
|---|---|
| `HttpVersionMetadataProvider` | Fetches `maven-metadata.xml` from Maven Central / Artifactory |
| `HttpVulnerabilityProvider` | Queries OSV `POST /v1/query`; caches responses (TTL from `rk_config`, default 24h — see Configurable Cache TTLs) |
| `CacheTtlConfig` | Reads a cache TTL override from `rk_config` for a given key, falling back to the compiled-in default; read fresh on every call, not cached |
| `CacheAwareMetadataService` | Thin orchestrator delegating to both providers (currently unused — no call sites) |

### `red-kite-server`

Single class `RedKiteServerMain` (~5000 lines) containing:
- HTTP server setup and request routing
- Scan job orchestration (background thread pool)
- `Store` inner class: all H2 persistence
- All HTML rendering (Thymeleaf shells; card/row content built as strings)
- POM patching (`generatePomPatches`, `patchPomXml`)

---

## Scan Pipeline

### Trigger

`POST /api/scan {"path": "/abs/path"}` → enqueued as a background job, returns `{"jobId": "..."}`. Client polls `GET /api/scan-status?jobId=...` until `status == "done"`.

### Phase 0 — Project Discovery and Tree Analysis

```
MavenProjectScanner.scan(path)
  ├── git metadata (branch, HEAD commit, clean/dirty)
  ├── walk filesystem → collect all pom.xml
  ├── pre-pass: for each POM → parsePom() → PomModel
  │     (groupId, artifactId, version, properties, deps, depMgmt, plugins)
  │     builds projectModuleKeys set (groupId:artifactId for every module in
  │     the project) — used to filter internal cross-module dependencies from
  │     the scan results so they don't appear as SNAPSHOT components
  └── for each POM:
        direct dependency loop:
          skip self-references and projectModuleKeys members
          → ScanComponent (direct=true)
        plugin loop:
          → ScanComponent (scope=PLUGIN_BUILD)
        if aggregator POM (has <modules>):
          dep-management loop → ScanComponent per entry
        else:
          mvn dependency:tree -f pom.xml -DskipTests
          → parseDependencyTreeOutput()
                strip [INFO] prefix
                measure depth by leading |   / spaces
                split on : → (groupId, artifactId, packaging, version, scope)
                skip lines containing "(omitted" (Maven's conflict losers)
                skip projectModuleKeys nodes (inherit parent slot in ancestry)
          → build ScanComponent map
          → build DependencyEdge list (parent → child)
        external parent POM loop:
          parents not in projectModuleKeys → ScanComponent
        final defensive pass: remove any projectModuleKeys coordinates that
          slipped through any code path above
→ ScanInput
```

**Version source tagging:**

| `VersionSource` | Meaning |
|---|---|
| `LITERAL` | Direct `<version>` tag in the POM |
| `PROPERTY` | References `${property}` |
| `BOM_MANAGED` | No version tag; managed by a BOM in `<dependencyManagement>` |
| `UNKNOWN` | Transitive dependency (version from Maven resolution) |

### Phase 1 — Version Metadata

For each non-SNAPSHOT component, `HttpVersionMetadataProvider.latestVersion()` fetches `maven-metadata.xml`:
- **Maven Central:** `GET https://repo1.maven.org/maven2/{groupPath}/{artifactId}/maven-metadata.xml`
- **Artifactory:** `GET /api/search/versions?g=...&a=...` (JSON)

Stable version filter: must match `^\d+(\.\d+){1,3}([.\-](Final|RELEASE|GA|SP\d*|SR\d*))?$` (case-insensitive). Pre-releases, alphas, RCs, milestones, and SNAPSHOTs are excluded from recommendation targets but retained in the version dropdown.

Upgrade path: one representative per `major.minor` family (the highest patch in that family), filtered to versions strictly above the current, sorted ascending.

### Phase 2 — Vulnerability Scan

For each non-SNAPSHOT component, `HttpVulnerabilityProvider.vulnerabilities()` POSTs to OSV:
```json
{"version": "2.13.0", "package": {"name": "com.fasterxml.jackson.core:jackson-databind", "ecosystem": "Maven"}}
```
Responses cached for 24 hours in memory and H2.

### Phase 3 — Upgrade Recommendation

Components without a known CVE go through `selectUpgradeTarget()`:
1. Prefer `latestSameMajorVersion` if it differs from current
2. Otherwise walk `upgradePathVersions`, picking the closest same-major-minor candidate, else the next candidate
3. Fall back to `latestVersion` (potentially a major bump)

Reason codes: `PATCH_AVAILABLE` / `MINOR_AVAILABLE` / `MAJOR_AVAILABLE` / `SNAPSHOT_REPLACEMENT`

Components with a known CVE go through `resolveCveFix()` instead — a three-tier resolver (see "CVE Fix Resolution" below) that tries an upgrade, then a downgrade, then a bounded best-effort search, verifying each candidate is itself free of unrelated vulnerabilities before recommending it.

`ScanReport` is built and stored (base64 Java serialization in H2).

### Phase 4 — Enforcer / Conflict Detection

```
runEnforcerCheck(projectRoot, scanId)
  ├── TempPomAnalyzer.scanPomMetadata()
  │     (reads existing dep-management pins and RedKite exclusion counts from POMs)
  ├── EnforcerRunner.run()
  │     try: mvn enforcer:enforce -f root/pom.xml
  │     if "No rules configured" in output:
  │         fall back to: mvn verify -DskipTests
  │         persist enforcer_use_verify=true on project
  ├── ConflictOutputParser.parse(rawOutput)
  │     → List<TransitiveConflictFinding>
  ├── runPhase2Validation()   [auto-fix pins]
  │     → computeWinnerVersion() per finding
  │     → TempPomAnalyzer.runWithPins()  [write temp POM tree with pins]
  │     → re-run enforcer on temp tree
  │     → returns remaining (unresolvable) findings
  ├── detectStaleExclusions()
  │     exclusions whose groupId:artifactId no longer appears in any finding
  └── store.saveEnforcerResult()
```

---

## Flow Diagram

```
User (browser)
     │
     │ POST /api/scan {"path": "..."}
     ▼
RedKiteServerMain
     │
     ├──── Background thread pool ─────────────────────────────────────────┐
     │                                                                      │
     │                              Phase 0                                 │
     │                    MavenProjectScanner.scan()                        │
     │                              │                                       │
     │               ┌──────────────┴──────────────┐                       │
     │               │                              │                       │
     │       parsePom() ×N              mvn dependency:tree ×N             │
     │       (DOM parse)                (subprocess)                        │
     │               │                              │                       │
     │               └──────────────┬──────────────┘                       │
     │                              │                                       │
     │                          ScanInput                                   │
     │                              │                                       │
     │                         Phase 1 + 2                                  │
     │             ┌────────────────┴────────────────┐                     │
     │             │                                  │                     │
     │   HttpVersionMetadataProvider          HttpVulnerabilityProvider    │
     │   GET maven-metadata.xml ×N            POST /v1/query ×N           │
     │   (cached in memory + H2)              (cached in memory + H2)      │
     │             │                                  │                     │
     │             └────────────────┬────────────────┘                     │
     │                              │                                       │
     │                         Phase 3                                      │
     │                  selectUpgradeTarget() ×N                            │
     │                  → UpgradeRecommendation                             │
     │                              │                                       │
     │                          ScanReport                                  │
     │                         store.ingest()                               │
     │                              │                                       │
     │                         Phase 4                                      │
     │               EnforcerRunner.run() (subprocess)                      │
     │                              │                                       │
     │               ConflictOutputParser.parse()                           │
     │               → List<TransitiveConflictFinding>                      │
     │                              │                                       │
     │               runPhase2Validation()                                  │
     │               → TempPomAnalyzer.runWithPins()                        │
     │               → enforcer on temp tree (subprocess)                   │
     │               → remaining findings                                   │
     │                              │                                       │
     │               store.saveEnforcerResult()                             │
     │                              │                                       │
     │                        job complete                                  │
     └──────────────────────────────┴─────────────────────────────────────┘
     │
     │ GET /scans/{id}
     ▼
renderRemediationView()
     │
     ├── RemediationClassifier.classify() ×N → RemediationStatus ×N
     ├── conflictsByKey (from enforcer_results)
     ├── conflictDefaultVersion() per conflicted component
     ├── renderVersionSelect() per component (ordered version dropdown)
     └── HTML page → browser
```

---

## Dependency Analysis Rules

### Version Comparison

Versions are compared token by token after splitting on `[-.]`:
- Numeric tokens compared as `long`
- Non-numeric tokens compared lexicographically
- Numeric tokens always sort higher than non-numeric tokens at the same position (so `1.0.0` > `1.0.0-SNAPSHOT`)

### Stable Version Filter

A version is considered stable and safe to recommend if it matches:
```
^\d+(\.\d+){1,3}([.\-](Final|RELEASE|GA|SP\d*|SR\d*))?$
```
(case-insensitive). Any version containing `alpha`, `beta`, `rc`, `CR`, `M\d`, `milestone`, or `SNAPSHOT` is excluded from recommendation targets.

### Upgrade Path Construction

1. Group all available stable versions by `major.minor` family
2. Keep one representative per family (the highest patch in that family)
3. Filter to versions strictly above the current version
4. Sort ascending

This produces a stepped upgrade path (e.g. `[2.14.3, 2.15.4, 2.16.2, 2.17.3, 2.18.3]`) rather than listing every patch release.

### Upgrade Target Selection (`selectUpgradeTarget`)

Used only for components with **no known CVE**.

```
if latestSameMajorVersion > currentVersion:
    candidate = latestSameMajorVersion
else if upgradePathVersions is not empty:
    candidate = last(upgradePathVersions)  // highest in same-major path
else:
    candidate = latestVersion              // possibly a major bump

return UpgradeRecommendation(target=candidate, reason=...)
```

Reason codes in priority order: `PATCH_AVAILABLE` > `MINOR_AVAILABLE` > `MAJOR_AVAILABLE` > `SNAPSHOT_REPLACEMENT`

### CVE Fix Resolution (`resolveCveFix`)

Used for components **with** a known CVE, in place of `selectUpgradeTarget`. Three tiers, tried in order, each using data already fetched for the current version (no extra network calls except tier 3):

```
Tier 1 — Upgrade (RecommendationReason.CVE_FIX):
    requiredFix = max(fixedVersion across all findings for this component)
    if any finding has no fixedVersion (open-ended/unbounded advisory):
        tier fails entirely — an upgrade can never resolve an unbounded CVE
    else:
        candidates = available versions >= requiredFix, ascending (closest first)
        return the first candidate verified live to have ZERO vulnerability
        findings of its own (not just clear of the original CVE's range)

Tier 2 — Downgrade (RecommendationReason.CVE_FIX_DOWNGRADE):
    requiredBelow = min(introducedVersion across all findings)
    if any finding has no introducedVersion (affected since inception):
        tier fails entirely — no downgrade can escape it
    else:
        candidates = available versions < requiredBelow, descending (closest first)
        return the first candidate verified live to be fully clean

Tier 3 — Best effort (RecommendationReason.CVE_BEST_EFFORT):
    candidates = nearest ~6 versions above current + nearest 3 below + the true
                 latest release, live-queried for their own worst severity
    upgrade candidates are checked before any downgrade candidate, so a tie
    always resolves toward the upgrade
    a candidate is accepted only if its severity is no worse than current's;
    ties are broken toward whichever candidate is closest to current
    (an upgrade tying current's severity is still worth suggesting — likely
    carries other unrelated fixes; a downgrade tying current's severity is not,
    since it's pure downside with no CVE benefit — downgrade ties are rejected)
    return null if nothing at least as good as current is found (→ CVE Nofix)
```

The version dropdown's fixability status (`CVE Upgrade` / `CVE Downgrade` / `CVE Nofix` tabs) is derived directly from which tier produced the recommendation, folding `CVE_BEST_EFFORT` into Upgrade or Downgrade by whether its target is above or below the current version — `CVE Nofix` means no recommendation was found at all (tier 3 also failed).

### Remediation Classification (`RemediationClassifier`)

A component `needsRemediation()` if any of these are true:

| Flag | Condition |
|---|---|
| `isSnapshot` | Version string contains `SNAPSHOT` |
| `hasDeclaredVersionDeclaration` | Direct dep with `VersionSource.LITERAL` (version should be a property reference) |
| `hasVulnerability` | At least one `VulnerabilityFinding` |
| `hasUpgradeRecommendation` | An `UpgradeRecommendation` exists |
| `hasStaleMetadata` | Metadata cache is `STALE`, `MISSING`, `ERROR_CACHED`, or provider returned a rate-limit/error status |

**UI override (`isCardClean`):** A non-conflicted transitive dependency is force-marked `data-clean="true"` regardless of `needsRemediation()` unless it has a *fixable* CVE (a resolved `UpgradeRecommendation` from `resolveCveFix`'s upgrade or downgrade tier — a `CVE_BEST_EFFORT` suggestion does **not** count as fixable here) or is a SNAPSHOT. This is fixability-based, not severity-based — a Low-severity CVE with an available fix is surfaced; a Critical-severity CVE with no available fix is suppressed as noise. Direct dependencies are never suppressed this way.

The remediation panel's filter tabs are: `CVE Upgrade` / `CVE Downgrade` / `CVE Nofix` (mutually exclusive, derived from which `resolveCveFix` tier produced the recommendation — see "CVE Fix Resolution"), `Conflict`, `Snapshot`, `Upgradeable` (a plain, non-CVE `UpgradeRecommendation`), `Transitive`, `Clean`, `All`.

---

## Conflict Resolution Rules

### Conflict Detection

The Maven enforcer plugin (`maven-enforcer-plugin`) is run with one of two rules:
- `dependencyConvergence` — flags any dependency that appears at more than one version in the resolved tree
- `requireUpperBoundDeps` — flags transitive dependencies where a declared version is lower than what a transitive path requires

RedKite detects which is present from the enforcer output header:
- `Dependency convergence error for G:A:V` → `ruleName = "dependencyConvergence"`
- `Require upper bound dependencies error for G:A:V` → `ruleName = "requireUpperBoundDeps"`

If the project has no enforcer rules configured, RedKite falls back to `mvn verify -DskipTests` and inspects the output for enforcer-like failure messages.

### Parsing Conflict Paths

For each conflict header, `ConflictOutputParser.collectPaths()` gathers the following tree-structured lines into raw path blocks.

For `requireUpperBoundDeps`, path entries follow the format:
```
   +- com.example:parent:jar:1.0.0:compile
   |  \- com.fasterxml.jackson.core:jackson-databind:2.19.4 (managed) <-- com.fasterxml.jackson.core:jackson-databind:2.21.4
```

The `(managed)` annotation means a dep-management entry forced the version to `2.19.4`. The `<-- 2.21.4` means a transitive path actually required `2.21.4`. RedKite extracts the version after `<--` as the "conflicting" (required) version, not the managed one.

### Version Fields in `TransitiveConflictFinding`

| Field | Meaning |
|---|---|
| `resolvedVersion` | The version Maven's nearest-wins algorithm selected (what is actually on the classpath) |
| `conflictingVersions` | Versions that other paths required but did not win (extracted from path entries) |
| `managedVersion` | Not a dedicated field — appears only in raw path text as the `(managed)` annotation |

### Conflict Default Version (`conflictDefaultVersion`)

The UI pre-selects a version for each conflict card using the following algorithm:

```
1. candidate = max(resolvedVersion, conflictingVersions..., component.version())
   (by semantic version comparison)

2. For each CVE vulnerability found for this artifact:
   if affectedVersion <= candidate < fixedVersion
   and fixedVersion is same major as candidate:
       advance candidate to fixedVersion
       (or to the lowest available same-major version >= fixedVersion
        if fixedVersion itself is not in the upgrade path)

3. Repeat step 2 until no more CVE advancements or iteration limit reached

4. Return candidate (or null if blank)
```

This ensures the pre-selected version is both the highest available to resolve the conflict AND free of known CVEs.

### Phase 2 Auto-Fix (Computed Dep-Management Pins)

After the initial enforcer run, RedKite attempts to compute a set of dep-management pins that would resolve all conflicts:

```
For each TransitiveConflictFinding:
    winner = max(
        resolvedVersion,
        all conflictingVersions,
        existing dep-management pin for this artifact (if any)
    )
    pin: groupId:artifactId → winner

TempPomAnalyzer.runWithPins(pins):
    1. Strip all RedKite-managed pins and exclusions from all module POMs
       (the project's OWN dep-management entries stay — they are deliberate
        choices that must keep participating in resolution)
    2. Write pins into root POM's <dependencyManagement>
    3. Symlink non-POM project content into a temp directory tree
    4. Re-run enforcer on the temp tree
       (this verifies exactly the state Apply would produce: project as-is,
        minus previous RedKite pins, plus the newly computed ones)

If enforcer passes:
    Phase 2 result = [] (all conflicts resolved)
Else:
    Phase 2 result = remaining findings (unresolvable without exclusions)
```

**Family alignment (`FamilyVersionAligner`, in `red-kite-maven`):** `computeWinnerVersion` is strictly per-artifact — it only sees the resolved/conflicting versions observed for that one groupId:artifactId's own conflict finding. For a coordinated release train (all modules of a library published and versioned together), this can pick a version for one member that's incompatible with a sibling member found elsewhere in the tree — e.g. pinning `io.cucumber:cucumber-core` to a version lower than the `cucumber.version` the project's own `cucumber-java`/`cucumber-spring`/`cucumber-junit-platform-engine` dependencies are declared at, since `cucumber-java`'s version never appears as a candidate in `cucumber-core`'s own finding. `cucumber-junit-platform-engine` then fails to discover tests because the Cucumber JVM classpath is split across two incompatible releases.

Winner selection also respects the project's own choices: if the root POM already has a (non-RedKite) `dependencyManagement` entry for the conflicting artifact — resolved via `BomVersionResolver.resolveProjectDeclared`, which walks the root POM's parent chain and imported BOMs with `ManagedVersionResolver` rather than flatly parsing `<dependencyManagement>` — that declared version wins by default, reconciled via `reconcileWithDeclared`. The computed winner overrides it only when it is a raise WITHIN the declared release line (same major.minor — logback declared `1.5.25`, findings require `1.5.38` → `1.5.38`); a computed winner on a different line must not displace the declared version (a project pinning Netty `4.1.135.Final` must not get its Netty modules force-pinned to a `4.2.x` observed on some unrelated transitive path).

After all per-finding winners are computed, `FamilyVersionAligner.align` aligns every pin belonging to a known `FamilyGroup` (`COORDINATED_FAMILIES`: Cucumber's core module set, `io.netty`, `software.amazon.awssdk`, `io.zipkin.brave`, `org.eclipse.jetty*`, `net.bytebuddy`, `io.opentelemetry`, `ch.qos.logback`, `org.junit.jupiter` and `org.junit.platform` — released together but on different version schemes, aligned within themselves, never with each other — Micrometer core and Micrometer tracing, and `com.fasterxml.jackson`). The family's target release is chosen the same way as before (the project's own declared ceiling, raised only within its release line by observed conflicts, or the highest version observed anywhere for the family), but that target is **no longer copied onto every member as a literal** — real BOMs frequently manage different members at different versions (the Jackson 2.22.1 BOM manages `jackson-core`/`jackson-databind` at `2.22.1` but `jackson-annotations` at `2.22`; pinning the latter to `2.22.1` produces a nonexistent artifact and a confusing repository-transport error). Instead:

- A member the project explicitly overrides itself (a direct dependencyManagement entry, not something a BOM/parent contributes) keeps that override, reconciled independently — never touched by the family-wide target.
- Otherwise, when the family's controlling BOM coordinate is knowable — because the project already imports it, or because it's Jackson (currently the only family with a curated `bomGroupId`/`bomArtifactId`, added as configuration data alongside `COORDINATED_FAMILIES`, not a special implementation path) — that BOM is probed at the target version (`BomVersionResolver.resolveBomMembers`, which feeds `ManagedVersionResolver` a synthetic single-entry `PomModel` representing the import and reuses its existing recursive BOM/property resolution), and each member gets its own version from that probe.
- A member the probe has no data for, or when no BOM is knowable at all, falls back to the plain broadcast target — the original, correct behavior for genuine release trains (Netty, Cucumber, JUnit, etc.) that really do share one literal version and have no BOM to consult.
- When two or more members land on the target version through a BOM they're already imported via, their pins collapse into one pin keyed at the BOM's own coordinate, letting `RemediationApplier`'s existing property-bump logic apply it as a single `<jackson.version>` update instead of N literal pins — only once every affected member is verified against the probe.

Allowlists on `FamilyGroup` exist because some groupIds also publish independently-versioned siblings (Cucumber's formatter/reporting plugins and standalone `gherkin` parser; Micrometer's `context-propagation`) that must NOT be forced to the family version. The same declared-version override and realignment are applied to stored pins at display/Apply time (`realignStoredPins`), so pin lists persisted by older scans converge to the same result as a fresh computation. Before recommending or applying any computed pin, `runPhase2Validation` also checks it through `PomAvailabilityChecker` (backed by `PomFetcher`, which distinguishes a confirmed-absent coordinate from a repository transport error via `PomFetchResult`) and drops anything that doesn't actually resolve, logging the exact coordinate and repository detail.

This does not reduce the number of pins generated for genuinely independent members — Phase 2 still pins one entry per conflicting artifact whose version can't be expressed through a shared property; it only ensures each pin is a version that actually exists. A project with a very large, sprawling dependency graph can still legitimately produce a long pin list; that reflects the number of real convergence violations Maven found, not an inefficiency in the pin format itself.

The pins are displayed in the UI under "Auto-fix — computed dep-management pins" with an Apply button. Clicking Apply submits all pins as one `remediationActions` batch to `POST /api/scans/remediation/apply-batch` (same validate→apply→validate→revert-on-failure job as "Apply selected", see below) and triggers a re-scan once it succeeds. This batch is what actually rolls a multi-module project's POMs back on a broken result — the older single `POST /api/scans/remediation/apply` endpoint below writes straight to disk with no validation and must not be used for anything that needs a rollback guarantee.

### Stale Exclusion Detection

After the enforcer run, RedKite identifies any previously applied RedKite-managed exclusions (identified by `<!-- redkite:exclusion ... -->` marker comments in POM files) whose `groupId:artifactId` no longer appears in any current `TransitiveConflictFinding`. These are reported in the UI as "stale exclusions" that can be removed.

### Applying Remediations

**Dep-management pin** (`RemediationApplier.applyDependencyManagementPin()`):
- Marker format: `<!-- redkite:dependency-management pin groupId="..." artifactId="..." version="..." reason="..." — remove this comment to prevent RedKite managing this dependency -->`. Detection (finding an existing pin to update) matches on the `redkite:dependency-management` prefix without requiring the `pin` suffix, so pins written before that rename are still recognized and updated in place rather than duplicated.
- If a marker already exists for this artifact, the version in the following `<version>` tag is updated in place
- If the project has its OWN (non-RedKite) `dependencyManagement` entry for the artifact:
  - entry versioned via `${property}` → the property's VALUE is updated (in the root `<properties>`), the entry itself is untouched and gets no marker — the property typically drives a whole family (e.g. `${logback.version}` for both `logback-core` and `logback-classic`), and hardcoding one entry would silently detach it from that family. If the property isn't defined in this POM (e.g. inherited from an external parent), the POM is left unmodified rather than converting the entry into a standalone pin
  - entry with a literal version → taken over in place (marker added, version updated) rather than duplicated, which Maven rejects with "must be unique"
- Otherwise a new `<dependency>` block is inserted before `</dependencies>` in the existing `<dependencyManagement>`, or a full `<dependencyManagement>` block is inserted before `</project>` if none exists
- `<version>` tags RedKite inserts itself are always hardcoded literals, never `${...}` properties — `patchPomXml()`'s literal-to-property normalisation pass explicitly skips any `<dependency>` element immediately preceded by this marker comment (`isRedkiteDepMgmtPin`), so applying an unrelated upgrade elsewhere in the POM can't silently convert a pin into a property reference

**Exclusion** (`RemediationApplier.applyExclusion()`):
- Inserts the exclusion into the matching `<dependency>` entry's `<exclusions>` block (reusing an existing block — Maven allows at most one per dependency — or creating one), tagged with `<!-- redkite:exclusion ... -->` for future stale detection

**POM upgrade** (`patchPomXml()`):
- For `VersionSource.LITERAL` (excluding RedKite dependency-management pins, see above): normalises the literal `<version>` to a `${artifactId.version}` property reference, then sets the property value
- For `VersionSource.PROPERTY`: updates the referenced property value directly
- Uses Java DOM parse + serialise; does not modify unrelated POM structure

---

## Severity Mapping (OSV)

Severity is determined from the OSV response in priority order:

1. `database_specific.severity` string (provided by GHSA advisories as a label, e.g. `"HIGH"`)
2. CVSS vector from `severity[].score` where `type` starts with `CVSS_V`:

| CVSS condition | Mapped severity |
|---|---|
| C:H **and** I:H **and** A:H | `CRITICAL` |
| Any one of C:H, I:H, A:H | `HIGH` |
| Any one of C:M, I:M, A:M | `MEDIUM` |
| Otherwise | `LOW` |
| No severity information | `UNKNOWN` |

Severity ordinal for comparison: `NONE < UNKNOWN < LOW < MEDIUM < HIGH < CRITICAL`

---

## Storage Schema

H2 database at `~/.redkite/redkite.mv.db`.

```
projects
  id uuid PK
  name varchar
  root_path varchar UNIQUE
  enforcer_use_verify boolean      ← true = skip enforcer, use mvn verify
  validation_maven_args varchar    ← unused since config.yml replaced it; column kept, never read/written
  validation_env varchar           ← unused since config.yml replaced it; column kept, never read/written

scans
  id uuid PK
  project_id uuid FK → projects
  project_name, repo_path, branch_name, head_commit
  working_tree_clean boolean
  raw_input_json text              ← base64 Java-serialized ScanInput
  report_json text                 ← base64 Java-serialized ScanReport
  complete boolean
  completeness_message text
  created_at timestamp
                                   [pruned to 7 entries per project]

enforcer_results
  scan_id uuid PK FK → scans
  status varchar                   ← ENFORCER_RUN_PASSED | ENFORCER_RUN_FAILED |
                                      ENFORCER_NOT_CONFIGURED | ENFORCER_FAILED_TO_RUN | ...
  raw_output text
  findings_blob text               ← base64 List<TransitiveConflictFinding>
  stale_exclusions_json text
  phase2_findings_blob text        ← base64 remaining findings after auto-fix
  phase2_pins_json text            ← JSON list of computed pins
  exclusions_stripped int
  dep_mgmt_removed_json text

source_poms
  scan_id, file_path, pom_xml text
  UNIQUE(scan_id, file_path)

generated_poms
  scan_id, file_path, pom_xml text
  UNIQUE(scan_id, file_path)

rk_version_cache
  cache_key varchar PK             ← "groupId:artifactId"
  all_versions text                ← comma-separated version list
  latest_version varchar
  expires_at_epoch_ms bigint

rk_vuln_cache
  cache_key varchar PK             ← "groupId:artifactId@version"
  response_json text               ← raw OSV response body
  expires_at_epoch_ms bigint       ← TTL from rk_config, default 24h

rk_config
  config_key varchar PK            ← e.g. "cache.ttl.vulnerability.fresh"
  config_value varchar             ← minutes, as a string
  updated_at timestamp
                                   [seeded with each key's compiled-in default
                                    on startup, only if the row is missing —
                                    never overwrites a value set from /config]

metadata_cache_entries             ← per-component metadata log per scan
provider_rate_limit_state          ← rate-limit tracking (not actively enforced)
rk_schema_version                  ← migration gate (current: v2)
```

`ScanInput` and `ScanReport` are stored as base64-encoded Java object serialization (`SerializationSupport.toBase64()`). All domain records implement `java.io.Serializable`.

---

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Home page: project list + scan form |
| `GET` | `/logo.svg` | SVG logo |
| `GET` | `/projects/{id}` | Project detail: metadata, scan history |
| `GET` | `/scans/{id}` | Scan analysis: remediation, inventory, enforcer |
| `GET` | `/health` | Liveness check → `"ok"` |
| `POST` | `/api/scan` | Start scan job → `{"jobId":"..."}` |
| `GET` | `/api/scan-status?jobId=` | Poll scan progress → `{status, phases[]}` or `{status:"done", scanId}` |
| `POST` | `/api/scans/pom?scanId=` | Generate POM patch → `{filePath: patchedXml}` (called internally by **Apply selected** to compute patches before submitting the apply-batch job; the result is not shown to the user) |
| `GET` | `/api/scans/pom?scanId=` | Download patched POM(s) — handler still present but no longer linked from the UI (see note below) |
| `POST` | `/api/scans/pom/write?scanId=` | Write patched POMs to disk — handler still present but no longer linked from the UI (see note below) |
| `POST` | `/api/scans/remediation/apply` | Apply one dep-management pin or exclusion to disk (no validation, no rollback) — handler still present but no longer linked from the UI; use apply-batch for anything that needs a rollback guarantee, especially multi-module projects |
| `POST` | `/api/scans/remediation/apply-batch` | Start bracketed validate→apply→validate job → `{"jobId":"..."}` |
| `GET` | `/api/scans/remediation/apply-status?jobId=` | Poll apply job → `{status, phase}` or `{status:"done"}` or `{status:"failed",...}` |
| `GET` | `/api/scans/enforcer?scanId=` | Get enforcer findings as JSON |
| `POST` | `/api/metadata/clear` | Clear version and vulnerability caches |
| `DELETE` | `/api/projects/{id}` | Delete project and all its scans |
| `POST` | `/api/prefs` | Save UI preferences (theme) |
| `GET` | `/config` | Config page: edit cache TTLs (`rk_config`) |
| `POST` | `/api/config` | Save cache TTL values, redirects back to `/config` |

All endpoints are unauthenticated. The server is intended for local use only.

---

## Caching Strategy

| Data | In-memory cache | H2 cache | TTL |
|---|---|---|---|
| Version metadata (Maven Central) | `LinkedHashMap` (unbounded) | `rk_version_cache` | configurable via `/config`, default 24h |
| Version metadata (internal/local repos) | `LinkedHashMap` (unbounded) | `rk_version_cache` | configurable, default 1h — shorter since these can change more frequently |
| Version metadata (artifact not found) | `LinkedHashMap` (unbounded) | `rk_version_cache` | configurable, default 6h |
| Version metadata (provider error) | `LinkedHashMap` (unbounded) | `rk_version_cache` | configurable, default 15m |
| Vulnerability data | `HashMap` (unbounded) | `rk_vuln_cache` | configurable via `/config`, default 24h |
| Scan results | — | `scans` table | 7 per project |
| Enforcer results | — | `enforcer_results` | Per scan |

`POST /api/metadata/clear` force-clears both caches immediately regardless of TTL. The in-memory cache is checked first on every request. The H2 cache is checked on cache miss. External network calls are made only on H2 miss or TTL expiry. TTL values are read fresh from `rk_config` on every lookup via `CacheTtlConfig` (see `red-kite-metadata`), so a change made on `/config` takes effect on the very next lookup — no restart, no in-memory caching of the TTL setting itself.

---

## Apply Changes Flow

When the user clicks **Apply selected**, the browser first calls `POST /api/scans/pom` to compute the patched POM XML, then immediately submits it to `POST /api/scans/remediation/apply-batch`, which enqueues a background job and returns `{"jobId":"..."}`. The browser polls `GET /api/scans/remediation/apply-status?jobId=...` every 500 ms and updates the overlay text to reflect the current phase.

There is no longer a preview step between computing the patch and applying it — the patched POM XML is not shown to the user before the apply job runs. The client-side preview modal (`showPomModal`/`writePomFiles`/`copyPomContent` in `scripts.js`, the `#pom-modal` markup in `RedKiteServerMain`) and the `GET /api/scans/pom` / `POST /api/scans/pom/write` handlers it used are still present in the code but are dead — nothing in the current UI opens the modal or links to them.

### Job phases

```text
PRE_VALIDATE
  ValidationRunner.validateWithStartup(projectRoot, rootPom, 90s)
    → mvn clean install -DskipTests -Denforcer.skip=true
    → if spring-boot-maven-plugin present in root POM:
        mvn spring-boot:run --server.port=<random verified-free port>
        (so the check never collides with a developer-run or orphaned instance;
         killed — including all descendant processes, since destroying only the
         mvn wrapper leaves the forked JVM holding its port — after the startup
         signal or 90 s timeout)
  Records baselinePassed=true/false.
  Non-blocking: a failing baseline means the project was already broken.
  Apply continues regardless.

APPLYING
  Save original content of every POM that will be modified.
  Apply each remediationAction via RemediationApplier.
  Write each pomPatch to disk.

POST_VALIDATE
  ValidationRunner.validateWithStartup(projectRoot, rootPom, 90s)
  If failed:
    Restore all saved POM originals.
    Run ValidationRunner.attributeFailure(rawOutput) → groupId:artifactId or null.
    If baselinePassed was true: attribute failure to our changes.
    If baselinePassed was false: note project was already failing before changes.
    job.status = FAILED, populate failureMessage, attribution, failureSignature.
  If passed:
    job.status = DONE, baselinePassed recorded in response.
```

### Validation command

```
mvn clean install -DskipTests -Denforcer.skip=true -f <rootPom>
```

Enforcer is skipped because enforcer violations are what RedKite is fixing — running it during validation would create an unresolvable catch-22 on broken projects. Tests are skipped by default for speed, but this is configurable per-project (`skipTests`, below) — the shown command is `Mode.RUN`'s default.

Both the build and the `spring-boot:run` startup check accept extra configuration, read from the project's own `.redkite/config.yml` (`ProjectConfigFile`, red-kite-maven) — real YAML, parsed with SnakeYAML (`org.yaml:snakeyaml`) into its natural `Map<String, Object>` tree rather than a hand-rolled parser, then read field-by-field with each accessor tolerating a missing section or unexpected shape. Everything lives under `redkite.maven` — nested under a `redkite:` root rather than `maven:` directly, leaving room for future non-Maven config sections alongside it: `args` (a real YAML list, or a whitespace-separated scalar string for convenience), `profile`, `mode`, `skipTests`, `fullLogs`, an `env` map, and a nested `spring.profiles`. `ProjectConfig.toBuildArgs()` folds `args`/`profile` into one argument list (`-P<profile>`) that applies to *every* validation call; `springBootArgs()` returns `-Dspring-boot.run.profiles=<value>` separately, appended only to the `spring-boot:run` invocation, never the plain build — segregated because it's meaningless outside a Spring Boot startup. `mode` (`ValidationRunner.Mode`: `RUN`/`VERIFY`/`TEST`) picks the build command — `RUN` (default) is `mvn clean install` (plus `-DskipTests` unless `skipTests: false`), `VERIFY` is `mvn clean verify` (tests included), `TEST` is `mvn clean test` — and whether a startup check is ever attempted at all: only `RUN` ever does, and only when `spring-boot-maven-plugin` is present; `VERIFY`/`TEST` always stop at the build/test phase, for a project where starting the app for real isn't practical but its own test suite is still a meaningful gate. `skipTests` (default `true`, `ProjectConfig.skipTests()` → `ValidationOptions.skipTests()`) only has any effect in `Mode.RUN` — `VERIFY`/`TEST` always run tests regardless, since that's the entire reason to pick one of those modes. `fullLogs` (default `false`) applies to every `mvn` invocation regardless of mode — `ValidationRunner.buildCommand` normally adds `--no-transfer-progress`; `fullLogs: true` omits it, so dependency download/upload activity shows up in the raw output.

These are bundled into `ValidationRunner.ValidationOptions(mavenArgs, env, mode, springBootArgs, skipTests, fullLogs)`, loaded fresh from `projectRoot` at the start of each apply job and passed into `ValidationRunner.validateWithStartup(..., options)` for both PRE_VALIDATE and POST_VALIDATE. This exists because projects that require an active Spring profile or environment-specific config to build/start would otherwise always fail startup validation, and different projects need different values. The project page shows a read-only panel with whatever the file currently resolves to — there's no UI form or API endpoint to edit it; the old `projects.validation_maven_args`/`validation_env` columns and their `/api/projects/{id}/validation` endpoint are gone from the code (columns remain in the schema, unused, per the project's no-destructive-migration convention). If a project has no `.redkite/config.yml` at all, `ProjectConfigFile.ensureDefaultExists` creates a fully commented-out template the first time RedKite scans it (called from `handleApiScan` right after `store.reconfigureForProject`) — idempotent and best-effort, so it never overwrites an existing file (even an empty one) and never blocks a scan on a write failure.

### Status responses

```json
{"status":"running","phase":"pre-validate"}
{"status":"running","phase":"applying"}
{"status":"running","phase":"post-validate"}
{"status":"done","baselinePassed":true}
{"status":"failed","message":"...","attribution":"groupId:artifactId",
 "revertedVersion":"1.2.3","failedVersion":"1.4.0","failureSignature":"[ERROR] ..."}
{"status":"error","message":"..."}
```

On `{"status":"done",...}` the browser calls `triggerScan()` for the same project path, kicking off a fresh analysis so the user can see whether further remediation is needed on top of what was just applied.

The job is removed from the in-memory map after DONE/FAILED/ERROR is delivered.

---

