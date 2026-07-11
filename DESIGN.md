# RedKite — Design Document

## Overview

RedKite is a self-contained Maven dependency analysis tool. It runs as a local HTTP server, analyses checked-out Maven projects by invoking Maven subprocesses, fetches version metadata and vulnerability data from external services, and presents an interactive remediation UI. There is no framework dependency — the server uses the JDK built-in `com.sun.net.httpserver.HttpServer`, H2 for persistence, and Thymeleaf for page shell templating.

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
| `VulnerabilityFinding` | One OSV advisory: ID, severity, CVEs, affected version, fixed version |
| `UpgradeRecommendation` | Upgrade target and reason for one component |
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
| `RemediationApplier` | Inserts dep-management pins and exclusions into POM XML with marker comments |
| `ValidationRunner` | Runs `mvn clean install -DskipTests -Denforcer.skip=true` (and optionally `spring-boot:run`) to validate a project build |
| `PomModel` | In-memory representation of a parsed POM |
| `MavenSettingsReader` | Reads `~/.m2/settings.xml` for repository URLs and credentials |

### `red-kite-metadata`

External data providers with two-level caching (in-memory + H2).

| Class | Purpose |
|---|---|
| `HttpVersionMetadataProvider` | Fetches `maven-metadata.xml` from Maven Central / Artifactory |
| `HttpVulnerabilityProvider` | Queries OSV `POST /v1/query`; caches responses for 24 hours |
| `CacheAwareMetadataService` | Thin orchestrator delegating to both providers |

### `red-kite-server`

Single class `RedKiteServerMain` (~4200 lines) containing:
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

`selectUpgradeTarget()` for each component with upgrade potential:
1. Prefer `latestSameMajorVersion` if it differs from current
2. Otherwise walk `upgradePathVersions` stopping at a CVE-clean version
3. Fall back to `latestVersion` (potentially a major bump)

Reason codes: `CVE_FIX` → `PATCH_AVAILABLE` → `MINOR_AVAILABLE` → `MAJOR_AVAILABLE` → `SNAPSHOT_REPLACEMENT`

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

```
if latestSameMajorVersion > currentVersion:
    candidate = latestSameMajorVersion
else if upgradePathVersions is not empty:
    candidate = last(upgradePathVersions)  // highest in same-major path
else:
    candidate = latestVersion              // possibly a major bump

if candidate has CVE vulnerabilities:
    walk upgradePathVersions looking for a CVE-clean version >= candidate
    prefer lowest clean version that is still same-major

return UpgradeRecommendation(target=candidate, reason=...)
```

Reason codes in priority order: `CVE_FIX` > `PATCH_AVAILABLE` > `MINOR_AVAILABLE` > `MAJOR_AVAILABLE` > `SNAPSHOT_REPLACEMENT`

### Remediation Classification (`RemediationClassifier`)

A component `needsRemediation()` if any of these are true:

| Flag | Condition |
|---|---|
| `isSnapshot` | Version string contains `SNAPSHOT` |
| `hasDeclaredVersionDeclaration` | Direct dep with `VersionSource.LITERAL` (version should be a property reference) |
| `hasVulnerability` | At least one `VulnerabilityFinding` |
| `hasUpgradeRecommendation` | An `UpgradeRecommendation` exists |
| `hasStaleMetadata` | Metadata cache is `STALE`, `MISSING`, `ERROR_CACHED`, or provider returned a rate-limit/error status |

**UI override:** Transitive dependencies without HIGH/CRITICAL CVE are force-marked `data-clean="true"` in the UI regardless of `needsRemediation()`, suppressing them from the upgrade tab. Only transitives with HIGH/CRITICAL CVE or an active conflict are surfaced.

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
    1. Strip all existing dep-management from all module POMs
    2. Strip all RedKite-managed exclusions from all module POMs
    3. Write pins into root POM's <dependencyManagement>
    4. Symlink non-POM project content into a temp directory tree
    5. Re-run enforcer on the temp tree

If enforcer passes:
    Phase 2 result = [] (all conflicts resolved)
Else:
    Phase 2 result = remaining findings (unresolvable without exclusions)
```

The pins are displayed in the UI under "Auto-fix — computed dep-management pins" with an Apply button. Clicking Apply writes all pins via `POST /api/scans/remediation/apply` and triggers a re-scan.

### Stale Exclusion Detection

After the enforcer run, RedKite identifies any previously applied RedKite-managed exclusions (identified by `<!-- redkite:exclusion ... -->` marker comments in POM files) whose `groupId:artifactId` no longer appears in any current `TransitiveConflictFinding`. These are reported in the UI as "stale exclusions" that can be removed.

### Applying Remediations

**Dep-management pin** (`RemediationApplier.applyDependencyManagementPin()`):
- If a `<!-- redkite:dependency-management groupId="..." artifactId="..." ... -->` marker already exists for this artifact, the version in the following `<version>` tag is updated in place
- Otherwise a new `<dependency>` block is inserted before `</dependencies>` in the existing `<dependencyManagement>`, or a full `<dependencyManagement>` block is inserted before `</project>` if none exists

**Exclusion** (`RemediationApplier.applyExclusion()`):
- Inserts an `<exclusions>` block inside the matching `<dependency>` entry in `<dependencies>`, tagged with `<!-- redkite:exclusion ... -->` for future stale detection

**POM upgrade** (`patchPomXml()`):
- For `VersionSource.LITERAL`: normalises the literal `<version>` to a `${artifactId.version}` property reference, then sets the property value
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
  expires_at_epoch_ms bigint       ← 24-hour TTL

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
| `GET` | `/api/scans/pom?scanId=` | Download patched POM(s) |
| `POST` | `/api/scans/pom?scanId=` | Generate POM patch → `{filePath: patchedXml}` |
| `POST` | `/api/scans/pom/write?scanId=` | Write patched POMs to disk |
| `POST` | `/api/scans/remediation/apply` | Apply one dep-management pin or exclusion to disk (no validation) |
| `POST` | `/api/scans/remediation/apply-batch` | Start bracketed validate→apply→validate job → `{"jobId":"..."}` |
| `GET` | `/api/scans/remediation/apply-status?jobId=` | Poll apply job → `{status, phase}` or `{status:"done"}` or `{status:"failed",...}` |
| `GET` | `/api/scans/enforcer?scanId=` | Get enforcer findings as JSON |
| `POST` | `/api/metadata/clear` | Clear version and vulnerability caches |
| `DELETE` | `/api/projects/{id}` | Delete project and all its scans |
| `POST` | `/api/prefs` | Save UI preferences (theme) |

All endpoints are unauthenticated. The server is intended for local use only.

---

## Caching Strategy

| Data | In-memory cache | H2 cache | TTL |
|---|---|---|---|
| Version metadata | `LinkedHashMap` (unbounded) | `rk_version_cache` | Until `POST /api/metadata/clear` |
| Vulnerability data | `HashMap` (unbounded) | `rk_vuln_cache` | 24 hours |
| Scan results | — | `scans` table | 7 per project |
| Enforcer results | — | `enforcer_results` | Per scan |

The in-memory cache is checked first on every request. The H2 cache is checked on cache miss. External network calls are made only on H2 miss or TTL expiry.

---

## Apply Changes Flow

When the user clicks **Apply selected**, `POST /api/scans/remediation/apply-batch` enqueues a background job and returns `{"jobId":"..."}`. The browser polls `GET /api/scans/remediation/apply-status?jobId=...` every 500 ms and updates the overlay text to reflect the current phase.

### Job phases

```text
PRE_VALIDATE
  ValidationRunner.validateWithStartup(projectRoot, rootPom, 90s)
    → mvn clean install -DskipTests -Denforcer.skip=true
    → if spring-boot-maven-plugin present in root POM:
        mvn spring-boot:run (kill after startup signal or 90 s timeout)
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

Enforcer is skipped because enforcer violations are what RedKite is fixing — running it during validation would create an unresolvable catch-22 on broken projects. Tests are skipped for speed.

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

The job is removed from the in-memory map after DONE/FAILED/ERROR is delivered.

---

