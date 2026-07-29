# Evolution

How RedKite got here, traced through its own git log.

---

This traces RedKite's history through its git log, from the first commit (`493ca92`,
2026-06-18) to the present (164 commits, ~5 weeks). It's the story of how "tell me if a
newer version exists and whether it has a CVE" grew into a model that treats an upgrade as
one kind of *update* among many, tracks *why* a dependency's version is what it is, and lets
a user compare alternative fixes instead of accepting the first one offered.

Two design documents worth knowing about up front, both still in the repo: **`future.md`**
(2026-07-01) and **`hybrid.md`** (2026-07-02). They describe a considerably more ambitious
system than what's built — four-model comparison (pristine/clean/in-place/candidate),
Minimal/Manual/Maximal remediation strategies, bounded auto-retry loops with rollback. Most
of that was never implemented as literally specified, but its *influence* runs through
everything that came after: the three-tier CVE resolution, the pin lifecycle, the "compare
alternative strategies" idea this session finally built a working version of.

---

## 1. Genesis: scan, recommend, flag CVEs (06-18 → 06-19)

The initial commit already had the shape RedKite would keep for months: scan a Maven
project, check Maven Central for newer versions, recommend upgrades, and — added within a
day (`4d06a39`) — check OSV.dev for known vulnerabilities. `2761e8c` ("Stages 1 & 2:
remediation model and advisory severity") and `effc49b` ("Stage 6 & 8: Remediation-first UI
with severity badges") laid down `RemediationStatus`/`RemediationClassifier` and the
severity-badge UI that (heavily evolved) is still the analysis page today.

The rest of this era is fast, small fixes typical of a tool finding its feet: matching CVE
findings by coordinate *and* version rather than coordinate alone (`67f5363`, after a "CVE
bleed-over" bug let one version's vulnerability leak onto another), excluding pre-releases
from recommendations (`0931553`), skipping `dependency:tree` for aggregator POMs to stop
version contamination (`155f60c`).

## 2. Hardening against real repositories (06-19 → 06-22)

Real Maven projects don't all point at Maven Central. This stretch is almost entirely about
making version lookups work everywhere: Artifactory GAVC search (`a3e3072`), settings.xml
credential discovery with project-local-first resolution (`a5f1b58`, `8c774cd`),
`mirrorOf=*` handling (`b6809ed`), `${env.*}` credential expansion with anonymous-then-401-retry
(`6529cb1`) — the exact retry pattern `PomFetcher` reuses today for fetching parent/BOM POMs.
A persistent DB-backed version-metadata cache landed here too (`0de5794`), with TTLs tuned
differently for Maven Central versus internal repos (`87f2bed`).

The UI churned in parallel: direct/transitive/snapshot tabs, hiding transitive-only upgrades
by default, a `CVE / Upgrades / All` exclusive-tab bar (`ef652f3`) — the direct ancestor of
the tab set Stage 5 of this session's redesign eventually replaced.

## 3. The first pullback: removing the planner (06-20)

Before any of the above had fully settled, RedKite briefly grew a much bigger scope — a
`red-kite-git` module for branch creation, a `red-kite-scan` CLI with `apply-plan`, an
`UpgradePlan`/`PlanSafetyChecker`/`RecommendationPlanner` machinery for generating and
applying multi-step remediation plans. `cdaa233` removed all of it in one commit:

> "RedKite is now a pure scan-and-report tool: scan in the browser, review upgrades per
> module, click Apply to get a popup with the patched POM, copy and paste it into the file
> on disk."

This is the first sign of a pattern that recurs through the project's history: an ambitious
planning/strategy abstraction gets tried, turns out to be more machinery than the tool is
ready to support, and gets cut back to something the UI can actually drive end-to-end.

## 4. Convergence detection and a real templating layer (06-22 → 06-26)

`4dcd771` added the other major analysis axis besides CVEs and stale versions: Maven
Enforcer's `dependencyConvergence`/`requireUpperBoundDeps` conflicts, with one-click
Pin/Exclude actions. `8ebf9c4`/`9c1fb1a` streamlined conflict resolution into the same
"Apply Selected" flow as everything else, rather than a separate path.

`291b080`/`b5dac02` migrated the server's hand-built HTML strings to Thymeleaf templates for
the page shell — though, as later sessions would rediscover, the actual remediation-card
markup stayed as Java string-building in `RedKiteServerMain`, which is still true today (and
is exactly why this session's Stage 5 filter-chip work had to edit Java string concatenation,
not a template).

## 5. The big vision documents (07-01 → 07-02)

`ae4b068`/`f92ee60` (`future.md`) and `0b9d5cb`/`f10aa91` (`hybrid.md`) sketched the
four-model/strategy system described at the top of this file. Nothing merged in this
session — it's pure design — but reading it alongside what shipped afterward, it clearly
set the agenda for the next month and a half:

- "RedKite must distinguish project-owned controls from RedKite-originated controls" → the
  pin lifecycle work in section 6.
- "resolves known CVEs" with upgrade/downgrade/best-effort tiers → `b50b68c`.
- "No hardcoded dependency-family knowledge" → the alignment work in section 6, and later,
  this session's insistence that release families come from curated/authoritative sources,
  never inferred from a shared property.
- "compare alternative strategies" → not attempted again until this session's `UpdatePlan`.

## 6. Building the pieces, incrementally (07-11 → 07-16)

Nine days after `hybrid.md`, `c8fc792` added a validate → apply → validate flow — a much
smaller, concrete slice of the four-model document's "unmodified baseline validation" idea.
`b50b68c` then added the three-tier CVE resolution (upgrade fix / downgrade fix / best-effort
lowest-severity) that's still the core CVE-remediation logic today, verified live so the
suggested version doesn't carry its own unrelated CVE.

The pin system grew up in this window: a `Pin` control so bulk upgrades can skip specific
components (`a794e17`), release-train/family alignment during auto-fix (`296c51c`,
`3a15d93`), and — after enough line-splicing bugs (an `applyExclusion` that always inserted a
*second* `<exclusions>` block, which Maven's XSD rejects) — a full rewrite of
`RemediationApplier` onto DOM parse/serialise instead of string manipulation (`b3d6ea1`),
which is the approach every POM mutation still uses.

## 7. The "unmanaged" experiment (07-16 → 07-21)

`461571b` stopped recommending unjustified version bumps for transitive dependencies — the
rule that "a transitive dependency needs a *concrete* reason to move" (an existing pin, a
conflict, or a fixable CVE), later formalized as `transitiveRecommendedVersion`. `786b14b`
added a "Leave alone" pin state so non-conflicting transitives would stop nagging, which
`665f43b` then refined: a fixable CVE overrides "leave alone" and forces a real
recommendation regardless.

This "unmanaged" marker went through several iterations — renamed from `redkite:ignore`
(`3ac0214`), fixed for a stale-`<dependency>`-entry bug (`e5917fb`), fixed for silently
no-op'ing on CVE upgrades (`77a14b9`) — before this session opened by removing the concept
entirely (`b9f60f2`): "unmanaged" became a purely computed UI default, never written to the
POM at all, once analysis showed the persisted marker's only real value was an audit trail
nothing was reading.

## 8. This session: upgrade becomes one kind of update (07-22 → 07-23)

The rest of the current session's commits are one continuous arc, prompted by a design brief
asking RedKite to stop treating "upgrade" as the only kind of change and start modeling
*why* a dependency needs attention, *what* controls its version, and *what* concrete actions
are actually available — separately.

**Stage 1 — vocabulary, additive only** (`c0debfd`): `DependencyOrigin`, `VersionController`,
`DependencyFinding`, `ControlSet`, `ReleaseFamily`, `UpdateAction` — new types computed from
existing scan data, nothing persisted changed shape (`Store` serializes `ScanReport` via raw
Java serialization, so changing an existing record's fields would risk breaking every
previously stored scan).

**Provenance** (`e32dea4`, `8199398`, `6f6dd25`): local `dependencyManagement` entries
promoted to components even on non-aggregator modules (previously invisible — including
RedKite's *own* prior CVE pins); BOM imports (`<type>pom</type><scope>import</scope>`)
finally distinguished from plain managed entries; and a real parent/BOM provenance resolver
(`PomFetcher`/`ManagedVersionResolver`) that walks the parent chain and imported BOMs via the
local `.m2` cache or HTTP — not by shelling out to Maven again, since fetching a POM by known
coordinate is a static file GET, not a resolution algorithm.

**Candidate updates and plans** (`65ff520`, `0a99eab`, `e2397d2`): selections sharing a
control set (like `logback-core` and `logback-classic`, linked only by the
`logback.version` property, one declared locally, one resolved through Spring Boot's own
BOM) now collapse into one proposed change instead of two independent edits — the exact
worked example from `hybrid.md`'s "compare alternative strategies" idea, minus the parts that
still need external version metadata this session didn't wire up (updating a parent/BOM to a
newer release as its own alternative).

**UI** (`b740d8f`): the CVE/Conflict/Snapshot/Upgradeable/Transitive/Clean/All tab bar —
descended in a more or less straight line from `ef652f3`'s original `CVE/Upgrades/All`
buttons — replaced with three actual views (Findings/Clean/All) and independent,
multi-select filter chips, since a dependency being both a CVE fix *and* transitive was never
really an exclusive-tab fact in the first place.

**Terminology and accuracy** (`e98988b`, `9031210`, `6a15aa5`, `b2e178a`, `f6825f2`):
"upgrade" reworded to "update" everywhere it meant the general case rather than a specific
direction, and — prompted by simply looking at the live counts — two real bugs found and
fixed: the "needs an update" count included dependencies the user had already pinned
(misleading, since a pin *is* the decision not to move), and included transitive
dependencies whose own version selector had already concluded there was nothing to actually
apply. Both were the same root inconsistency the codebase had carried since `ef652f3`: a raw
"does a recommendation exist" signal standing in for "is this genuinely actionable," never
reconciled until something made the gap between them visible.

## 9. Cache efficiency and a license axis (07-23 → 07-26)

The apply flow got one real gap fixed before this stretch's bigger arc started: `7e898e3`
replaced a silent no-op "Apply selected" (nothing visibly happened if the computed patch set
came out empty) with a preview panel listing every change about to be made, or an honest "No
changes." — and in building it, `5f963b9` found a real bug it had been quietly hiding: a
user-picked version for one of RedKite's *own* prior pins had nowhere to go, because
`patchPomXml` deliberately excludes RedKite's own pin elements from the normal patch path (to
protect them from literal-to-property normalisation during unrelated bulk upgrades). A
one-off third pass now updates a pin's own `<version>` and its marker comment's `version=`
attribute in place when explicitly requested. `b6400c8` closed a related piece of drift:
`${xxx.version}` properties left behind after the pin or dependency that created them was
later replaced or removed, now swept up — but only when neither a literal `${name}` reference
nor the scan's own provenance resolution still needs them, since a property a project's BOM
references *internally* (never appearing as a literal `${...}` in the child POM's own text)
would otherwise look orphaned and get wrongly deleted.

`ccdb5f5` fixed a scaling problem the three-tier CVE search had been quietly generating since
`b50b68c`: verifying up to ~16 candidate versions per vulnerable component meant one OSV call
per candidate — 3115 calls on one real project's first scan. OSV's package-level query
(omitting the version) returns every advisory for a package in one call; `HttpVulnerabilityProvider`
now fetches and caches that once per package and matches version ranges locally, dropping the
same project's first-scan call count to 344 — one per distinct package — with the differential
correctness checked against six real per-version OSV results captured before the change.

The rest of the window is a single, iterative arc: giving a dependency's *license* the same
first-class treatment CVEs and updates already had. `0732cf5` added `LicenseResolver` (reusing
`PomFetcher`'s parent-chain walk) and per-card license badges; `1a2d6f1`/`dbb6688` worked out
where the breakdown panel actually belonged (not the remediation banner, not nested inside a
panel that only renders when Enforcer is configured — its own always-visible panel). `a60569a`
added `LicenseNormalizer`, deliberately conservative (a Classpath Exception or `-only` vs.
`-or-later` never merges, even when superficially similar), built and refined twice against
real observed license strings. `10f058a`/`d1cdc49`/`ba050ab` made license badges clickable
filters — and immediately hit the same class of bug the CVE-count work would hit again later:
a filter whose matches are silently hidden by an unrelated, already-active view or module
selector, with no indication why. Each fix followed the same pattern as the eventual Findings
reconciliation: reset the *other* dimension when a filter is chosen, rather than leaving the
user to guess why their click produced zero results. `aa7726c` made permissiveness a
configurable ranking (not hardcoded) and highlighted a dependency's most-permissive license;
`c433b7e` then fixed *counting* to match — a dual-licensed dependency now contributes to
exactly one bucket (its representative license) instead of inflating every license it happens
to declare, with the per-card filter switched to the same representative pick so a chip's
count and its actual matches never diverge again. `134ace7`/`c9ff555` rounded it out: a
single declared license is still eligible for the "most permissive" star, and badges display
the canonicalized name with the original declared string preserved in the tooltip rather than
lost.

## 10. This session: real per-artifact BOM resolution, and making the counts honest (07-29)

Three threads, worked in sequence over one long session.

**Child-dependency CVE visibility** (`a5819ed`, `4a2dc40`, `99ad2f5`): a dependency's own
severity badge only ever reflected *its own* findings — a clean, non-vulnerable direct
dependency gave no hint that something it pulls in transitively has a known CVE. A new
`ChildVulnerabilityAggregator` (`red-kite-core`) rolls up severity-by-count from a component's
full transitive subtree, deduped by `groupId:artifactId@version` so a diamond-shaped dependency
reachable through more than one path is only counted once, and rendered as a small chip row
("In dependencies: 2 Critical, 1 High") with each chip's own tooltip naming the specific child
and advisory behind that count — not just one generic message for the whole row.

**A real, non-rollback-safe apply path found and closed**: the "Auto-fix — computed
dep-management pins" button (the multi-module convergence workflow's own apply action) turned
out to route through `/api/scans/remediation/apply` — a single-pin-at-a-time endpoint with no
build validation and no rollback at all, unlike the properly bracketed
validate→write→validate→revert job every other apply path already used. `d5eddb6` rewired it
onto the same `apply-batch` job, gaining the existing rollback guarantee for free. Verified by
deliberately pinning a real fixture to a version that fails to resolve and confirming the
build genuinely rolls back afterward — not just that the code compiles.

**The Jackson BOM bug, and the fix that generalizes past Jackson**: reported as "RedKite pins
`jackson-annotations` to a version that doesn't exist." The actual defect: `alignFamilyVersions`
computed one target version per coordinated release family (Jackson, Netty, Cucumber, ...) and
broadcast it onto every member unconditionally — correct for a true release train where every
module really does share one version string, wrong for a BOM that manages different members at
different versions (the real Jackson 2.22.1 BOM manages `jackson-core`/`jackson-databind` at
`2.22.1` but `jackson-annotations` at `2.22` — confirmed live against Maven Central, where
`jackson-annotations:2.22.1` is a genuine 404). The fix is a full rewrite,
`FamilyVersionAligner` (`red-kite-maven`), reusing — not replacing — the existing
`ManagedVersionResolver` BOM-walking engine that already existed for provenance display but had
never been wired into version *computation*: a family member with a resolvable managed version
(via an imported BOM, a parent, or the project's own direct entry) is now reconciled
independently, never broadcast; a member the project explicitly overrides is respected and
never silently replaced; when several members land on the exact same target version through a
BOM they're already imported via, their pins collapse into one pin at the BOM's own coordinate
so `RemediationApplier`'s existing property-bump logic can apply it as a single
`<jackson.version>` update instead of N literal ones — verified only after probing confirms
every affected member. Two smaller, real gaps were found and closed along the way:
`ManagedVersionResolver` didn't chase a property whose own value was itself another property
reference (the real Jackson BOM's `jackson.version.core` is literally `${jackson.version}`) —
fixed with a cycle-guarded resolution chain; and `PomFetcher` collapsed "confirmed absent" and
"transport error" into the same empty result, which a new `PomFetchResult` sealed type and
`PomAvailabilityChecker` now keep apart, so an unreachable optional repository never masquerades
as proof an artifact doesn't exist. The `convergence-fixture` test project gained a matching
scenario (old-wrapper/new-wrapper declaring the mismatched Jackson versions directly, no BOM
import, reproducing the bug's simpler branch) — verified against the real, running app end to
end: the computed pin for `jackson-annotations` is `2.22`, never `2.22.1`, and the full
multi-module reactor genuinely builds, both before and after applying it. Jackson itself is
just one configured entry (`bomGroupId`/`bomArtifactId`) in the existing family table — the
resolution mechanism underneath has no Jackson-specific code at all.

**Making "N need remediation" mean what it says**: reported as three separate-looking bugs that
turned out to share one root cause. The top banner's counts came from
`RemediationClassifier.summarize()` (deduped by unique dependency); the Findings/Clean/All tabs
counted cards (one per module a dependency resolves into) using a *different* predicate,
`isCardClean`, which had accumulated a special case suppressing transitive dependencies with no
*fixable* CVE — which also, as a side effect, hid transitive dependencies with a real,
*unfixable* CVE. Fixing that surfaced a second bug: `severityBadgeHtml` printed "✓ Clean"
whenever a component had no CVE at all, regardless of whether it actually needed attention for
a non-CVE reason — decoupled from the very flag meant to gate it. A third: the "No upgrade
available" chip was true whenever RedKite wasn't offering to apply anything, not whether an
upgrade actually existed — so a dependency with "(Latest: 5.34.0)" printed right above it could
still read "No upgrade available." And a fourth, once the first three surfaced dependencies
that had been invisible before: a version selector could render for a transitive dependency
with nothing but a plain, unforced recommendation behind it, defaulting to "No change" — because
`showVersionSelector`'s gate hadn't been updated to match the same "concrete reason required"
rule `transitiveRecommendedVersion` already enforced elsewhere. Each was fixed in turn, verified
live against a real scan after every change — and the final shape settled on isn't "always show
everything": a transitive dependency whose *only* issue is a plain, non-CVE update with nothing
forcing the move is deliberately excluded from Findings as noise (it still shows an
informational chip, just filed under Clean) — and, at the user's explicit request, the banner's
own counts were switched to derive from that same per-dependency judgment instead of a separate
core-level tally, so the two can no longer disagree about what they're both supposed to be
describing.

A GitHub Pages documentation site (`docs/`, `just-the-docs`, dark color scheme) was set up
alongside this work, starting with a Quick Start guide — the first page of what's intended to
grow into a full manual over time.

---

## Where that leaves things

The current shape, per `DESIGN.md`: four modules (`red-kite-core` pure domain and
classifiers, `red-kite-maven` subprocess/POM/provenance, `red-kite-metadata` external
lookups, `red-kite-server` HTTP/orchestration/UI), H2 for storage, no framework beyond the
JDK's own `HttpServer`. The discipline from section 8 has held: additive where possible,
verified against a real project — often a real, running scan, not just a passing test suite —
at every step, and scoped back rather than guessed at when the honest answer was "not
resolvable yet."

What `future.md`/`hybrid.md` still describe that doesn't exist: the four-model comparison,
bounded auto-retry ("Maximal") search, and branch-based execution history. What's now real
that wasn't a week ago: a coordinated dependency family's version isn't just "the family's
version" broadcast onto every member — it's whatever a real BOM actually manages for that
specific member, resolved the same way for any family with a known BOM, not special-cased for
Jackson; a license has the same first-class treatment (resolution, normalization, permissiveness
ranking, filtering) that CVEs and updates already had; and the counts a user sees at the top of
a page and the list they see underneath it are, provably, describing the same thing.
