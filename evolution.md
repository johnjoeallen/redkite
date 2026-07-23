# RedKite — Evolution

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

---

## Where that leaves things

The current shape, per `DESIGN.md`: four modules (`red-kite-core` pure domain and
classifiers, `red-kite-maven` subprocess/POM/provenance, `red-kite-metadata` external
lookups, `red-kite-server` HTTP/orchestration/UI), H2 for storage, no framework beyond the
JDK's own `HttpServer`. Every stage this session added followed the same discipline the
codebase has mostly kept since the planner got removed in `cdaa233`: additive where possible,
verified against a real project's `pom.xml` at every step, and scoped back rather than
guessed at when the honest answer was "not resolvable yet" (an imported BOM's *own* newer
releases, or a parent update, as alternatives in `UpdatePlan` — noted as follow-ups, not
faked).

What `future.md`/`hybrid.md` still describe that doesn't exist: the four-model comparison,
bounded auto-retry ("Maximal") search, and branch-based execution history. What's now real
that wasn't six weeks ago: a dependency's version has a *provenance* (not just a current
value), findings and updates are separate concepts from each other, and one finding can have
several genuinely different, comparable fixes rather than one recommendation the UI hands
you and calls it a day.
