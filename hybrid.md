RedKite Assist — Search, Validation, and Evidence Model

RedKite Assist is a local Maven dependency remediation assistant. It analyses dependency state, validates the current project, constructs safe candidate states, lets the user choose a strategy, applies changes safely, validates the result, and records useful history.

This document focuses on the auto-search design, manual override model, CVE-first candidate generation, validation strategy, wavefront search, stepwise refinement, and evidence rules.

⸻

1. Core Principle

Success proves compatibility.
Failure only proves that the tested state failed.

A successful build/startup proves that a dependency state works.

A failed build/startup does not automatically prove that the most recently changed dependency is bad. It may be a combination problem.

RedKite should persist strong evidence and derive weaker compatibility conclusions on demand.

⸻

2. High-Level Flow

flowchart TD
    A[Scan current repository] --> B[Construct Maven models]
    B --> C[Compare models]
    C --> D[Analyse facts]
    D --> E[Validate current unmodified POM]
    E --> F{Baseline valid?}
    F -- No --> G[Block Minimal and Maximal by default]
    G --> H[Manual lower-confidence override only]
    F -- Yes --> I[Run metadata/CVE candidate-generation phase]
    I --> J[Generate candidate states]
    J --> K[Choose strategy]
    K --> L[Generate plan]
    L --> M[Apply change]
    M --> N[Validate changed state]
    N --> O{Validation passed?}
    O -- Yes --> P[Record successful state]
    O -- No --> Q[Record failed attempt]
    Q --> R[Attribute failure if possible]
    R --> S[Rollback / retry / stop]
    P --> T[Accept / Manual / Other strategy / Rollback]

⸻

3. Maven Models

RedKite compares four Maven resolution models.

Model	Purpose
Pristine model	Project without RedKite-originated controls, even if later accepted by the user.
Clean accepted baseline	Accepted project state, excluding unaccepted RedKite pins.
In-place model	Current POM exactly as it exists on disk.
Natural candidate model	Candidate upstream changes without RedKite-originated transitive overrides.

The current dependency:tree alone is not enough because RedKite-injected dependencyManagement entries can mask what Maven would naturally resolve.

⸻

4. RedKite-Originated Controls

RedKite-generated changes should be marked while RedKite-managed.

Example:

<properties>
    <!-- redkite:pin action=modified control=property originalValue=2.15.4 recommendationId=rk-rec-123 -->
    <com.fasterxml.jackson.core.version>2.17.3</com.fasterxml.jackson.core.version>
</properties>

Rules:

Case	Behaviour
RedKite modified existing property	Keep property, substitute original value in clean/pristine models.
RedKite modified existing dependencyManagement entry	Keep entry, substitute original version in clean/pristine models.
RedKite modified existing BOM	Keep BOM, substitute original version in clean/pristine models.
RedKite injected dependencyManagement transitive override	Remove in clean/pristine/natural models.
User removed pin	Treat as accepted, but retain origin metadata in local history.
Pin lacks original value	Keep current value but mark baseline uncertain.

Important principle:

RedKite restores declared controls, not dependency-tree accidents.

A resolved transitive version is an outcome of Maven resolution, not automatically a rollback target.

⸻

5. Unmodified Baseline Validation

Before automated remediation, RedKite must validate the current POM exactly as it exists on disk.

This is the unmodified baseline.

mvn clean install
startup validation if configured
smoke checks if configured

Virtual models are for analysis and planning. They are not substitutes for proving that the real project currently builds and starts.

If unmodified validation fails:

Strategy	Behaviour
Minimal	Blocked by default
Maximal	Blocked by default
Manual	Allowed only as explicit lower-confidence override

⸻

6. Metadata/CVE Candidate-Generation Phase

After the unmodified baseline passes, RedKite should run a metadata-only candidate-generation phase before expensive build/startup validation.

This phase should not try versions by building them.

It should use metadata and analysis facts to construct a small set of candidate states worth validating.

validated baseline
→ metadata/CVE analysis
→ candidate filtering
→ candidate-state generation
→ ranking
→ shortlisted validation

The purpose is to avoid spending build time on candidates that cannot improve the project.

⸻

7. Candidate-Generation Inputs

The candidate-generation phase should use:

current resolved dependency graph
effective POM
dependencyManagement
pluginManagement
BOMs
properties
direct dependencies
transitive dependencies
available version metadata
CVE/OSV/security advisory data
known-good history
known-bad exact states
Java compatibility
Maven compatibility
Spring Boot/platform constraints where inferable
RedKite-originated control metadata

It should not require a build/run attempt for every version.

⸻

8. Candidate-Generation Outputs

The phase should produce candidate states, not just individual version suggestions.

Outputs include:

minimal candidate state
maximal candidate state
fallback candidate states
per-dependency candidate lists
candidate ranking
discarded candidates with reasons
candidate-state fingerprints

Example discarded reasons:

still vulnerable
introduces worse CVE risk
outside same major
known-bad exact state
Java-incompatible
Maven-incompatible
not reachable through declared controls
requires Manual because major upgrade

⸻

9. CVE-First Filtering

Before any build is attempted, RedKite should reduce candidate versions.

For each dependency/control group:

same major only, except Manual
skip exact known-bad states
require Java compatibility
require Maven compatibility
prefer CVE-free versions
if no CVE-free versions exist, keep lowest-risk CVE versions
discard versions that do not improve the current CVE/policy state

Candidate ranking:

1. CVE-free versions
2. lowest weighted CVE risk
3. highest version for Maximal
4. lowest sufficient version for Minimal
5. previously successful versions
6. versions seen in successful combinations

Example:

Current: 2.15.4
Available:
2.18.3  CVE-free
2.18.2  CVE-free
2.17.3  Medium CVE
2.16.2  High CVE
2.15.5  Critical CVE
Candidate set:
2.18.3
2.18.2
Skip the CVE versions unless no CVE-free option works or policy allows fallback.

⸻

10. Minimal Candidate Generation

Minimal should choose the lowest acceptable fixing candidate, not the next patch blindly.

Example:

Current:
A 1.2.0 vulnerable
Available:
1.2.1 vulnerable
1.2.2 vulnerable
1.2.3 CVE-free
1.3.0 CVE-free
1.4.0 CVE-free

Minimal first candidate:

A 1.2.3

Not:

A 1.2.1
A 1.2.2

Minimal candidate generation optimises for:

lowest version that fixes/reduces the issue
fewest changed controls
smallest dependency movement
same major only
lowest blast radius

⸻

11. Maximal Candidate Generation

Maximal should choose the highest acceptable same-major CVE-free candidate first.

Example:

Current:
A 1.2.0
CVE-free same-major candidates:
1.2.3
1.3.0
1.4.0

Maximal first candidate:

A 1.4.0

If that fails, fallback candidates remain inside the CVE-free set first:

1.3.0
1.2.3

Only if there are no CVE-free candidates should RedKite consider lowest-risk CVE-bearing candidates.

Maximal candidate generation optimises for:

highest same-major version
CVE-free preferred
lowest CVE risk fallback
known-good evidence
successful-combination evidence

⸻

12. Candidate States Before Validation

RedKite should build candidate states before running expensive validation.

Example:

Current:
A vulnerable
B vulnerable
C clean
Minimal candidate state:
A lowest CVE-free
B lowest CVE-free
C unchanged
Maximal candidate state:
A highest CVE-free
B highest CVE-free
C highest acceptable same-major if in scope

These states can then be validated using wavefront, staged validation, bisection, and stepwise refinement.

The key rule:

CVE-free candidate generation filters what is worth validating.
It does not prove the candidate builds or starts.

⸻

13. Reduced Validation Goal

Without CVE prefiltering:

60 dependencies × 7 versions = 420 per-dependency attempts

At 5 minutes per full build:

420 × 5 minutes = 2,100 minutes = 35 hours

With metadata/CVE candidate generation, RedKite should aim for:

baseline validation
+ minimal candidate state
+ maximal candidate state
+ a few bisection/stepwise retries if needed

In many projects this should reduce full build/startup validations from hundreds to roughly:

3–15 full validations

This is a target, not a guarantee.

⸻

14. Strategy Modes

After analysis and candidate generation, the user chooses a strategy.

Strategy	Direction	Behaviour
Minimal	Forward from origin	Finds the smallest same-major working upgrade.
Manual	User controlled	User chooses exact versions. Only mode allowed to cross major versions.
Maximal	Backward from highest candidate	Finds the highest working same-major upgrade.

Manual must remain available even after Minimal or Maximal finds a solution.

A found automatic solution is not the end of the workflow. The user can still choose:

Accept solution
Try Manual
Run Minimal
Run Maximal
Rollback
View logs/history

⸻

15. Strategy Flow

flowchart TD
    A[Analysis and candidate generation complete] --> B{Choose strategy}
    B --> C[Minimal]
    B --> D[Maximal]
    B --> E[Manual]
    C --> C1[Start from minimal candidate state]
    C1 --> C2[Validate lowest acceptable same-major fix]
    C2 --> C3{Validated?}
    C3 -- Yes --> C4[Return first minimal solution]
    C3 -- No --> C5{More higher fixing candidates?}
    C5 -- Yes --> C6[Try next fixing candidate]
    C6 --> C3
    C5 -- No --> C7[No minimal auto solution]
    D --> D1[Start from maximal candidate state]
    D1 --> D2[Validate highest acceptable same-major state]
    D2 --> D3{Validated?}
    D3 -- Yes --> D4[Return highest working solution]
    D3 -- No --> D5{More lower CVE-free candidates above origin?}
    D5 -- Yes --> D6[Try lower candidate]
    D6 --> D3
    D5 -- No --> D7[No maximal auto solution]
    E --> E1[User selects exact version/control]
    E1 --> E2[Warn if major/unsafe/non-aligned]
    E2 --> E3[Validate selected plan]
    C4 --> F[Accept / Manual / Maximal / Rollback]
    D4 --> F
    E3 --> F

⸻

16. Minimal Strategy

Minimal is conservative.

It starts at the origin and moves forward, but only through candidates that can actually improve the CVE or policy state.

origin → lowest fixing candidate → next fixing candidate → stop at first validated solution

Minimal optimises for:

smallest movement
fewest changed controls
lowest blast radius
CVE or policy improvement
same major only

Example:

Origin:
1.2.0
Candidates:
1.2.1 vulnerable
1.2.2 vulnerable
1.2.3 CVE-free
1.3.0 CVE-free
Minimal skips:
1.2.1
1.2.2
Minimal tries:
1.2.3
then 1.3.0 if required

Minimal does not chase latest.

⸻

17. Maximal Strategy

Maximal attempts to find the highest working same-major upgrade.

It starts at the highest acceptable same-major candidate and iterates backward.

highest acceptable candidate → lower CVE-free candidate → lower CVE-free candidate → stop at first validated solution

Maximal optimises for:

highest validated same-major version
CVE-free preferred
lowest CVE risk if no CVE-free candidate exists
same major only

Example:

Origin:
1.2.0
Candidates:
1.4.0 CVE-free
1.3.5 CVE-free
1.3.4 CVE-free
1.2.9 CVE-free
Maximal tries:
1.4.0
then 1.3.5
then 1.3.4
and stops at the first valid solution

Maximal never crosses major versions.

⸻

18. Manual Strategy

Manual gives explicit user control.

Manual supports:

exact versions
property changes
BOM changes
dependencyManagement changes
plugin changes
transitive overrides
major-version upgrades
partial/non-aligned changes
rollback targets

Manual is the only strategy that may cross major versions.

Manual must warn for:

major-version jumps
newer-than-minimal choices
non-aligned choices
partial overrides
failed unmodified baseline
likely source-code remediation
versions previously known-bad
still-vulnerable selected versions
worse CVE-risk selections

Manual choices are recorded as explicit user decisions and still require validation.

Manual remains available even after an automatic solution is found.

⸻

19. Why Exhaustive Search Is Impossible

With 60 dependencies and 7 versions each:

7^60 ≈ 5.08 × 10^50 combinations

Even one-dependency-at-a-time with 7 candidates each gives:

60 × 7 = 420 validation runs

At 5 minutes per full build:

420 × 5 minutes = 2,100 minutes = 35 hours

Therefore RedKite must not run full build/startup validation for every candidate.

The metadata/CVE candidate-generation phase exists specifically to avoid this.

⸻

20. Staged Validation

RedKite should use a validation ladder.

flowchart TD
    A[Candidate state] --> B[Resolve check]
    B --> C{Resolve passed?}
    C -- No --> X[Reject candidate]
    C -- Yes --> D[Compile check]
    D --> E{Compile passed?}
    E -- No --> X
    E -- Yes --> F[Full build]
    F --> G{Build passed?}
    G -- No --> X
    G -- Yes --> H{Startup configured?}
    H -- No --> I[Candidate works]
    H -- Yes --> J[Startup validation]
    J --> K{Startup passed?}
    K -- Yes --> I
    K -- No --> X

Suggested stages:

1. dependency resolution
2. compile
3. full build
4. startup/smoke validation

Only shortlisted candidates should reach full build/startup.

⸻

21. Auto-Step Origin Rules

Every automated run must record:

run_start_state
component_start_version
candidate list
current candidate
last known-good state
attempt count
elapsed time

For each dependency/control group:

Minimal:
    search upward from origin
    skip non-fixing vulnerable candidates
    stop when no higher acceptable same-major candidate remains
Maximal:
    search downward from highest acceptable candidate
    prefer CVE-free fallback candidates first
    stop before returning to or below origin
Both:
    if candidate == origin, stop for that dependency

When all target dependencies/control groups have returned to origin or have no viable candidate:

stop auto strategy
report no automatic solution found
restore previous known-good state

⸻

22. Search Modes

RedKite can support multiple automated search modes.

Search Mode	Description
linear	Step one dependency/control at a time.
highest-first	Try the best candidate first, then fall back.
binary-probe	Use binary-style probing as an attempt-ordering heuristic.
survivor-set	Retain working combinations and combine them with later candidates.
wavefront	Move many dependencies together in strategy direction.
wavefront-then-stepwise	Use wavefront to gather evidence, then stepwise search to refine.

Binary probing is only a heuristic because dependency compatibility is not guaranteed to be monotonic.

1.0 works
1.1 fails
1.2 works
1.3 fails
1.4 works

A failed higher version does not prove lower versions fail.

⸻

23. Survivor-Set Search

Survivor-set search is useful in auto mode when RedKite wants to explore working combinations rather than one path.

Basic idea:

For dependency A:
    test candidate versions
    keep working versions
For dependency B:
    combine B candidates with A survivors
    validate combinations
    keep working combinations
For dependency C:
    combine C candidates with surviving A+B states
    validate
    keep working combinations
flowchart TD
    A[Start with known-good baseline] --> B[Test candidates for dependency A]
    B --> C[Keep working A survivors]
    C --> D[Combine B candidates with A survivors]
    D --> E[Validate A+B combinations]
    E --> F[Keep working A+B survivors]
    F --> G[Combine C candidates]
    G --> H[Validate A+B+C combinations]
    H --> I[Keep best survivors]
    I --> J{More dependencies and budget remains?}
    J -- Yes --> G
    J -- No --> K[Select best surviving state]

This is stronger than linear stepping because it can discover that a version works in one combination but not another.

⸻

24. Survivor Explosion

Survivor-set search can still explode.

If every dependency has 2 working versions:

2^60 combinations

Therefore RedKite must prune.

Required limits:

max candidates per dependency
max survivors per stage
max total attempts
max elapsed time
max validation time
max interaction depth

⸻

25. Wavefront Search

Wavefront search moves multiple eligible dependencies together in the strategy direction.

It reduces the number of validation attempts by testing combined states early.

Minimal Wavefront

Minimal wavefront moves forward from origin.

origin
→ lowest acceptable fix for each targeted dependency
→ validate
→ reanalyse
→ stop if acceptable solution is found

Minimal wavefront should usually target only dependencies needed for CVE or policy remediation.

Example:

Origin:
A1 B1 C1
Wave 1:
A2 B2 C2
If Wave 1 validates and fixes the issue:
    stop

Maximal Wavefront

Maximal wavefront starts from the highest acceptable same-major state.

highest acceptable state
→ validate
→ if fail, move downward or split the wave

Example:

Origin:
A1 B1 C1 D1
Highest acceptable:
A7 B7 C7 D7
If this validates:
    return highest working state

Wavefront can reduce validation attempts dramatically, but failed waves have weaker attribution.

A failed wave only proves:

this combined state failed

It does not prove every dependency in the wave is bad.

⸻

26. Wavefront Bisection

When a wavefront attempt fails, RedKite should not immediately step every dependency down.

It should use bounded bisection or subset validation.

flowchart TD
    A[Failed wavefront state] --> B[Split changed controls]
    B --> C[Test first subset against known-good baseline]
    C --> D{Subset passed?}
    D -- Yes --> E[Record passing subset]
    D -- No --> F[Record failing subset]
    E --> G[Test remaining subset or recombine]
    F --> H[Bisect failing subset further]
    G --> I[Build evidence for stepwise refinement]
    H --> I

Example:

Origin:
A1 B1 C1 D1 E1 F1
Maximal wave:
A7 B7 C7 D7 E7 F7
Wave fails.
Test subset:
A7 B7 C7 D1 E1 F1
If this passes:
    A/B/C are promising.
Test other subset:
A1 B1 C1 D7 E7 F7
If this fails:
    D/E/F or their interactions are suspicious.

Bisection gives RedKite useful evidence without testing every dependency individually.

⸻

27. Wavefront Then Stepwise

The strongest practical auto model is:

metadata/CVE candidate generation
→ wavefront
→ bounded bisection on failure
→ evidence-guided stepwise refinement

Candidate generation prevents useless validations.

Wavefront is the fast discovery phase.

Bisection identifies promising and suspicious regions.

Stepwise refinement uses the collected evidence to make precise changes.

flowchart TD
    A[Metadata/CVE candidate generation] --> B[Build candidate states]
    B --> C[Run wavefront attempt]
    C --> D{Wavefront passed?}
    D -- Yes --> E[Record successful full state]
    E --> F{Strategy}
    F -- Minimal --> G[Stop at first acceptable solution]
    F -- Maximal --> H[Return highest working state]
    F -- Manual --> I[Allow user refinement]
    D -- No --> J[Record failed exact state]
    J --> K[Extract failure signature]
    K --> L[Run bounded bisection/subset validation]
    L --> M[Record passing and failing subsets]
    M --> N[Derive candidate confidence]
    N --> O[Run evidence-guided stepwise search]
    O --> P{Solution found?}
    P -- Yes --> Q[Record successful state]
    P -- No --> R[Report no auto solution within guardrails]
    Q --> S[Accept / Manual / Rollback / Try other strategy]

Minimal

metadata/CVE candidate generation
forward wavefront
if pass, stop at first acceptable solution
if fail, bisect and stepwise only the failing required targets

Maximal

metadata/CVE candidate generation
backward wavefront from highest acceptable state
if pass, stop at highest solution
if fail, bisect and stepwise the failing or suspicious region

⸻

28. Evidence-Guided Stepwise Search

Stepwise search should not start blind if wavefront evidence exists.

It should use:

successful full states
failed full states
successful subsets
failed subsets
failure signatures
candidate confidence
known-good states
known-bad exact states
CVE-free candidate ranking
discarded candidate reasons

Example:

Origin:
A1 B1 C1 D1 E1 F1
Maximal wave:
A7 B7 C7 D7 E7 F7
Wave fails.
Bisection:
A7 B7 C7 D1 E1 F1 passes
A1 B1 C1 D7 E7 F7 fails
Stepwise should now:
preserve A7 B7 C7
focus on D/E/F
try candidates in D/E/F using confidence evidence

This avoids wasting validation attempts on already promising regions.

⸻

29. Failure Evidence

A failed combination should not automatically blame the latest dependency.

Failed state:

A3 + B2 + C5 failed

Possible causes:

C5 is bad
A3 + C5 conflict
B2 + C5 conflict
A3 + B2 conflict
A3 + B2 + C5 conflict
environment issue
test flake

Therefore RedKite should record the failed attempt, but not over-model every inferred failed pair/triple.

⸻

30. What to Persist

Persist strong evidence.

Candidate generation result

analysis_id
base_state_fingerprint
candidate_generation_mode
candidate_state_fingerprints
discarded_candidates
discard_reasons
timestamp

Successful attempt

attempt_id
base_state_fingerprint
successful_state_fingerprint
changed_controls
validation stages passed
logs
timestamp

Failed attempt

attempt_id
base_state_fingerprint
failed_state_fingerprint
changed_controls
validation_stage_failed
failure_signature
logs
timestamp

Successful subset

attempt_id
base_state_fingerprint
successful_subset_fingerprint
changed_controls
validation stages passed
source_attempt_id
timestamp

Failed subset

attempt_id
base_state_fingerprint
failed_subset_fingerprint
changed_controls
validation_stage_failed
failure_signature
source_attempt_id
timestamp

High-confidence attribution

Only persist culprit attribution when evidence is strong.

culprit_control
culprit_version
confidence
evidence

Examples of stronger evidence:

failure as only changed item
compiler package clearly maps to changed artifact
Maven resolution error names the artifact
runtime linkage error maps to changed artifact
same failure repeats with same component

⸻

31. What Not to Persist Permanently

Do not permanently store every inferred failed pair/triple combination as hard compatibility truth.

Avoid persisting:

A3+B2 failed
A3+C5 failed
B2+C5 failed
A3+B2+C5 failed

unless there is repeated evidence or strong attribution.

Reason:

Failure only proves the exact tested state failed.
It does not prove every pair inside the state is incompatible.

⸻

32. Derived Scoring

RedKite can derive scores from evidence counts rather than mutating a single score.

For each candidate version/control:

individual_success_count
individual_failure_count
combination_success_count
combination_failure_count
known_good_state_count
known_bad_state_count
successful_subset_count
failed_subset_count
error_attributed_failure_count
cve_free_candidate_count
discarded_candidate_count

Suggested scoring:

CVE-free candidate: +10
lowest-risk CVE fallback: +4
individual success: +10
combination success: +5
successful subset: +4
combination failure: -1
failed subset: -2
individual failure: -8
error-attributed failure: -5
known-good exact state: strong boost
known-bad exact state: exclude
still-vulnerable candidate: exclude for auto unless fallback policy allows

Failure penalties should be smaller than success boosts because combination failure is weak evidence.

⸻

33. Successful Combinations

Successful combinations are valuable and should be recorded completely.

A success proves that those versions worked together under validation.

Example:

A3 + B4 + C5 passed build and startup

This is strong compatibility evidence.

When selecting future candidates, RedKite should prefer versions that:

worked individually
appeared in successful combinations
appeared in successful subsets
appeared in successful pairs/triples with already-selected candidates
belong to known-good exact states
were selected by CVE-free candidate generation

⸻

34. Failed Attempts

Failed attempts are useful mainly for:

avoiding exact retries
failure attribution
debugging
detecting repeated signatures
small suspicion penalties

They should not become hard pairwise incompatibility rules unless supported by repeated or attributed evidence.

⸻

35. Selection Rule

When building candidate states or survivor sets:

1. prefer CVE-free candidates
2. stay same-major unless Manual
3. prefer Java/Maven-compatible candidates
4. exclude exact known-bad states
5. exclude still-vulnerable candidates unless no better option exists
6. prefer candidate states generated by metadata/CVE analysis
7. prefer individual success evidence
8. prefer successful combination evidence
9. prefer successful subset evidence
10. penalise failed-combination evidence lightly
11. focus stepwise refinement on suspicious or unproven regions
12. keep only top N survivors
13. full-validate finalists

⸻

36. Failure Handling

flowchart TD
    A[Validation failed] --> B[Record exact failed state]
    B --> C[Extract failure signature]
    C --> D{High-confidence culprit?}
    D -- Yes --> E[Record attributed culprit]
    E --> F[Try targeted rollback or lower candidate]
    D -- No --> G[Apply weak penalties only]
    G --> H[Do not blame latest dependency automatically]
    H --> I{Search mode}
    I -- Wavefront --> J[Bisect or test subsets]
    I -- Stepwise --> K[Try alternative candidate]
    I -- Survivor Set --> L[Keep other survivors]
    J --> M[Record subset evidence]
    K --> N[Continue or stop]
    L --> N
    M --> N

⸻

37. YAML Configuration Only

RedKite configuration should use YAML only.

Example:

redkite:
  validation:
    stages:
      - name: resolve
        command: "mvn dependency:tree"
        required: true
      - name: compile
        command: "mvn -DskipTests compile"
        required: true
      - name: build
        command: "mvn clean install"
        required: true
      - name: startup
        command: "mvn spring-boot:run"
        required: false
        timeoutSeconds: 90
  remediation:
    autoAnalysis:
      firstPass:
        mode: cve-candidate-generation
        runBuildValidation: false
        runStartupValidation: false
        filters:
          sameMajorOnly: true
          preferCveFree: true
          discardStillVulnerableVersions: true
          discardWorseRiskVersions: true
          requireJavaCompatible: true
          requireMavenCompatible: true
          skipKnownBadStates: true
        outputs:
          generateMinimalCandidateState: true
          generateMaximalCandidateState: true
          generateFallbackStates: true
          maxFallbackStates: 5
    strategies:
      minimal:
        sameMajorOnly: true
        searchDirection: forward
        searchMode: wavefront-then-stepwise
        candidateSource: cveCandidateStates
        useLowestFixingCandidate: true
        stopAtFirstValidSolution: true
        wavefront:
          enabled: true
          onlyCveOrPolicyTargets: true
          useLowestFixingCandidate: true
          onFailure: bisect
          keepPassingSubsets: true
          maxWaveSize: 20
          maxBisectionDepth: 5
        stepwise:
          enabledAfterWavefront: true
          useWavefrontEvidence: true
          focusOnFailingSubsets: true
          preservePassingSubsets: true
          maxAttemptsPerDependency: 3
      maximal:
        sameMajorOnly: true
        searchDirection: backward
        searchMode: wavefront-then-stepwise
        candidateSource: cveCandidateStates
        useHighestCveFreeCandidate: true
        fallbackWithinCveFreeSetFirst: true
        wavefront:
          enabled: true
          startAtHighestAcceptableState: true
          onFailure: bisect
          keepPassingSubsets: true
          recombinePassingSubsets: true
          maxWaveSize: 20
          maxBisectionDepth: 5
        stepwise:
          enabledAfterWavefront: true
          useWavefrontEvidence: true
          focusOnFailingSubsets: true
          preservePassingSubsets: true
          tryHighestConfidenceFirst: true
          maxAttemptsPerDependency: 3
        candidateFiltering:
          preferCveFree: true
          ifNoCveFreeUseLowestRisk: true
          skipKnownBad: true
          requireJavaCompatible: true
          requireMavenCompatible: true
        evidence:
          persistSuccessfulStates: true
          persistFailedStates: true
          persistSuccessfulSubsets: true
          persistFailedSubsets: true
          persistFailedPairs: false
          persistCandidateGenerationResults: true
          deriveScoresFromCounts: true
          cveFreeCandidateBoost: 10
          lowestRiskCveFallbackBoost: 4
          combinationFailurePenalty: 1
          failedSubsetPenalty: 2
          combinationSuccessBoost: 5
          successfulSubsetBoost: 4
          individualSuccessBoost: 10
          individualFailurePenalty: 8
        guardrails:
          maxTotalAttempts: 50
          maxAttemptsPerDependency: 3
          maxSurvivorsPerStage: 5
          maxElapsedMinutes: 60
          maxValidationMinutes: 8
          stopAtOrigin: true
          stopWhenNoSurvivors: true
          revertToKnownGoodOnStop: true
      manual:
        alwaysAvailable: true
        allowMajorUpgrade: true
        requireMajorUpgradeWarning: true
        warnOnStillVulnerableSelection: true
        warnOnWorseCveRisk: true

⸻

38. Recommended Default Auto Model

The recommended default automated model is:

cve-candidate-generation
→ wavefront-then-stepwise

This gives RedKite four layers:

Metadata/CVE candidate generation:
    avoid useless validations
Wavefront:
    fast global evidence
Bisection:
    identify promising and suspicious regions
Stepwise:
    precise refinement using collected evidence

Minimal should use:

metadata/CVE candidate generation
forward wavefront
lowest acceptable fixing candidates
stop at first valid solution
stepwise only if the wave fails

Maximal should use:

metadata/CVE candidate generation
backward wavefront
start from highest acceptable same-major state
if wave fails, bisect and stepwise suspicious regions

Manual remains available at all times.

⸻

39. Final Design Rule

RedKite should persist:

candidate-generation results
exact successful states
exact failed states
successful subsets
failed subsets
validation logs
failure signatures
high-confidence culprit attribution

RedKite should derive:

candidate confidence
pair/triple suspicion
compatibility likelihood
survivor ranking
stepwise priority

RedKite should avoid treating failed combinations as permanent hard incompatibility facts unless there is repeated or attributed evidence.

The practical rule is:

Validate the current project first.
Generate CVE-safe candidate states before expensive validation.
Record successes as strong compatibility evidence.
Record failures as exact failed states plus weak evidence.
Use wavefront to gather broad evidence quickly.
Use bisection to locate suspicious regions.
Use stepwise search to refine using collected evidence.
Manual remains available even after automation finds a solution.
Minimal searches forward.
Maximal searches backward.