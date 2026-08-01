# AI-Assisted Development

RedKite's code, tests, and documentation were written by AI coding assistants —
**Claude** (Anthropic) and **Codex** (OpenAI) — directed, reviewed, and manually tested
throughout by the project's author. This page states that plainly, since it isn't
obvious from the code or commit history alone.

## How it worked

The author did not write production code, tests, or documentation by hand. The actual
workflow was:

- **Direction** — describing a feature, bug, or design change in plain language, often
  iterating on the design itself over several rounds before or during implementation.
- **Review** — reading the resulting diffs, catching design issues, and requesting
  changes.
- **Manual testing** — running RedKite against real Maven projects to find issues that
  only show up in practice, not in a spec.

Every commit in this repository was authored end-to-end by an AI assistant working from
that direction and feedback, including the automated test suite that backs it — see
[Testing](testing.md) — and the documentation site you're reading now.

## Estimated time saved

The author's own estimate, based on repository data (lines of code, test count, and lines
deleted through redesign) and throughput rates the author — a developer with 40+ years of
experience — considers realistic for their own solo pace:

| Deliverable | Volume | Rate | Solo hours |
|---|---|---|---|
| Production code | 14,451 LOC | 30 LOC/hr | 482h |
| Test suite | 3,628 LOC, 227 tests | 17.5 LOC/hr | 207h |
| Documentation | 4,259 LOC | 15 LOC/hr | 284h |
| Redesign/refactor tax | 8,749 LOC deleted | 12 LOC/hr | 729h |
| **Total** | | | **1,702h (46.0 person-weeks)** |

The redesign/refactor tax accounts for lines written and then deleted as the design
changed mid-project — real effort invisible in a final-state line count, but the kind of
cost that's disproportionately expensive to pay by hand, since revisiting a settled design
gets more expensive the later it happens.

Actual investment was **85 hours (2.3 person-weeks)** — review, direction, and manual
testing only, no hand-written code, tests, or docs.

**Net effort avoided: 1,617 hours — 43.7 person-weeks — a 20x leverage factor.**

## Why this is disclosed here

Software built this way can look, in the diff, indistinguishable from hand-written code.
Whether that matters to you depends on what you're using RedKite for, but it shouldn't be
something you have to infer — see [Evolution](evolution.md) for how the design actually
got here, iteration by iteration, and [Bugs Fixed](bugs-fixed.md) for a record of what's
gone wrong and been corrected along the way. Both are also AI-written, from the same git
history anyone can inspect.
