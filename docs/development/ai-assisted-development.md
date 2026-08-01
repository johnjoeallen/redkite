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

## Why this is disclosed here

Software built this way can look, in the diff, indistinguishable from hand-written code.
Whether that matters to you depends on what you're using RedKite for, but it shouldn't be
something you have to infer — see [Evolution](evolution.md) for how the design actually
got here, iteration by iteration, and [Bugs Fixed](bugs-fixed.md) for a record of what's
gone wrong and been corrected along the way. Both are also AI-written, from the same git
history anyone can inspect.
