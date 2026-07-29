# Contributing

There's no separate contribution process document yet — this page covers the conventions the codebase itself already follows.

## Before submitting a change

- `mvn test` should pass across all modules — see [Testing](testing.md).
- Keep the module boundaries intact: `red-kite-core` has no dependency on Maven-specific or I/O-performing code, so general-purpose logic belongs there, not duplicated into `red-kite-maven` or `red-kite-server`. See [Modules](modules.md).
- If your change touches a subprocess-driven or network-driven code path (Maven invocation, HTTP calls), prefer testing it against a fake the way the existing suite does, and use the fixtures under `test/projects/` for manual verification rather than adding a real subprocess-driving test.

## Design philosophy

RedKite deliberately avoids a web framework, DI container, or ORM — see [Architecture](architecture.md) for why. A change that pulls one in for convenience runs against that grain and should have a strong reason behind it.

## Where to start

- `DESIGN.md` at the repository root — a deeper architectural reference than this site currently covers in places.
- [Evolution](evolution.md) — how the project got to its current shape, which is useful context for understanding why some things are built the way they are.
