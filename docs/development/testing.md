# Testing

```bash
mvn test
```

runs the full suite across all four modules (JUnit 5). There's no separate integration-test profile to opt into or out of — the suite is deliberately kept fast enough to run as part of the normal build.

## In-memory, not subprocess-driven

Tests that would otherwise need a real Maven subprocess or a real network call are written against fakes instead — for example, `ManagedVersionResolver`'s tests use a `FakePomSource` that returns canned POM XML rather than fetching anything real. This keeps the suite fast and deterministic, at the cost of not exercising the real `mvn`/network code paths directly.

## Manual verification for subprocess-driven behavior

Logic that genuinely depends on invoking Maven or validating a real build (dependency-tree scanning, enforcer runs, build/startup validation) is verified manually against the bundled fixture projects under `test/projects/`, rather than by a JUnit test that shells out. `test/projects/revert-poms.sh` restores those fixtures to their checked-in `.orig` baseline between runs, so manual verification doesn't leave the repository dirty.

## Adding a test

New logic in `red-kite-core` or `red-kite-maven` should get a unit test following the existing pattern for that module — plain JUnit for `red-kite-core`, fake-backed I/O for `red-kite-maven`. If what you're testing can only be verified by actually running Maven, prefer extending the manual-verification fixtures over adding a subprocess-driving test to the suite.
