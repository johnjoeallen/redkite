# Dependency Resolution

RedKite doesn't reimplement Maven's dependency resolution — it runs `mvn dependency:tree` against each module's POM and parses the real output. This means RedKite always sees exactly what your own Maven setup would resolve, including whatever repositories, mirrors, and version conflicts your project's own configuration produces.

## Direct vs. transitive

The tree's indentation is what determines whether a dependency is direct or transitive — a dependency at the first indentation level is direct (declared in that module's own `<dependencies>`), anything deeper is transitive. RedKite doesn't use a separate flag or a second resolution pass for this; it reads it straight off the shape of the tree Maven already produced.

## Conflict losers are skipped

Maven's tree output marks a dependency version that lost a "nearest wins" conflict as `(omitted for conflict with X)`. RedKite skips these lines entirely — only the version Maven actually resolved to is kept, since that's the version that will actually end up on the classpath.

## Aggregator modules

A module whose POM only declares child modules (`packaging=pom`, no dependencies of its own) doesn't get its own `dependency:tree` run — there's nothing to resolve.
