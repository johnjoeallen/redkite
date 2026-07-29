# Building from Source

RedKite is a standard multi-module Maven reactor, requiring nothing beyond [the same JDK and Maven RedKite itself needs](../getting-started/requirements.md) — Java 17+ and Maven 3.9+.

```bash
git clone <repository-url>
cd redkite
mvn clean install -DskipTests
```

This builds all four modules (`red-kite-core`, `red-kite-maven`, `red-kite-metadata`, `red-kite-server`) and produces the runnable shaded jar at:

```
red-kite-server/target/red-kite-<version>.jar
```

Run it directly:

```bash
java -jar red-kite-server/target/red-kite-<version>.jar
```

To run the full test suite instead of skipping it, drop `-DskipTests`:

```bash
mvn clean install
```

See [Testing](testing.md) for what the suite covers, and [Release Layout](../reference/release-layout.md) for how a packaged distribution is put together.
