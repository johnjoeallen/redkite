# Requirements

- Java 17 or later ([download](https://adoptium.net))
- Maven 3.9 or later

Both `java` and `mvn` must be available on the system `PATH` — RedKite shells out to Maven for dependency-tree resolution and build validation. Verify both before installing:

```bash
java -version
mvn -version
```

RedKite itself keeps all analysis data on the local machine — see [Local-First Design](../concepts/local-first-design.md) for exactly what it does and doesn't send over the network.
