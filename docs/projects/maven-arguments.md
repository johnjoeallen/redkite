# Maven Arguments

`.redkite/project.cfg` has three fields that all end up as extra arguments on every validation `mvn` call RedKite runs for a project — both the build check and, for Spring Boot projects, the `spring-boot:run` startup check:

```yaml
mavenArgs: -Dfoo=bar
profile: redkite
springProfiles: redkite
```

- **`mavenArgs`** — a whitespace-separated string of raw arguments, appended as-is. Use this for anything not covered by the two fields below.
- **`profile`** — a Maven profile ID (or comma-separated list), turned into `-P<profile>`.
- **`springProfiles`** — a Spring Boot active profile (or comma-separated list), turned into `-Dspring-boot.run.profiles=<value>` — a separate mechanism from a Maven profile; both can be needed at once.

The example above produces the equivalent of `-Dfoo=bar -Predkite -Dspring-boot.run.profiles=redkite`. These are appended after any arguments RedKite generates itself for the startup check (such as the port it starts the application on), so they never conflict with RedKite's own flags unless you explicitly set the same property yourself.

Only what you actually need has to be set — a project with no special build requirements needs none of these fields at all.
