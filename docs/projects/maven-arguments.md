# Maven Arguments

`.redkite/config.yml` has two fields that end up as extra arguments on every validation `mvn` call RedKite runs for a project — both the build check and, for Spring Boot projects, the `spring-boot:run` startup check:

```yaml
mavenArgs: -Dfoo=bar
profile: redkite
```

- **`mavenArgs`** — a whitespace-separated string of raw arguments, appended as-is. Use this for anything not covered by `profile` or `springBoot.profiles`.
- **`profile`** — a Maven profile ID (or comma-separated list), turned into `-P<profile>`.

The example above produces `-Dfoo=bar -Predkite`, appended after any arguments RedKite generates itself for the startup check (such as the port it starts the application on), so they never conflict with RedKite's own flags unless you explicitly set the same property yourself.

A Spring Boot active profile is a separate, related concept — see the `springBoot.profiles` field on [Build Validation](build-validation.md), which turns into `-Dspring-boot.run.profiles=<value>` but, unlike these two fields, only applies to the `spring-boot:run` startup check, never the plain build.

Only what you actually need has to be set — a project with no special build requirements needs none of these fields at all.
