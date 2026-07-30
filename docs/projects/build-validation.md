# Build Validation

RedKite validates a project before and after applying changes — by default, it builds the project, and for Spring Boot projects, also starts it via `spring-boot:run`. Any extra Maven arguments, activated profile, environment variables, validation mode, or Spring Boot-specific settings the project needs to build or start are declared once, in a file checked into the project itself: `.redkite/config.yml`.

```yaml
mavenArgs: -Dfoo=bar
profile: redkite
mode: run
env:
  DB_HOST: localhost
springBoot:
  profiles: redkite
```

None of the fields are required — an empty or missing file just means validation runs with nothing extra, in the default mode.

- **`mavenArgs`**, **`profile`**, and **`env`** apply to *every* validation RedKite runs — the plain build check, and, for a Spring Boot project in `mode: run`, the `spring-boot:run` startup check too. See [Maven Arguments](maven-arguments.md) and [Environment Variables](environment-variables.md).
- **`springBoot.profiles`** applies *only* to the `spring-boot:run` startup check — it's kept in its own section rather than a flat field specifically because it's meaningless for the plain build check, and mixing it into settings that apply everywhere was confusing.
- **`mode`** picks which Maven lifecycle phase validation runs, and whether a startup check is ever attempted at all:

| Mode | Command | Startup check |
|---|---|---|
| `run` (default) | `mvn clean install -DskipTests` | Yes, for a Spring Boot project |
| `verify` | `mvn clean verify` (tests included, plus anything else bound to the `verify` phase, e.g. integration tests via failsafe) | Never |
| `test` | `mvn clean test` (unit tests only, no packaging) | Never |

Use `verify` or `test` for a project where starting the app for real isn't practical, but its own tests are still a meaningful gate to run before an apply is kept — `test` is the lighter check of the two, `verify` the more thorough one.

The project dashboard shows a read-only **Project configuration** panel with whatever `.redkite/config.yml` currently resolves to, so you can confirm RedKite is reading what you expect without leaving the UI. There's nothing to save from the UI itself — edit the file in your project and RedKite picks it up on the next validation run, no restart needed.

For Spring Boot projects specifically, see [Spring Boot Projects](../getting-started/spring-boot-projects.md) for guidance on choosing or building a suitable profile. For what these settings actually get used for, see [Validation Process](../applying-changes/validation-process.md).
