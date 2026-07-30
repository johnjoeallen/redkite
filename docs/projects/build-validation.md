# Build Validation

RedKite validates a project before and after applying changes — it builds the project, and for Spring Boot projects, also starts it via `spring-boot:run`. Any extra Maven arguments, activated profile, environment variables, or Spring Boot-specific settings the project needs to build or start are declared once, in a file checked into the project itself: `.redkite/config.yml`.

```yaml
mavenArgs: -Dfoo=bar
profile: redkite
verify: false
env:
  DB_HOST: localhost
springBoot:
  profiles: redkite
```

None of the fields are required — an empty or missing file just means validation runs with nothing extra.

- **`mavenArgs`**, **`profile`**, and **`env`** apply to *every* validation RedKite runs — the plain build check, and, for a Spring Boot project, the `spring-boot:run` startup check too. See [Maven Arguments](maven-arguments.md) and [Environment Variables](environment-variables.md).
- **`springBoot.profiles`** applies *only* to the `spring-boot:run` startup check — it's kept in its own section rather than a flat field specifically because it's meaningless for the plain build check, and mixing it into settings that apply everywhere was confusing.
- **`verify`** switches validation from the default `mvn clean install -DskipTests` to `mvn clean verify` (unit tests included), and skips the Spring Boot startup check entirely — even if `spring-boot-maven-plugin` is present. Use this for a project where starting the app for real isn't practical, but its own test suite is still a meaningful gate to run before an apply is kept.

The project dashboard shows a read-only **Project configuration** panel with whatever `.redkite/config.yml` currently resolves to, so you can confirm RedKite is reading what you expect without leaving the UI. There's nothing to save from the UI itself — edit the file in your project and RedKite picks it up on the next validation run, no restart needed.

For Spring Boot projects specifically, see [Spring Boot Projects](../getting-started/spring-boot-projects.md) for guidance on choosing or building a suitable profile. For what these settings actually get used for, see [Validation Process](../applying-changes/validation-process.md).
