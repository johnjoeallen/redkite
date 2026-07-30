# Build Validation

RedKite validates a project before and after applying changes — it builds the project, and for Spring Boot projects, also starts it via `spring-boot:run`. Any extra Maven arguments, activated profile, Spring profile, or environment variables the project needs to build or start are declared once, in a file checked into the project itself: `.redkite/project.cfg`.

```yaml
mavenArgs: -Dfoo=bar
profile: redkite
springProfiles: redkite
env:
  DB_HOST: localhost
```

None of the fields are required — an empty or missing file just means validation runs with nothing extra. See:

- [Maven Arguments](maven-arguments.md) — `mavenArgs`/`profile`/`springProfiles`
- [Environment Variables](environment-variables.md) — `env`

The project dashboard shows a read-only **Project configuration** panel with whatever `.redkite/project.cfg` currently resolves to, so you can confirm RedKite is reading what you expect without leaving the UI. There's nothing to save from the UI itself — edit the file in your project and RedKite picks it up on the next validation run, no restart needed.

For Spring Boot projects specifically, see [Spring Boot Projects](../getting-started/spring-boot-projects.md) for guidance on choosing or building a suitable profile. For what these settings actually get used for, see [Validation Process](../applying-changes/validation-process.md).
