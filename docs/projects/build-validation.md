# Build Validation

RedKite validates a project before and after applying changes — it builds the project, and for Spring Boot projects, also starts it via `spring-boot:run`. Any extra Maven arguments or environment variables the project needs to build or start are entered once per project, on the project dashboard's **Build validation** panel, and reused for every apply — no restart of RedKite needed.

Two fields are available there:

- **Extra mvn arguments** — see [Maven Arguments](maven-arguments.md)
- **Extra environment variables** — see [Environment Variables](environment-variables.md)

Click **Save** after entering the project's configuration. It's stored per project (`projects.validation_maven_args` / `projects.validation_env` in the database) and applied to the next validation run.

For Spring Boot projects specifically, see [Spring Boot Projects](../getting-started/spring-boot-projects.md) for guidance on choosing or building a suitable validation profile. For what these settings actually get used for, see [Validation Process](../applying-changes/validation-process.md).
