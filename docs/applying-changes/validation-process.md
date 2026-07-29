# Validation Process

RedKite runs a bracketed validation sequence around every apply, using the Maven arguments and environment variables configured in [Build Validation](../projects/build-validation.md) for both passes:

1. **Pre-validate** — builds the project in its current state (`mvn clean install -DskipTests`, plus the Spring Boot startup check via `spring-boot:run` if `spring-boot-maven-plugin` is present). This step is informational, not a gate — a project that's already broken before any change is still a valid starting point, and RedKite records whether the baseline passed so a later failure can be attributed correctly.
2. **Write** — the selected POM changes are written to disk.
3. **Post-validate** — the same build (and startup, where applicable) check runs again against the updated project. This is the authoritative gate.
4. **Keep or revert** — if post-validate passes, the changes stay. If it fails, RedKite reverts every POM file it touched — see [Rollback](rollback.md).

A progress overlay shows which phase is currently running. If post-apply validation fails, RedKite attempts to attribute the failure to a specific dependency (by matching common Maven resolution-error patterns in the build output) and reports it — but only when the baseline (pre-validate) build actually passed; a failure on a project that was already broken isn't blamed on the change that was just applied.
