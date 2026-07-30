# Spring Boot Projects

For RedKite to apply changes successfully to a Spring Boot project, the application must be able to build and start directly through Maven using the configuration declared in the project's own [`.redkite/config.yml`](../projects/build-validation.md).

The configured profile doesn't have to be named `local` — any suitable profile works, such as `dev`, `test`, `desktop`, or a profile created specifically for this purpose, e.g. `redkite`. A dedicated `redkite` profile can be designed specifically for dependency validation, and should require as little external infrastructure as practical. A suitable profile might:

- use embedded databases
- connect to lightweight local services
- disable optional external integrations
- replace remote systems with local alternatives
- use safe development credentials
- avoid production-only infrastructure

The goal isn't to reproduce the full production environment — the application only needs to start reliably enough for RedKite to verify that dependency changes haven't broken it. Docker shouldn't be required for this: RedKite starts the project directly through Maven, so any services it needs should either be available locally, or disabled/replaced by the selected profile.

For example, a Maven profile and a Spring Boot profile used together, declared in `.redkite/config.yml`:

```yaml
redkite:
  maven:
    profile: redkite
    spring:
      profiles: redkite
```

`profile` applies to every validation call; `spring.profiles` applies only to the startup check. RedKite uses this to run the equivalent of:

```bash
mvn clean install -DskipTests -Predkite
mvn spring-boot:run \
  -Predkite \
  -Dspring-boot.run.profiles=redkite
```

!!! tip
    Before applying changes to a Spring Boot project for the first time, verify the configured commands work outside RedKite — run the build (`mvn clean install -DskipTests -Predkite`) and the startup check (`mvn spring-boot:run -Predkite -Dspring-boot.run.profiles=redkite`) yourself first. Once both succeed on their own, RedKite can use the same configuration to validate dependency updates and conflict resolutions.

RedKite only runs this startup check when it detects `spring-boot-maven-plugin` in the project's root POM, and `mode` is `run` (the default) — a plain (non-Spring-Boot) project, or one with `mode: verify`/`mode: test`, only ever gets the build check. See [Validation Process](../applying-changes/validation-process.md) for the full sequence.
