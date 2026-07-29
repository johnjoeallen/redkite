# Environment Variables

**Extra environment variables** is a comma-separated list of `KEY=VALUE` pairs set on the Maven processes RedKite spawns to validate this project — both the build check and, for Spring Boot projects, the `spring-boot:run` startup check.

```text
SPRING_PROFILES_ACTIVE=redkite,DB_HOST=localhost
```

Use this for anything the application reads from the environment rather than a system property or Maven profile — for example, activating a Spring profile the traditional way, or pointing a validation profile at a local service on a non-default host or port.
