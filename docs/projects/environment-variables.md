# Environment Variables

The `env` section of `.redkite/config.yml` is a set of `KEY: value` pairs set on the processes RedKite spawns to validate this project — both the build check and, for Spring Boot projects, the `spring-boot:run` startup check.

```yaml
env:
  SPRING_PROFILES_ACTIVE: redkite
  DB_HOST: localhost
```

Use this for anything the application reads from the environment rather than a system property or Maven profile — for example, activating a Spring profile the traditional way, or pointing a validation profile at a local service on a non-default host or port. A value containing a colon (a JDBC URL, say) is read correctly — only the *first* colon on the line separates the key from the value.
