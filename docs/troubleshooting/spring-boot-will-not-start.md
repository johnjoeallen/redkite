# Spring Boot Will Not Start

For a project whose root POM references `spring-boot-maven-plugin`, RedKite's validation goes further than a plain build — it also runs `spring-boot:run` and waits for a "Started ... in N seconds" line in the output, confirming the application actually came up. See [Build Validation](../projects/build-validation.md) for the full mechanism.

## The most common cause: missing profile arguments

RedKite launches the app with a randomized free port (specifically so it never collides with anything else, including another instance of the same app), plus whatever Maven arguments and environment variables you've configured for the project. If your application needs a specific Spring profile active — to point it at an embedded/test database, disable something that needs real infrastructure, or supply a required property — and that profile isn't included in your configured arguments, the app is likely to exit immediately or hang without ever printing its "Started" line.

This looks identical, from RedKite's side, to the app simply taking too long to start (validation waits up to 180 seconds) — both are reported as a startup failure with no crash-specific detail beyond the captured output.

**Fix**: add the profile activation to the project's [Maven arguments](../projects/maven-arguments.md), for example:

```
-Dspring-boot.run.profiles=redkite
```

and any environment variables the profile depends on under [Environment Variables](../projects/environment-variables.md). See [Spring Boot Projects](../getting-started/spring-boot-projects.md) for a worked example.

## Read the captured output

The failure signature and raw output captured before the process was killed are shown the same way as a build failure — look for the actual exception or `[ERROR]` line your application printed before it gave up.

## If a previous run's process didn't fully die

RedKite force-kills the validation process tree on failure or timeout. If a child process survives that for more than a few seconds, a warning is logged that it may still be holding its port — worth knowing if a *subsequent* validation run behaves strangely for no obvious reason.
