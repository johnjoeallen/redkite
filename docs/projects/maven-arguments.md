# Maven Arguments

**Extra mvn arguments** is a whitespace-separated list appended to every validation `mvn` call RedKite runs for this project — both the build check and, for Spring Boot projects, the `spring-boot:run` startup check.

To activate a Maven profile:

```text
-Predkite
```

To select a Spring Boot profile via a system property (a separate mechanism from a Maven profile — both can be needed at once):

```text
-Dspring-boot.run.profiles=redkite
```

Both combined:

```text
-Predkite -Dspring-boot.run.profiles=redkite
```

These are appended after any arguments RedKite generates itself for the startup check (such as the port it starts the application on), so they never conflict with RedKite's own flags unless you explicitly set the same property yourself.
