# Build Validation

RedKite validates a project before and after applying changes — by default, it builds the project, and for Spring Boot projects, also starts it via `spring-boot:run`. Any extra Maven arguments, activated profile, environment variables, validation mode, or Spring Boot-specific settings the project needs to build or start are declared once, in a file checked into the project itself: `.redkite/settings.yml` (`.redkite/settings.yaml` also works, and takes precedence if — unusually — both exist). It's real YAML, everything under `redkite.maven`:

```yaml
redkite:
  maven:
    mode: [run, test]
    fullLogs: false
    profile: redkite
    args:
      - "-Dfoo=bar"
    env:
      DB_HOST: localhost
    spring:
      profiles: redkite
```

Everything lives under a `redkite:` root — rather than `maven:` directly — leaving room for future, non-Maven config sections alongside it.

None of the fields are required — an empty or missing file just means validation runs with nothing extra, in the default mode. If a project has neither `.redkite/settings.yml` nor `.redkite/settings.yaml`, RedKite creates a `settings.yml` automatically the first time it scans the project: a fully commented-out template with every field shown but disabled, so it's discoverable and easy to edit without changing any validation behavior by its mere presence.

- **`args`**, **`profile`**, and **`env`** apply to *every* validation RedKite runs — the plain build check, and, for a Spring Boot project that reaches the `run` goal, the `spring-boot:run` startup check too. See [Maven Arguments](maven-arguments.md) and [Environment Variables](environment-variables.md).
- **`spring.profiles`** applies *only* to the `spring-boot:run` startup check — it's kept in its own section rather than a flat field specifically because it's meaningless for the plain build check, and mixing it into settings that apply everywhere was confusing.
- **`mode`** is a combination of `run`/`verify`/`test` — written as a single value (`mode: run`) or a list (`mode: [run, test]`). Two things fall out of the combination:
    1. **Which Maven goal runs, and whether a startup check is ever attempted** — the deepest phase present wins, since each one's underlying Maven lifecycle already contains the shallower ones:

        | Present | Goal | Startup check |
        |---|---|---|
        | `run` | `mvn clean install` | Yes, for a Spring Boot project |
        | `verify` (no `run`) | `mvn clean verify` (plus anything else bound to that phase, e.g. integration tests via failsafe) | Never |
        | `test` only | `mvn clean test` (no packaging) | Never |

    2. **Whether `-DskipTests` is added** — this is decided purely by whether `test` appears anywhere in the combination, independent of which goal above was picked:

        | `mode:` | Effective command |
        |---|---|
        | `run` (default) | `mvn clean install -DskipTests` — today's existing default |
        | `[run, test]` | `mvn clean install` |
        | `verify` | `mvn clean verify -DskipTests` |
        | `[verify, test]` | `mvn clean verify` — traditional "verify with tests" behavior |
        | `test` | `mvn clean test` (tests always run — `test` is what selected this goal) |

    Use `verify` or `test` for a project where starting the app for real isn't practical, but its own tests are still a meaningful gate to run before an apply is kept.

- **`fullLogs`** (default `false`) applies to every validation `mvn` call regardless of mode. RedKite normally runs with `--no-transfer-progress`, which suppresses per-artifact dependency download/upload logging — set this to `true` to include it in the raw build output, useful when a failure looks repository- or network-related rather than a genuine build error.

The project dashboard shows a read-only **Project configuration** panel with whatever `.redkite/settings.yml`/`.yaml` currently resolves to, so you can confirm RedKite is reading what you expect without leaving the UI. There's nothing to save from the UI itself — edit the file in your project and RedKite picks it up on the next validation run, no restart needed.

For Spring Boot projects specifically, see [Spring Boot Projects](../getting-started/spring-boot-projects.md) for guidance on choosing or building a suitable profile. For what these settings actually get used for, see [Validation Process](../applying-changes/validation-process.md).
