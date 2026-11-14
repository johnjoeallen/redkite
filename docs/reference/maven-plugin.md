# Maven Plugin

The `red-kite-maven-plugin` runs the same analysis as the RedKite server from the command line, without the server. It prints a text report to the build log and writes no report files by default. It is run by hand when you want it; nothing runs unless you invoke it or bind it in your POM.

It reuses RedKite's own scanner, Maven Central and OSV.dev providers and an H2 database. By default the cache is **disabled**: each build uses a throwaway in-memory database, queries Maven Central and OSV.dev afresh, and leaves nothing on disk. Pass `-Dredkite.cache=true` to keep a persistent database at `~/.redkite/plugin/redkite`, shared by all projects so lookups are cached between builds. That database is separate from the server's database, so the plugin and server can run at the same time, and parallel builds share it through H2's `AUTO_SERVER` mode. Use `-Dredkite.db.url=...` (with the cache enabled) to put it elsewhere.

## Goals

| Goal | Default phase | Purpose |
| --- | --- | --- |
| `redkite:report` | none | Analyse and print the report. Never fails the build. |
| `redkite:check` | `verify` | Print the report, then fail the build for vulnerabilities a developer can fix. |

Both goals are aggregators: they run once, at the execution root, and analyse every module beneath it.

## Enable it in a project

This section is a runbook, written so that a person or a coding agent can follow it step by step. The plugin needs **no change to the target project's POM** to run. Adding it to the POM is optional (step 4).

**Facts to rely on**

- The plugin is **not on Maven Central**. It has to be installed into the local Maven repository (`~/.m2`) from a RedKite checkout first.
- Plugin coordinates: `net.dublinux.redkite:red-kite-maven-plugin`. Goals: `report` and `check`. Short prefix: `redkite`.
- It never edits POMs or any project file. By default it writes nothing to disk. It reads the project, queries Maven Central and OSV.dev, and prints to the build log.
- It runs `mvn dependency:tree` as a child process, so it needs `mvn` on `PATH`, Java 17+, Maven 3.9+ and network access.

**1. Install the plugin (once per machine, repeat to update).** From a RedKite checkout:

```bash
git clone https://github.com/johnjoeallen/redkite.git     # skip if you already have a checkout
cd redkite
mvn install -DskipTests -pl red-kite-maven-plugin -am
```

`-am` also builds the modules the plugin depends on. Success ends with `BUILD SUCCESS`. The installed version is the `<version>` in `red-kite-maven-plugin/pom.xml` (currently `0.1.0-SNAPSHOT`). It is also the directory name under `~/.m2/repository/net/dublinux/redkite/red-kite-maven-plugin/`.

**2. Make the short `redkite:` prefix work (once per machine).** Add this to `~/.m2/settings.xml`. Create the file if it is missing, and add the `<pluginGroup>` line inside an existing `<pluginGroups>` element if there is one:

```xml
<settings>
  <pluginGroups>
    <pluginGroup>net.dublinux.redkite</pluginGroup>
  </pluginGroups>
</settings>
```

If you can't or don't want to change `settings.xml`, skip this step and use the full form `mvn net.dublinux.redkite:red-kite-maven-plugin:0.1.0-SNAPSHOT:report` wherever the commands below say `mvn redkite:report`.

**3. Run it in the target project.** From the directory holding the root `pom.xml`, with no edits to that project:

```bash
mvn -B redkite:report     # print the report; never fails the build
mvn -B redkite:check      # print the report; fail the build for fixable vulnerabilities
```

`-B` (batch mode) gives plain log lines, which suits agents and CI. Without it, an interactive terminal shows a live spinner instead. To run the check after a normal build: `mvn -B verify redkite:check`.

**4. (Optional) Run it as part of the project's own build.** Add an opt-in profile to the project's **root `pom.xml`**. It has to be in the POM because profiles in `settings.xml` cannot bind plugins:

```xml
<profile>
  <id>redkite</id>
  <build>
    <plugins>
      <plugin>
        <groupId>net.dublinux.redkite</groupId>
        <artifactId>red-kite-maven-plugin</artifactId>
        <version>0.1.0-SNAPSHOT</version>
        <executions>
          <execution>
            <goals><goal>check</goal></goals>
            <configuration>
              <failOnSeverity>HIGH</failOnSeverity>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</profile>
```

Run it with `mvn -B verify -Predkite`. Because the plugin is only in the local repository, anyone building with that profile, including CI, has to install it first (step 1), so keep the profile opt-in. `check` binds to `verify` by default.

**5. Verify it works.** A successful run prints `RedKite analysing <path> (cache disabled)`, a `RedKite report` block with counts, then `BUILD SUCCESS`. For `check`, a failing exit code (Maven exits `1`) with `[ERROR] RedKite: …` lines means it found something to fix. That is the plugin working, not a failure to run.

Common setup problems:

| Symptom | Cause and fix |
| --- | --- |
| `No plugin found for prefix 'redkite'` | Step 2 not done, or the plugin isn't installed. Use the full coordinates, or redo steps 1 and 2. |
| `Could not find artifact net.dublinux.redkite:red-kite-maven-plugin:…` | Step 1 not done on this machine, or the version in the command doesn't match the installed one. |
| `RedKite analysis failed: … dependency:tree failed` | The project doesn't build on its own (missing parent POM, unreachable repository). Fix that first, then re-run. |
| H2 `EOFException` or `Timeout trying to lock table` | Only with `-Dredkite.cache=true`. Delete `~/.redkite/plugin/` and re-run. |

## Usage

```bash
mvn -B redkite:report                                   # report only, never fails the build
mvn -B redkite:check                                    # fails on fixable HIGH or worse (the default)
mvn -B redkite:check -Dredkite.failOnSeverity=CRITICAL  # stricter or looser threshold
mvn -B redkite:check -Dredkite.failOnSnapshot=true      # also fail on SNAPSHOT dependencies
mvn -B redkite:report -Dredkite.enforcer=true           # include dependency-convergence analysis (slower)
mvn -B redkite:report -Dredkite.jsonReport=true         # also write target/redkite/redkite-report.json
```

## Reading the output and acting on it

The report is plain text, one line per finding:

```
RedKite report
==============
Components:      254 (64 direct, 190 transitive)
Analysis:        complete
Vulnerabilities: 10 (2 critical, 6 high, 2 medium)
Recommendations: 81

Vulnerabilities
---------------
  CRITICAL  org.springframework:spring-webmvc:6.2.19  GHSA-j9f9-w8pj-32f8 (CVE-2026-47890)  no fixed version known
  HIGH      com.fasterxml.jackson.core:jackson-core:2.22.2  GHSA-7hhh-6rmp-j9qf (CVE-2026-89425)  fixed in 2.22.3

Recommended upgrades
--------------------
  com.fasterxml.jackson.core:jackson-core   2.22.2 -> 2.22.3  [CVE_FIX, PATCH risk]
```

To act on a `check` failure, change the dependency's version in the project's POM (or the property that holds it) to the version named in the message, rebuild and test it yourself, then re-run `redkite:check`. The plugin does not apply changes. A `[WARNING]` from `check` means there is nothing fixable on the same major line, so no version change will clear it; it doesn't fail the build.

## When `check` fails the build

`check` only fails for problems you can do something about, so it is safe to leave bound to every build. A dependency with a vulnerability at or above `failOnSeverity` fails the build when another version **on the same major line** (newer or older) has nothing at or above that severity. The message names the version to move to:

```
[ERROR] RedKite: com.fasterxml.jackson.core:jackson-core:2.22.2 has High vulnerabilities (GHSA-7hhh-6rmp-j9qf); upgrade to 2.22.3 leaves nothing at or above High
```

If no such version exists, for example because the vulnerability has no fix yet, the finding is logged as a warning and the build passes:

```
[WARNING] RedKite: org.springframework:spring-webmvc:6.2.19 has Critical vulnerabilities (...); no version on the same major line is below High, so this does not fail the build
```

Candidate versions come from RedKite's CVE search (a bounded window of nearby versions, up to six each side of the current version plus the latest release, each verified against OSV.dev), so a fixable finding the search doesn't reach is reported as a warning rather than failing.

## Output

- **Build log:** a plain-text report (counts, vulnerabilities worst first with fixed versions, SNAPSHOT dependencies, recommended upgrades) is printed unless `consoleReport` is `false`. Nothing else is written for text.
- **`target/redkite/redkite-report.json`** (only with `jsonReport`): components, vulnerabilities and recommendations for CI tooling.

## Parameters

| Parameter | Property | Default | Goals | Description |
| --- | --- | --- | --- | --- |
| `skip` | `redkite.skip` | `false` | both | Skip the plugin. |
| `jsonReport` | `redkite.jsonReport` | `false` | both | Also write a JSON copy of the report. No files are written by default. |
| `outputDirectory` | `redkite.outputDirectory` | `${project.build.directory}/redkite` | both | Where the JSON report is written when `jsonReport` is true. |
| `cache` | `redkite.cache` | `false` | both | Keep a persistent lookup cache between builds. When false, an in-memory database is used and nothing is written to disk. |
| `showProgress` | `redkite.progress` | `true` | both | Show progress while analysing: a live status line (spinner, current step, elapsed time) on an interactive terminal, one log line per step when output is piped, in batch mode (`-B`), on CI or with `-X`. |
| `databaseUrl` | `redkite.db.url` | `~/.redkite/plugin/redkite` (H2, `AUTO_SERVER`) | both | H2 database for the cache and scan history; used only when `cache` is true. |
| `consoleReport` | `redkite.consoleReport` | `true` | both | Print the text report to the build log. |
| `enforcer` | `redkite.enforcer` | `false` | both | Also run the dependency-convergence analysis (several extra Maven runs). |
| `allowMajorUpgrades` | `redkite.allowMajorUpgrades` | `false` | both | Allow major-version upgrade recommendations. |
| `failOnSeverity` | `redkite.failOnSeverity` | `HIGH` | `check` | Severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) at or above which a fixable vulnerability fails the build; `NONE` disables. |
| `failOnSnapshot` | `redkite.failOnSnapshot` | `false` | `check` | Fail on SNAPSHOT dependencies. |
| `failOnIncomplete` | `redkite.failOnIncomplete` | `false` | `check` | Fail when metadata could not be fetched. |

## Notes

- The scan runs `mvn dependency:tree` as a child process, so `mvn` must be on `PATH`, as for the server.
- The plugin only reads the project. It never edits POMs; applying upgrades remains a server feature.
- Run with `-X` to see RedKite's per-component logging.
- If a run fails with an H2 error such as `EOFException` or `Timeout trying to lock table`, the plugin's persistent cache database (`redkite.cache=true`) is damaged. It holds only cached lookups, so delete `~/.redkite/plugin/` and re-run.
