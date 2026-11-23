# Maven Plugin

The `red-kite-maven-plugin` runs the same analysis as the RedKite server from the command line, without the server. It prints a text report to the build log and writes no report files by default. It is run by hand when you want it; nothing runs unless you invoke it or bind it in your POM.

It reuses RedKite's own scanner, Maven Central and OSV.dev providers and an H2 database. By default the cache is **disabled**: each build uses a throwaway in-memory database, queries Maven Central and OSV.dev afresh, and leaves nothing on disk. Pass `-Dredkite.cache=true` to keep a persistent database at `~/.redkite/plugin/redkite`, shared by all projects so lookups are cached between builds. That database is separate from the server's database, so the plugin and server can run at the same time, and parallel builds share it through H2's `AUTO_SERVER` mode. Use `-Dredkite.db.url=...` (with the cache enabled) to put it elsewhere.

## Goals

| Goal | Default phase | Purpose |
| --- | --- | --- |
| `redkite:report` | none | Analyse and print the report. Never fails the build. |
| `redkite:check` | `verify` | Print the report, then fail the build for vulnerabilities a developer can fix. |
| `redkite:upgrade` | none | Edit the POMs: upgrade exactly the dependencies you name (`-Dredkite.upgrades`). |
| `redkite:upgrade-all` | none | Edit the POMs: apply the CVE fixes and recommended upgrades RedKite chooses. |
| `redkite:upgrade-cve` | none | Edit the POMs: upgrade only to fix vulnerabilities. |
| `redkite:drop` | none | Remove RedKite pins (`-Dredkite.pins`). Runs no analysis. |
| `redkite:unpin` | none | Keep a pinned version but release the pin (`-Dredkite.pins`). Runs no analysis. |

All goals are aggregators: they run once, at the execution root, and analyse every module beneath it.

## Enable it in a project

This section is a runbook, written so that a person or a coding agent can follow it step by step. The plugin needs **no change to the target project's POM** to run. Adding it to the POM is optional (step 4).

**Facts to rely on**

- The plugin is published on Maven Central, so Maven downloads it on first use. There is nothing to install by hand.
- Plugin coordinates: `net.dublinux.redkite:red-kite-maven-plugin`. Goals: `report` and `check`. Short prefix: `redkite`.
- It never edits POMs or any project file. By default it writes nothing to disk. It reads the project, queries Maven Central and OSV.dev, and prints to the build log.
- It runs `mvn dependency:tree` as a child process, so it needs `mvn` on `PATH`, Java 25+ (0.99.206 and earlier: Java 17+), Maven 3.9+ and network access.

**1. Pick the version.** Use the latest release of `net.dublinux.redkite:red-kite-maven-plugin` on [Maven Central](https://central.sonatype.com/artifact/net.dublinux.redkite/red-kite-maven-plugin). This page uses `0.99.207`. Maven downloads it the first time you run it.

**2. (Optional) Make the short `redkite:` prefix work (once per machine).** Add this to `~/.m2/settings.xml`. Create the file if it is missing, and add the `<pluginGroup>` line inside an existing `<pluginGroups>` element if there is one:

```xml
<settings>
  <pluginGroups>
    <pluginGroup>net.dublinux.redkite</pluginGroup>
  </pluginGroups>
</settings>
```

If you can't or don't want to change `settings.xml`, skip this step and use the full form `mvn net.dublinux.redkite:red-kite-maven-plugin:0.99.207:report` (and `…:check`) wherever the commands below say `mvn redkite:report`.

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
        <version>0.99.207</version>
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

Run it with `mvn -B verify -Predkite`. The plugin downloads from Maven Central like any other, so CI needs no extra setup. `check` binds to `verify` by default. Keep the profile opt-in so ordinary builds don't make network calls to Maven Central and OSV.dev.

**5. Verify it works.** A successful run prints `RedKite analysing <path> (cache disabled)`, a `RedKite report` block with counts, then `BUILD SUCCESS`. For `check`, a failing exit code (Maven exits `1`) with `[ERROR] RedKite: …` lines means it found something to fix. That is the plugin working, not a failure to run.

Common setup problems:

| Symptom | Cause and fix |
| --- | --- |
| `No plugin found for prefix 'redkite'` | The `<pluginGroup>` entry (step 2) is missing. Add it, or use the full coordinates. |
| `Could not find artifact net.dublinux.redkite:red-kite-maven-plugin:…` | The version doesn't exist on Maven Central (check the spelling and the version), or the machine can't reach Maven Central. |
| `RedKite analysis failed: … dependency:tree failed` | The project doesn't build on its own (missing parent POM, unreachable repository). Fix that first, then re-run. |
| H2 `EOFException` or `Timeout trying to lock table` | Only with `-Dredkite.cache=true`. Delete `~/.redkite/plugin/` and re-run. |

## Cache on for local builds only

The cache is off by default, so CI needs no change. To enable it only on your own machine, set an environment variable, for example in `~/.bashrc`:

```bash
export RK_CACHE=true
```

No POM or `settings.xml` change is needed. The cache is on when `RK_CACHE` is `true` and off otherwise, so CI, where the variable is unset, keeps it off. An explicit `-Dredkite.cache=true|false` or `<cache>` configuration always takes precedence over the variable. To confirm it is in effect, look for `(cache jdbc:h2:...)` rather than `(cache disabled)` in the `RedKite analysing` log line.

## Upgrading and pinning

These goals are the command-line version of the server's "Apply selected". Run `redkite:report` first to see what is recommended. None of them runs a build afterwards, so review the diff and run your build to validate it. All of them accept `-Dredkite.dryRun=true`, which shows what would change and writes nothing.

| Goal | Upgrades |
| --- | --- |
| `redkite:upgrade` | exactly what you name with `-Dredkite.upgrades=groupId:artifactId[:version],...` (required) |
| `redkite:upgrade-all` | the CVE fixes and recommended upgrades RedKite chooses |
| `redkite:upgrade-cve` | only the version that fixes a vulnerability |

```bash
# exactly these: an explicit version, or leave it off for RedKite's recommended one
mvn -B redkite:upgrade -Dredkite.upgrades=com.fasterxml.jackson.core:jackson-databind:2.22.3
mvn -B redkite:upgrade -Dredkite.upgrades=org.apache.tomcat.embed:tomcat-embed-core,com.rabbitmq:amqp-client

# let RedKite choose
mvn -B redkite:upgrade-cve
mvn -B redkite:upgrade-all -Dredkite.dryRun=true
```

**How a dependency is changed.** A *direct* dependency is upgraded where it is declared, with the same POM patching as the server: a version that is already a property has the property updated, a literal version is moved into a property, and a BOM-managed dependency gets an explicit version. A *transitive* dependency has no declaration of its own, so it is **pinned**: a `<dependencyManagement>` entry with the version goes into the root POM and forces that version for every module.

**What `upgrade-all` and `upgrade-cve` choose.**

- `upgrade-cve` takes only the same-fix recommendations: the version that fixes the vulnerability. Best-effort fixes (which leave some vulnerability behind) and downgrades are not applied.
- `upgrade-all` also takes best-effort fixes and newer versions of **direct** dependencies. A transitive dependency is only changed for a vulnerability. Downgrades and SNAPSHOT replacements are never done in bulk. Whether major-version upgrades are considered follows `redkite.allowMajorUpgrades`.
- A transitive fix from these goals is a normal RedKite pin, which later runs may move. A pin you create with `redkite:upgrade` is a **user pin**.
- If different modules are recommended different versions of the same dependency, it is left alone and listed, so you can name one with `redkite:upgrade`.

**Pinned dependencies.** A dependency with a user pin is never changed by `upgrade-all` or `upgrade-cve`, even to fix a vulnerability. It is listed with a warning instead. Only `redkite:upgrade` with the dependency named explicitly changes it, and it stays pinned at the new version.

**Removing pins.** Both goals take `-Dredkite.pins=groupId:artifactId,...`, read only the POMs, and so run in seconds.

```bash
mvn -B redkite:unpin -Dredkite.pins=com.rabbitmq:amqp-client   # keep the version, release the protection
mvn -B redkite:drop  -Dredkite.pins=com.rabbitmq:amqp-client   # remove the pin entry altogether
```

- `unpin` leaves the version where it is and removes the `redkite:user-pin` marker, so the bulk goals may move it again. The entry becomes an ordinary `<dependencyManagement>` entry, so a later `drop` will find no RedKite pin; remove such an entry by hand.
- `drop` removes the marked `<dependencyManagement>` entry (and the block around it, if that leaves it empty), so the dependency is no longer forced to a version. It does not restore the earlier version; upgrade the dependency afterwards if you want that.
- Naming something with no pin is reported as skipped and the goal fails.

The `redkite:pin-summary` comment at the top of each POM is refreshed after every change, as the server does. A missing or malformed argument fails immediately, before any analysis, and naming something that isn't a dependency of the project is reported as skipped and fails the goal.

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

The report is plain text. Each vulnerable dependency is listed once, with its advisories, where it comes from and whether it is pinned:

```
RedKite report
==============
Components:      118 (43 direct, 75 transitive)
Analysis:        complete
Vulnerabilities: 4 (2 critical, 2 high)
Recommendations: 20

Vulnerabilities
---------------
  CRITICAL  org.springframework:spring-webmvc:6.2.19  [pinned by RedKite]
      GHSA-j9f9-w8pj-32f8 (CVE-2026-47890)  no fixed version known
      GHSA-pc63-qcmh-9cmg (CVE-2026-47884)  no fixed version known
      declared in pom.xml

  HIGH      com.fasterxml.jackson.core:jackson-core:2.22.2
      GHSA-7hhh-6rmp-j9qf (CVE-2026-89425)  fixed in 2.22.3
      GHSA-p6pp-m3f8-5c89 (CVE-2026-89407)  fixed in 2.22.3
      declared in test/projects/convergence-fixture/old-wrapper/pom.xml  (not in the build)
      The upgrade goals cannot edit POMs outside the build; exclude them or fix them by hand.

Recommended upgrades
--------------------
  com.fasterxml.jackson.core:jackson-core   2.22.2 -> 2.22.3  [CVE_FIX, PATCH risk]
```

Under each dependency:

- **Advisories:** one line each, with its fix, or `no fixed version known`.
- **Where it comes from:** `declared in <pom>` for a direct dependency, or `via <module pom>` for a transitive one. Up to five locations are listed, then `+N more`.
- **`[pinned by user]` / `[pinned by RedKite]`:** the dependency is held by a `redkite:user-pin` marker or a RedKite-managed `dependencyManagement` pin.
- **`(not in the build)`:** the declaring POM is outside the Maven build, so the upgrade goals cannot edit it. See [Excluding folders](#excluding-folders).

To act on a `check` failure, change the dependency's version in the project's POM (or the property that holds it) to the version named in the message, rebuild and test it yourself, then re-run `redkite:check`. You can have the plugin make that change with `redkite:upgrade-cve` (or `redkite:upgrade` for one dependency). A `[WARNING]` from `check` means there is nothing fixable on the same major line, so no version change will clear it; it doesn't fail the build.

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

## Excluding folders

RedKite analyses every `pom.xml` under the project root. To leave out folders that are not part of the build, such as test fixtures or samples, list them in the `excludes` parameter in the root POM, or pass `-Dredkite.excludes=dir1,dir2` for one run:

```xml
<configuration>
  <excludes>
    <exclude>test/projects</exclude>
  </excludes>
</configuration>
```

Entries are directories relative to the project root and exclude everything below them. The setting applies to the report, `check`, the upgrade goals, the enforcer analysis and the pin search, and the RedKite server reads it from the same place. See [Excluding Folders](../configuration/excluding-folders.md) for the details.

## Output

- **Build log:** a plain-text report (counts, vulnerabilities worst first with fixed versions, SNAPSHOT dependencies, recommended upgrades) is printed unless `consoleReport` is `false`. Nothing else is written for text.
- **`target/redkite/redkite-report.json`** (only with `jsonReport`): components, vulnerabilities and recommendations for CI tooling.

## Parameters

Set any of these on the command line with `-D<property>=<value>`, or in the POM:

```xml
<plugin>
  <groupId>net.dublinux.redkite</groupId>
  <artifactId>red-kite-maven-plugin</artifactId>
  <version>0.99.207</version>
  <configuration>
    <failOnSeverity>CRITICAL</failOnSeverity>
    <allowMajorUpgrades>false</allowMajorUpgrades>
  </configuration>
</plugin>
```

The *Parameter* column is the `<configuration>` element name and the *Property* column is the `-D` name.

| Parameter | Property | Default | Goals | Description |
| --- | --- | --- | --- | --- |
| `skip` | `redkite.skip` | `false` | both | Skip the plugin. |
| `excludes` | `redkite.excludes` | none | all | Directories, relative to the project root, whose POMs are not analysed (for example test fixtures). On the command line, comma-separated; in the POM, `<excludes><exclude>test/projects</exclude></excludes>`. |
| `jsonReport` | `redkite.jsonReport` | `false` | both | Also write a JSON copy of the report. No files are written by default. |
| `outputDirectory` | `redkite.outputDirectory` | `${project.build.directory}/redkite` | both | Where the JSON report is written when `jsonReport` is true. |
| `cache` | `redkite.cache` | `false`; `true` if env `RK_CACHE=true` | both | Keep a persistent lookup cache between builds. When false, an in-memory database is used and nothing is written to disk. |
| `showProgress` | `redkite.progress` | `true` | both | Show progress while analysing: a live status line (spinner, current step, elapsed time) on an interactive terminal, one log line per step when output is piped, in batch mode (`-B`), on CI or with `-X`. |
| `databaseUrl` | `redkite.db.url` | `jdbc:h2:${user.home}/.redkite/plugin/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;AUTO_SERVER=TRUE` | both | H2 database for the cache and scan history; used only when `cache` is true. |
| `showTransitives` | `redkite.showTransitives` | `false` | `report` | Also list plain "newer version exists" updates for transitive dependencies, in a separate "Transitive-only updates" section. Off by default, matching the server's Outdated count: nothing in the project forces them to move. Direct dependencies and vulnerability fixes are always listed. `check` ignores it. |
| `consoleReport` | `redkite.consoleReport` | `true` | both | Print the text report to the build log. |
| `enforcer` | `redkite.enforcer` | `false` | both | Also run the dependency-convergence analysis (several extra Maven runs). |
| `allowMajorUpgrades` | `redkite.allowMajorUpgrades` | `false` | both | Allow major-version upgrade recommendations. |
| `failOnSeverity` | `redkite.failOnSeverity` | `HIGH` | `check` | Severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) at or above which a fixable vulnerability fails the build; `NONE` disables. |
| `failOnSnapshot` | `redkite.failOnSnapshot` | `false` | `check` | Fail on SNAPSHOT dependencies. |
| `failOnIncomplete` | `redkite.failOnIncomplete` | `false` | `check` | Fail when metadata could not be fetched. |
| `upgrades` | `redkite.upgrades` | none | `upgrade` | Dependencies to upgrade: comma-separated `groupId:artifactId[:version]`; no version means the recommended one. A transitive dependency is pinned. Required. |
| `pins` | `redkite.pins` | none | `drop`, `unpin` | Pins to remove: comma-separated `groupId:artifactId`. Required. |
| `dryRun` | `redkite.dryRun` | `false` | `upgrade`, `upgrade-all`, `upgrade-cve`, `drop`, `unpin` | Show what would change and write nothing. |

## Notes

- Dependencies pinned with a `redkite:user-pin` marker in any project POM (the pins the server writes) get no plain "newer version exists" recommendation, as in the server; vulnerability fixes are still listed. Their available upgrades are shown for information in a separate "Pinned dependencies with upgrades available" section of the report.
- The scan runs `mvn dependency:tree` as a child process, so `mvn` must be on `PATH`, as for the server.
- `report` and `check` only read the project. Only the `upgrade`, `upgrade-all`, `upgrade-cve`, `drop` and `unpin` goals edit POMs, and only when you run them.
- Run with `-X` to see RedKite's per-component logging.
- If a run fails with an H2 error such as `EOFException` or `Timeout trying to lock table`, the plugin's persistent cache database (`redkite.cache=true`) is damaged. It holds only cached lookups, so delete `~/.redkite/plugin/` and re-run.

## Building from source

To run a build of the plugin from a RedKite checkout instead of the release on Central:

```bash
git clone https://github.com/johnjoeallen/redkite.git
cd redkite
mvn install -DskipTests -pl red-kite-maven-plugin -am
```

This installs the checkout's version (the `<version>` in `red-kite-maven-plugin/pom.xml`, `0.1.0-SNAPSHOT` on `main`) into `~/.m2`, and you then use that version in the commands above.
