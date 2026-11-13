# Maven Plugin

The `red-kite-maven-plugin` runs the same analysis as the RedKite server from the command line, without the server. It prints a text report to the build log and writes a JSON copy. It is run by hand when you want it; nothing runs unless you invoke it or bind it in your POM.

It reuses RedKite's own scanner, Maven Central and OSV.dev providers and an H2 database. The plugin keeps its own database at `~/.redkite/plugin/redkite`, shared by all projects so version and vulnerability lookups are cached between builds. It is separate from the server's database, so the plugin and server can run at the same time, and parallel builds share it through H2's `AUTO_SERVER` mode. Use `-Dredkite.db.url=...` to put it elsewhere.

## Goals

| Goal | Default phase | Purpose |
| --- | --- | --- |
| `redkite:report` | none | Analyse, print the report and write the JSON copy. Never fails the build. |
| `redkite:check` | `verify` | Print the report, then fail the build for vulnerabilities a developer can fix. |

Both goals are aggregators: they run once, at the execution root, and analyse every module beneath it.

## Quick start

Requirements: Java 17+, Maven 3.9+ on `PATH`, and network access to Maven Central and OSV.dev.

1. **Install the plugin locally** from a RedKite checkout (it is not on Maven Central yet):

    ```bash
    git clone https://github.com/johnjoeallen/redkite.git
    cd redkite
    mvn install -DskipTests -pl red-kite-maven-plugin -am
    ```

    `-am` also installs the modules the plugin depends on. Repeat after pulling RedKite changes.

2. **Add the plugin group** to `~/.m2/settings.xml` so the `redkite:` prefix works in any project, with no POM changes:

    ```xml
    <settings>
      <pluginGroups>
        <pluginGroup>com.redkite</pluginGroup>
      </pluginGroups>
    </settings>
    ```

3. **Run it** from the root of the project you want to analyse:

    ```bash
    mvn redkite:report
    ```

4. **Read the report** in the build output. `target/redkite/redkite-report.json` is also written for tooling.

Without the settings change, use the full coordinates instead:

```bash
mvn com.redkite:red-kite-maven-plugin:0.1.0-SNAPSHOT:report
```

## Usage

```bash
mvn redkite:report                                   # report only, never fails the build
mvn redkite:check                                    # fails on fixable HIGH or worse (the default)
mvn redkite:check -Dredkite.failOnSeverity=CRITICAL  # stricter or looser threshold
mvn redkite:check -Dredkite.failOnSnapshot=true      # also fail on SNAPSHOT dependencies
mvn redkite:report -Dredkite.enforcer=true           # include dependency-convergence analysis (slower)
```

To run the check after a normal build without touching the POM, add the goal to the command line:

```bash
mvn verify redkite:check
```

To have `mvn verify` run it, put it in an opt-in profile in the project POM:

```xml
<profile>
  <id>redkite</id>
  <build>
    <plugins>
      <plugin>
        <groupId>com.redkite</groupId>
        <artifactId>red-kite-maven-plugin</artifactId>
        <version>0.1.0-SNAPSHOT</version>
        <executions>
          <execution>
            <goals><goal>check</goal></goals>
            <configuration>
              <failOnSeverity>HIGH</failOnSeverity>
              <failOnSnapshot>true</failOnSnapshot>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</profile>
```

Then run `mvn verify -Predkite`. Profiles in `settings.xml` cannot bind plugins, so the profile has to live in the POM.

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
- **`target/redkite/redkite-report.json`** (`outputDirectory`): components, vulnerabilities and recommendations for CI tooling.

## Parameters

| Parameter | Property | Default | Goals | Description |
| --- | --- | --- | --- | --- |
| `skip` | `redkite.skip` | `false` | both | Skip the plugin. |
| `outputDirectory` | `redkite.outputDirectory` | `${project.build.directory}/redkite` | both | Where the JSON report is written. |
| `databaseUrl` | `redkite.db.url` | `~/.redkite/plugin/redkite` (H2, `AUTO_SERVER`) | both | H2 database for the cache and scan history. |
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
- If a run fails with an H2 error such as `EOFException` or `Timeout trying to lock table`, the plugin's cache database is damaged. It holds only cached lookups, so delete `~/.redkite/plugin/` and re-run.
