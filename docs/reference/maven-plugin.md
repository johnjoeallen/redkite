# Maven Plugin

The `red-kite-maven-plugin` runs the same analysis as the RedKite server as part of a Maven build and writes a static report.

It reuses RedKite's own scanner, Maven Central and OSV.dev providers and an H2 database. The plugin keeps its own database at `~/.redkite/plugin/redkite`, shared by all projects so version and vulnerability lookups are cached between builds. It is separate from the server's database, so the plugin and server can run at the same time, and parallel builds share it through H2's `AUTO_SERVER` mode. Use `-Dredkite.db.url=...` to put it elsewhere.

## Goals

| Goal | Default phase | Purpose |
| --- | --- | --- |
| `redkite:report` | none | Analyse and write the report. Never fails the build. |
| `redkite:check` | `verify` | Write the report, then fail the build if a threshold is crossed. |

Both goals are aggregators: they run once, at the execution root, and analyse every module beneath it.

## Installation

The plugin is not published to Maven Central yet, so install it into your local repository from a RedKite checkout:

```bash
mvn install -DskipTests -pl red-kite-maven-plugin -am
```

`-am` also installs the modules the plugin depends on. Repeat after updating RedKite.

## Usage

Add the plugin group to `~/.m2/settings.xml` so the short prefix works in any project, with no POM changes:

```xml
<pluginGroups><pluginGroup>com.redkite</pluginGroup></pluginGroups>
```

```bash
mvn redkite:report
mvn redkite:check -Dredkite.failOnSeverity=CRITICAL
```

To run it as part of `mvn verify`, put it in an opt-in profile in the project POM:

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

## Output

Written to `target/redkite/` (`outputDirectory`):

- `redkite-report.html` — the RedKite analysis page, self-contained and read-only (no Analyse or Apply controls).
- `redkite-report.json` — components, vulnerabilities and recommendations for CI tooling.

## Parameters

| Parameter | Property | Default | Goals | Description |
| --- | --- | --- | --- | --- |
| `skip` | `redkite.skip` | `false` | both | Skip the plugin. |
| `outputDirectory` | `redkite.outputDirectory` | `${project.build.directory}/redkite` | both | Where reports are written. |
| `databaseUrl` | `redkite.db.url` | `~/.redkite/plugin/redkite` (H2, `AUTO_SERVER`) | both | H2 database for the cache and scan history. |
| `enforcer` | `redkite.enforcer` | `false` | both | Also run the dependency-convergence analysis (several extra Maven runs). |
| `allowMajorUpgrades` | `redkite.allowMajorUpgrades` | `false` | both | Allow major-version upgrade recommendations. |
| `failOnSeverity` | `redkite.failOnSeverity` | `HIGH` | `check` | Fail on any vulnerability at or above `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`; `NONE` disables. |
| `failOnSnapshot` | `redkite.failOnSnapshot` | `false` | `check` | Fail on SNAPSHOT dependencies. |
| `failOnIncomplete` | `redkite.failOnIncomplete` | `false` | `check` | Fail when metadata could not be fetched. |

## Notes

- The scan runs `mvn dependency:tree` as a child process, so `mvn` must be on `PATH`, as for the server.
- The plugin only reads the project. It never edits POMs; applying upgrades remains a server feature.
- Run with `-X` to see RedKite's per-component logging.
