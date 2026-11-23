# Excluding Folders

By default RedKite analyses every `pom.xml` under the project root. That includes POMs that are not part of your build: test fixtures that deliberately pin old, vulnerable versions, sample projects, vendored code. They show up as components and vulnerabilities in the report, and the upgrade goals cannot change them, so the same findings come back on every run.

Exclude those folders with the `excludes` setting of the RedKite Maven plugin.

## Configure it in the POM

Add the folders to the plugin's configuration in the project's **root `pom.xml`**. Put it in `<pluginManagement>` so it also applies when you run the plugin directly from the command line, not only when it is bound in a profile:

```xml
<build>
  <pluginManagement>
    <plugins>
      <plugin>
        <groupId>net.dublinux.redkite</groupId>
        <artifactId>red-kite-maven-plugin</artifactId>
        <version>0.99.208</version>
        <configuration>
          <excludes>
            <exclude>test/projects</exclude>
            <exclude>samples</exclude>
          </excludes>
        </configuration>
      </plugin>
    </plugins>
  </pluginManagement>
</build>
```

The plugin parameter exists from release `0.99.207`; earlier releases ignore the setting.

On the command line, pass a comma-separated list. This adds nothing to the POM and only affects that run:

```bash
mvn -B net.dublinux.redkite:red-kite-maven-plugin:0.99.208:report -Dredkite.excludes=test/projects,samples
```

## How entries match

- Each entry is a directory **relative to the project root**. A leading `./` or `/` and a trailing `/` are ignored.
- An entry excludes that directory and everything below it. Matching is by whole path segment, so `test` excludes `test/…` but not `testing/…` or `src/test/…`.
- Blank entries and `.` are ignored.
- There are no wildcards.

## What an exclusion affects

A POM in or below an excluded folder is left out of:

- the dependency scan, so its components, vulnerabilities and recommendations do not appear;
- the dependency-convergence (enforcer) analysis, when `redkite.enforcer` is on;
- the search for `redkite:user-pin` markers.

It is not read, reported or changed by any goal.

## The server

The RedKite server reads the same setting. When it scans a project it looks for `<excludes><exclude>` under a `red-kite-maven-plugin` entry in the project's root `pom.xml` (in `<build>`, `<pluginManagement>` or a profile) and skips those folders. Nothing needs configuring in the server itself.

The server cannot see `-Dredkite.excludes` from a command line, because that is a property of a Maven run. To exclude a folder for the server, put it in the POM.

## Spotting a folder that needs excluding

When a vulnerable dependency is declared in a POM that is outside the Maven build, the report says so and tells you the upgrade goals cannot edit it:

```
  HIGH      com.fasterxml.jackson.core:jackson-core:2.22.2
      GHSA-7hhh-6rmp-j9qf (CVE-2026-89425)  fixed in 2.22.3
      declared in test/projects/convergence-fixture/old-wrapper/pom.xml  (not in the build)
      The upgrade goals cannot edit POMs outside the build; exclude them or fix them by hand.
```

If those POMs are not meant to be analysed, add their folder to `excludes`. If they are, fix them by hand, or add them as modules of the build so the upgrade goals can reach them.
