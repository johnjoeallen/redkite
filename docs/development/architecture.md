# Architecture

RedKite is a self-contained local HTTP server with no external framework dependency: routing and request handling use the JDK's own built-in `com.sun.net.httpserver.HttpServer`, persistence uses H2, and page shells use Thymeleaf templating with content built as plain strings.

## Scan pipeline

Analysing a project runs through the phases described in [How RedKite Works](../concepts/how-redkite-works.md). A closer look at phase one, dependency discovery:

```
MavenProjectScanner.scan(path)
  ├── read git metadata (branch, HEAD commit, clean/dirty)
  ├── walk the filesystem, collect every pom.xml
  ├── parse each POM (groupId, artifactId, version, properties,
  │     dependencies, dependencyManagement, plugins)
  │     — builds the set of this project's own module coordinates,
  │       so an internal cross-module dependency is never mistaken
  │       for an external one
  └── for each POM:
        - direct dependencies → components (skipping self-references
          and the project's own modules)
        - plugins → components
        - if it's an aggregator (has <modules>, no code of its own):
            dependencyManagement entries only, no dependency:tree run
        - otherwise: run `mvn dependency:tree`, parse the output
          (see Dependency Resolution) into components and edges
        - the POM's own external parent → a component
```

Each component's version is tagged with where it came from — a literal `<version>` tag, a `${property}` reference, a BOM-managed entry with no version tag at all, or (for transitive dependencies) whatever Maven itself resolved — which downstream logic (like [Version Updates](../recommendations/version-updates.md)) uses to decide how an update should be written back.

## No framework, by design

Avoiding a web framework, DI container, or ORM keeps RedKite's own footprint small and its startup fast — appropriate for a tool meant to be launched, used for a session, and left running locally rather than deployed as a service.
