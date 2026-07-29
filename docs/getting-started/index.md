# Getting Started

This section covers the minimum steps to install RedKite, analyse a Maven project, and apply dependency changes.

1. [Check the requirements](requirements.md) — Java 17+, Maven 3.9+.
2. [Install and start RedKite](installation.md).
3. [Run your first analysis](first-analysis.md) against a local Maven project.
4. If it's a Spring Boot project, [configure a validation profile](spring-boot-projects.md) before applying anything.
5. Review the recommendations and apply the ones you want — see [Applying Changes](../applying-changes/index.md).

!!! note "Known limitations"
    RedKite currently supports Maven projects only (no Gradle or npm), and only repositories reachable from the machine it runs on. See [Limitations](../vulnerabilities/limitations.md) for what this means for vulnerability coverage specifically.
