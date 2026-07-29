# How RedKite Works

Clicking **Analyse** on a project runs a pipeline in the background, in three phases:

1. **Scan.** RedKite runs Maven against your project to discover its full dependency tree, module by module. See [Dependency Resolution](dependency-resolution.md).
2. **Ingest.** For every component found, RedKite looks up version metadata, checks for known vulnerabilities, and computes an update recommendation — this is the phase behind the "Version", "Vulnerability", and "Updates" progress you see during a scan.
3. **Enforcer check.** RedKite runs Maven Enforcer's convergence rules and parses the output into conflict findings, then computes candidate pin/exclusion fixes for them. See [Dependency Conflicts](../recommendations/dependency-conflicts.md).

Before scanning starts, RedKite re-resolves the project's Maven settings and repository configuration (see [Maven Settings](../configuration/maven-settings.md)), so a project whose `settings.xml` changed since the last scan picks that change up automatically.

The result of all three phases is stored as a single scan report — see [Analysis History](../analysis/analysis-history.md) for how past scans are kept and compared.
