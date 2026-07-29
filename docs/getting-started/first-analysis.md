# First Analysis

## Add and analyse a project

From the RedKite home page:

1. Enter the full path to the Maven project.
2. Click **Analyse**. A progress overlay shows while the analysis runs.
3. The browser navigates to the project's dashboard when it completes.

You can also click **Analyse** next to any previously-analysed project on the home page, or from inside an existing analysis, to re-scan it. See [Adding a Project](../projects/adding-a-project.md) and [Project Dashboard](../projects/project-dashboard.md) for more detail on what's shown there.

RedKite's analysis covers:

- direct dependencies
- transitive dependencies
- dependency-management entries
- build plugins
- available version updates
- known vulnerabilities (from OSV.dev)
- declared licenses
- duplicate and conflicting dependency versions across modules

See [Analysis](../analysis/index.md) for the full breakdown of what each of these means on the results page.

## Review the findings

The analysis view lists every dependency, grouped by module, with:

- a severity badge summarising known CVEs on that dependency (and, separately, any found among its own transitive dependencies)
- **Findings** / **Clean** / **All** tabs, and filter chips for CVE status, conflicts, and origin (direct vs. transitive)
- a version selector for anything with a concrete recommendation — a CVE fix, a resolved convergence conflict, or (for direct dependencies) a plain available update

See [Recommendations](../recommendations/index.md) for how RedKite decides what counts as a finding, and [Applying Changes](../applying-changes/index.md) for what happens when you select something and click **Apply selected**.
