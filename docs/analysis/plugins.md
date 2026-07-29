# Plugins

RedKite's analysis also covers a project's build plugins (`<build><plugins>` and plugin management), the same way it covers dependencies — recording each plugin's coordinates, declared version, and version source.

Plugin analysis feeds into RedKite's overall picture of the project, but the update-recommendation and CVE-detection machinery described under [Recommendations](../recommendations/index.md) and [Vulnerabilities](../vulnerabilities/index.md) is primarily built around dependencies. Treat plugin data on the analysis page as inventory information first.
