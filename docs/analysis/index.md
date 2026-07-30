# Analysis

Each RedKite analysis scans a Maven project's full dependency tree — every module, resolved the same way Maven itself would resolve it — and builds a report covering several distinct axes at once:

- [Dependency Inventory](dependency-inventory.md) — the full set of components found
- [Direct Dependencies](direct-dependencies.md)
- [Transitive Dependencies](transitive-dependencies.md)
- [Plugins](plugins.md)
- [Snapshots](snapshots.md)
- [License Scanning](license-scanning.md)
- [Analysis History](analysis-history.md)

What RedKite does with what it finds — recommending updates, flagging vulnerabilities, detecting conflicts — is covered separately under [Recommendations](../recommendations/index.md) and [Vulnerabilities](../vulnerabilities/index.md).
