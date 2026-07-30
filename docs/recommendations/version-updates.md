# Version Updates

For a direct dependency, RedKite recommends the newest version it considers safe to suggest automatically:

- pre-release versions (alphas, betas, release candidates, and similar) are excluded from consideration
- a major version bump (a change to the first version component) is **not** currently recommended automatically — RedKite scans within the current major line only

A transitive dependency is handled differently — see [Transitive Dependencies](../analysis/transitive-dependencies.md) for why a plain "newer version exists" isn't, by itself, a reason RedKite recommends moving one.

## How updates are applied

An accepted general update stays property-backed: if the dependency's version is a literal `<version>` tag, RedKite normalizes it to a `${artifactId.version}` property reference first, then sets the property's value to the chosen version. If it's already declared through a property, only the property's value changes. This is deliberately different from how conflict fixes are applied — see [Dependency Conflicts](dependency-conflicts.md) for why those always use a hardcoded literal instead.

Before introducing a new property, RedKite checks it against every property name already declared anywhere in the project's parent chain and imported BOMs — a Spring Boot parent, for example, defines properties like `jackson-bom.version` to control its own internal BOM imports, and a locally-created property with that exact name would silently redefine it for everything the parent manages through it, not just the dependency the new property was meant for. When the plain `artifactId.version` name would collide with one an ancestor already owns, RedKite falls back to a `groupId.artifactId.version` form instead.
