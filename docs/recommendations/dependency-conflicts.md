# Dependency Conflicts

In a multi-module project, the same dependency can resolve to different versions depending on which module pulled it in — a genuine convergence problem Maven itself can detect (see [Duplicate Dependencies](duplicate-dependencies.md) for the enforcer rules RedKite relies on). RedKite reads that enforcer output and computes a fix: a `dependencyManagement` pin or an exclusion, forcing every module to converge on one resolved version.

## Choosing the winning version

For a single conflicting artifact, RedKite picks the highest version already observed for it in the tree, reconciled against whatever the project itself already declares for that coordinate: a declared version is treated as a deliberate choice and wins by default, and a computed winner only overrides it when it's a raise *within the same release line* (e.g. a project on `1.5.25` moving to `1.5.38` because a finding requires it — never being dragged across a line the project has, deliberately or not, avoided).

## Coordinated release families and BOMs

Some groups of artifacts are released together and need to move as a set rather than being pinned independently — for example, a project whose Jackson `jackson-core` and `jackson-databind` need to stay in step with each other. RedKite recognizes a small set of these coordinated families and aligns their members to one release together.

Critically, this doesn't mean copying one version string onto every member: a real BOM frequently manages different members of the same family at different individual versions (the real Jackson 2.22.1 release, for example, manages `jackson-core` and `jackson-databind` at `2.22.1` but `jackson-annotations` at `2.22`). RedKite resolves each member's actual managed version — from the project's own imported BOM when it has one, or from the family's known BOM otherwise — rather than broadcasting the family's nominal version onto every member and risking a pin for a version that doesn't actually exist. When several members do land on the exact same version through a BOM they're already importing, RedKite collapses them into a single pin at the BOM's own coordinate instead of one pin per member, so a project already using `${jackson.version}` gets that one property bumped rather than N separate literal overrides.

## Applying a fix

Conflict fixes always use an explicit, hardcoded version — never a `${...}` property reference — since a pin is meant to be a single, self-contained, independently removable override. See [Applying Conflicts First](../applying-changes/applying-conflicts-first.md) for why these should be applied before unrelated general updates.
