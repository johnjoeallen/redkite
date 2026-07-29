# Apply Selected

From an analysis page:

1. Review the recommended dependency changes.
2. Select the changes to apply — adjust target versions in the dropdowns, or check individual conflict fixes.
3. Click **Apply selected**.

RedKite shows a preview panel first, listing every change that's actually about to be made (version bumps, pin/unpin, conflict resolutions) — or "No changes." if the current selection wouldn't actually modify anything. Review it and confirm before the validate/write/re-analyse sequence described in [Validation Process](validation-process.md) runs at all.

General updates stay property-backed: a literal `<version>` tag is normalized to a `${artifactId.version}` property reference, and RedKite updates the property value to the chosen version. Dependency-management pins are reserved for conflict fixes and transitive overrides specifically, and always use an explicit, hardcoded version rather than a property reference — see [Dependency Conflicts](../recommendations/dependency-conflicts.md).

Once apply succeeds, RedKite automatically triggers a fresh analysis of the project so you can see whether anything further needs attention.
