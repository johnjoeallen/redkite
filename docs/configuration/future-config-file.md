# Future: config.rk

!!! warning "Status: Planned"
    This page describes a capability that does not exist yet. Today, configuration is split across startup system properties, the `/config` page, and per-project settings — see [Configuration](index.md) for what's actually available right now.

## The idea

A single, project-local `config.rk` file (checked into the project's own repository, alongside its `pom.xml`) would let a team declare RedKite settings as part of the project itself — build validation arguments and environment variables, cache TTL overrides, family/BOM alignment hints — instead of configuring them by hand through the UI every time the project is added on a new machine. This would complement rather than replace the existing UI: values in `config.rk` would seed sensible defaults, still visible and overridable from the project's own settings page.

## Related

- [Configuration](index.md)
- [Project Settings](project-settings.md)
- [Planned Features](../roadmap/planned-features.md)
