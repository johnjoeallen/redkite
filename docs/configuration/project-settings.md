# Project Settings

A project's identity — its name and root path — is fixed at the point you add it (see [Adding a Project](../projects/adding-a-project.md)) and isn't edited afterward through the UI.

Build validation settings (extra Maven arguments, profile, Spring profile, environment variables) aren't edited through the UI either — they live in a file checked into the project itself, `.redkite/project.cfg`. See [Build Validation](../projects/build-validation.md) for the file format. The project page shows a read-only panel with whatever the file currently resolves to.

The project page also displays, read-only, the Maven `settings.xml` RedKite resolved for this project and the repository configuration derived from it — useful for confirming RedKite is looking at the settings file you expect. See [Maven Settings](maven-settings.md) for how that resolution works.
