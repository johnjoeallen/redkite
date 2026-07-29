# Project Settings

Most of a project's identity — its name and root path — is fixed at the point you add it (see [Adding a Project](../projects/adding-a-project.md)) and isn't edited afterward through the UI.

The one editable setting is **build validation**, on the project's own page: the Maven arguments and environment variables used when RedKite validates a change by running a real build (and, for Spring Boot projects, a real startup). See [Build Validation](../projects/build-validation.md) for what these fields do and worked examples.

The project page also displays, read-only, the Maven `settings.xml` RedKite resolved for this project and the repository configuration derived from it — useful for confirming RedKite is looking at the settings file you expect. See [Maven Settings](maven-settings.md) for how that resolution works.
