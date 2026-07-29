# Failed POMs

When a validation build or startup check fails, RedKite copies the root POM it was validating to a sibling `pom.failed` file, next to the real `pom.xml`, before anything is rolled back. This gives you the exact content that failed to build or start, for offline investigation, even after the working POM has been reverted to its last-known-good state.

`pom.failed` is overwritten on each new failure — it isn't a history, just the most recent one. It's a plain file on disk; delete it whenever you're done with it, or leave it — RedKite doesn't read it back for anything.
