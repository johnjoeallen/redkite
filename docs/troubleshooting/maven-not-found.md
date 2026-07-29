# Maven Not Found

RedKite runs the `mvn` command already installed on your system (`mvn.cmd` on Windows) — it doesn't bundle its own copy, and doesn't check in advance that Maven is actually reachable. If `mvn` isn't on `PATH`, the attempt to launch it fails immediately with an OS-level error (typically something like `Cannot run program "mvn": error=2, No such file or directory`), and that raw message is what you'll see as the failure signature in the UI — for both build and Spring Boot startup validation.

**Fix**: make sure `mvn -version` succeeds in the same shell/environment RedKite itself runs in — see [Requirements](../getting-started/requirements.md). This matters most if you're running RedKite as a service or from a different shell/profile than the one you normally use, since `PATH` isn't always inherited the way you'd expect.
