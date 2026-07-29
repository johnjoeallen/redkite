# Command Line

RedKite is a jar you run directly; there is no separate CLI binary.

```bash
java -jar red-kite.jar
```

or, using the bundled launcher script:

```bash
./red-kite.sh      # Linux/macOS
red-kite.bat        # Windows
```

Either starts the HTTP server (default port `6502`) and keeps running until stopped.

## Flags

| Flag | Effect |
|---|---|
| `--drop-db` | Deletes the local database files and exits, without starting the server. Use this for a clean-slate reset. |

Any other arguments are ignored; there's no subcommand form (e.g. no standalone `scan` or `apply` command run from outside the web UI) — everything else is driven through the HTTP API the UI itself uses.

Server-level configuration (port, database location, external service URLs) is set through system properties at launch, not command-line flags — see [System Properties](system-properties.md).
