# Installation

Download the latest `red-kite-<version>.zip` from the [releases page](https://github.com/johnjoeallen/redkite/releases), then extract it.

On Linux or macOS:

```bash
unzip red-kite-<version>.zip -d red-kite
cd red-kite
./red-kite.sh
```

On Windows, extract the archive and run:

```bat
red-kite.bat
```

RedKite starts on port `6502` and stores its database under `~/.redkite`. Open the UI at:

```text
http://localhost:6502
```

!!! note
    Need a different port, or to point RedKite at a different database? See [Application Settings](../configuration/application-settings.md).

## Building from source

If you'd rather build RedKite yourself instead of downloading a release, see [Building from Source](../development/building-from-source.md).
