# System Properties

Set with `-D` at launch, e.g. `java -Dredkite.port=8080 -jar red-kite.jar`.

| Property | Default | Purpose |
|---|---|---|
| `redkite.port` | `6502` | HTTP port the server listens on |
| `redkite.db.url` | `jdbc:h2:~/.redkite/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE` | H2 database JDBC URL |
| `redkite.db.user` | `sa` | Database user |
| `redkite.db.password` | *(empty)* | Database password |
| `redkite.prefs.file` | `~/.redkite/preferences.properties` | Local UI preferences file (theme, etc.) |
| `redkite.maven.repositories` | *(unset)* | Comma-separated repository URLs; bypasses `settings.xml` discovery when set — see [Maven Settings](../configuration/maven-settings.md) |
| `redkite.osv.url` | `https://api.osv.dev` | Base URL for OSV vulnerability queries |
| `redkite.version.lookback` | `10` | Number of prior versions considered when searching for a candidate fix |

See [Application Settings](../configuration/application-settings.md) for usage guidance on the properties most people need.
