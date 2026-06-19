#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mvn --no-transfer-progress package -DskipTests

JAR=$(ls "$DIR"/red-kite-server/target/red-kite-*.jar 2>/dev/null | grep -v 'shaded' | head -1)
if [ -z "$JAR" ]; then
  echo "Build succeeded but no JAR found in red-kite-server/target/" >&2
  exit 1
fi

cp "$JAR" "$DIR/scripts/red-kite.jar"
echo "Built: scripts/red-kite.jar"
