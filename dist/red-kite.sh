#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="$DIR/red-kite.jar"

if ! command -v java &>/dev/null; then
  echo "Error: Java 17 or later is required." >&2
  echo "Download from https://adoptium.net" >&2
  exit 1
fi

JAVA_VER=$(java -version 2>&1 | awk -F[\".] '/version/ {print $2}')
if [ "${JAVA_VER:-0}" -lt 17 ] 2>/dev/null; then
  echo "Error: Java 17 or later is required (found Java ${JAVA_VER})." >&2
  echo "Download from https://adoptium.net" >&2
  exit 1
fi

case "${1:-}" in
  scan|apply-plan)
    exec java -cp "$JAR" com.redkite.scan.RedKiteCliApplication "$@"
    ;;
  *)
    exec java -jar "$JAR" "$@"
    ;;
esac
