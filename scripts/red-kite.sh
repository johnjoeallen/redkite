#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLASSES_DIR="$ROOT/.redkite-docker/classes"
LIB_DIR="$ROOT/.redkite-docker/lib"
POSTGRES_JAR=""

ensure_java17() {
  local version
  version="$(java -version 2>&1 | awk -F[\".] '/version/ {print $2; exit}')"
  if [[ "$version" != "17" ]]; then
    echo "Java 17 is required on PATH (found: ${version:-unknown})" >&2
    exit 1
  fi
}

find_postgres_jar() {
  local candidate
  candidate="$(find "$HOME/.m2/repository/org/postgresql/postgresql" -name 'postgresql-*.jar' | sort -V | tail -n 1)"
  if [[ -z "${candidate}" ]]; then
    echo "Unable to find PostgreSQL JDBC jar in ~/.m2/repository/org/postgresql/postgresql" >&2
    exit 1
  fi
  POSTGRES_JAR="$candidate"
}

compile() {
  ensure_java17
  mkdir -p "$CLASSES_DIR" "$LIB_DIR"
  find_postgres_jar
  cp "$POSTGRES_JAR" "$LIB_DIR/postgresql.jar"
  javac --release 17 -d "$CLASSES_DIR" $(find "$ROOT/red-kite-core/src/main/java" "$ROOT/red-kite-git/src/main/java" "$ROOT/red-kite-maven/src/main/java" "$ROOT/red-kite-metadata/src/main/java" "$ROOT/red-kite-server/src/main/java" "$ROOT/red-kite-scan/src/main/java" -name '*.java')
}

compose_up() {
  docker compose -f "$ROOT/docker-compose.yml" up -d --build
}

wait_for_server() {
  local i
  for i in $(seq 1 60); do
    if curl -fsS "http://localhost:6502/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "RedKite server did not become ready on port 6502" >&2
  exit 1
}

run_scan() {
  local repo="${1:-.}"
  java -cp "$CLASSES_DIR" com.redkite.scan.RedKiteCliApplication scan "$repo" --server http://localhost:6502
}

open_db() {
  docker compose -f "$ROOT/docker-compose.yml" exec postgres psql -U redkite -d redkite
}

case "${1:-scan}" in
  start|up)
    compile
    compose_up
    wait_for_server
    echo "RedKite server is available on http://localhost:6502"
    ;;
  scan)
    shift || true
    compile
    wait_for_server
    run_scan "${1:-.}"
    ;;
  stop|down)
    docker compose -f "$ROOT/docker-compose.yml" down
    ;;
  db)
    open_db
    ;;
  *)
    echo "Usage: $0 [start|scan [repo]|db|stop]" >&2
    exit 1
    ;;
esac
