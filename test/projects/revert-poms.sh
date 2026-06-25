#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
find "$DIR" -name "pom.xml" ! -path "*/target/*" | while read -r f; do
  cp "${f}.orig" "$f"
  echo "Reverted: $f"
done
