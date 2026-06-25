#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mvn --no-transfer-progress clean package -DskipTests

JAR=$(ls "$DIR"/red-kite-server/target/red-kite-*.jar 2>/dev/null | grep -v 'shaded' | head -1)
if [ -z "$JAR" ]; then
  echo "Build succeeded but no JAR found in red-kite-server/target/" >&2
  exit 1
fi

cp "$JAR" "$DIR/scripts/red-kite.jar"
echo "Built: scripts/red-kite.jar"

# Create distribution zip: scripts + test fixture POMs
mkdir -p "$DIR/dist"
ZIP="$DIR/dist/red-kite.zip"
rm -f "$ZIP"

(
  cd "$DIR/scripts"
  zip -q "$ZIP" red-kite.jar red-kite.sh red-kite.bat
)

(
  cd "$DIR/test/projects"
  find convergence-fixture -name "pom.xml.orig" ! -path "*/target/*" | while read -r f; do
    cp "$f" "${f%.orig}"
  done
  find convergence-fixture \( -name "pom.xml" -o -name "pom.xml.orig" \) ! -path "*/target/*" | \
    xargs zip -q "$ZIP"
  zip -q "$ZIP" revert-poms.sh
)

echo "Built: dist/red-kite.zip"
