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
  zip -q "$ZIP" red-kite.jar red-kite.sh red-kite.bat red-kite.properties.default
)

(
  cd "$DIR/test/projects"
  # Reset pom.xml from pom.xml.orig in a scratch copy, never in the working tree — the fixture's
  # real pom.xml files may hold in-progress RedKite remediation state a developer is testing with,
  # and this packaging step has no business touching that.
  TMP_FIXTURE=$(mktemp -d)
  trap 'rm -rf "$TMP_FIXTURE"' EXIT
  find convergence-fixture \( -name "pom.xml" -o -name "pom.xml.orig" -o -name "settings.yml" -o -name "settings.yaml" \) ! -path "*/target/*" \
    -exec cp --parents {} "$TMP_FIXTURE/" \;
  find "$TMP_FIXTURE/convergence-fixture" -name "pom.xml.orig" | while read -r f; do
    cp "$f" "${f%.orig}"
  done
  (cd "$TMP_FIXTURE" && find convergence-fixture -type f -print0 | xargs -0 zip -q "$ZIP")
  rm -rf "$TMP_FIXTURE"
  trap - EXIT
  zip -q "$ZIP" revert-poms.sh
)

echo "Built: dist/red-kite.zip"
