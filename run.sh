#!/usr/bin/env bash
# run.sh — quickest way to try PQ-Kerberos: build + run the demo, no .deb needed
#
# Usage:
#   ./run.sh            # normal auth demo
#   ./run.sh attacks     # auth demo + 8 attack simulations

set -euo pipefail

if ! command -v mvn >/dev/null 2>&1; then
    echo "Maven not found. Install it first: https://maven.apache.org/install.html" >&2
    exit 1
fi

echo "[run.sh] Building (mvn clean package)..."
mvn -q clean package

JAR=$(ls target/pqkerberos-*.jar | grep -v original | head -n1)

echo "[run.sh] Launching..."
exec java -jar "$JAR" "$@"
