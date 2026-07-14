#!/usr/bin/env bash
# build-deb.sh — package the PQ-Kerberos fat JAR into a .deb via jpackage
#
# Requires: JDK 17+ with jpackage (bundled since JDK 14), and on Debian/Ubuntu
# systems `fakeroot` must be installed for jpackage's deb output.
#
# Usage:
#   ./packaging/build-deb.sh
#
# Produces: target/dist/pqkerberos_<version>_amd64.deb

set -euo pipefail

VERSION="${1:-1.0.0}"
APP_NAME="pqkerberos"
MAIN_JAR="target/pqkerberos-${VERSION}.jar"
MAIN_CLASS="pqkerberos.Demo"
DEST="target/dist"

if [ ! -f "$MAIN_JAR" ]; then
    echo "[build-deb] $MAIN_JAR not found — run 'mvn clean package' first." >&2
    exit 1
fi

command -v jpackage >/dev/null 2>&1 || {
    echo "[build-deb] jpackage not found. Install a JDK 17+ (jpackage ships with the JDK, not the JRE)." >&2
    exit 1
}

mkdir -p "$DEST"

echo "[build-deb] Building .deb for ${APP_NAME} ${VERSION}..."

jpackage \
    --type deb \
    --name "$APP_NAME" \
    --app-version "$VERSION" \
    --input target \
    --main-jar "$(basename "$MAIN_JAR")" \
    --main-class "$MAIN_CLASS" \
    --dest "$DEST" \
    --vendor "KerbPQ Project" \
    --description "Post-quantum Kerberos authentication demo (Kyber-768 + Dilithium-3 + AES-256-GCM)" \
    --linux-menu-group "Development;Security;" \
    --linux-app-category "utils"

echo "[build-deb] Done. Output in ${DEST}/"
ls -lh "$DEST"
