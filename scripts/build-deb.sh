#!/usr/bin/env bash
# build-deb.sh — build pqkerberos_<version>_amd64.deb from source.
#
# Usage: ./scripts/build-deb.sh [version]
#   version defaults to the version in pom.xml, or 1.0.0.
#
# Produces: dist/pqkerberos_<version>_amd64.deb

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${1:-$(grep -m1 '<version>' pom.xml | sed -E 's/.*<version>(.*)<\/version>.*/\1/')}"
VERSION="${VERSION:-1.0.0}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> Building fat JAR (mvn clean package)"
mvn -q clean package -DskipTests

echo "==> Building PAM module"
make -C pam clean all

echo "==> Staging package tree (version $VERSION)"
cp -r packaging/deb/. "$STAGE"
sed -i "s/__VERSION__/${VERSION}/" "$STAGE/DEBIAN/control"

mkdir -p "$STAGE/usr/share/pqkerberos"
cp target/pqkerberos.jar "$STAGE/usr/share/pqkerberos/pqkerberos.jar"

mkdir -p "$STAGE/lib/x86_64-linux-gnu/security"
cp pam/pam_pqkerberos.so "$STAGE/lib/x86_64-linux-gnu/security/pam_pqkerberos.so"

mkdir -p "$STAGE/usr/local/bin"
install -m 755 scripts/pqk-exec "$STAGE/usr/local/bin/pqk-exec"
install -m 755 scripts/pqkerberos-login "$STAGE/usr/local/bin/pqkerberos-login"

chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

mkdir -p dist
OUT="dist/pqkerberos_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"

echo "==> Built: $OUT"
