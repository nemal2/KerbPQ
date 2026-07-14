#!/usr/bin/env bash
# install.sh — build & install PQ-Kerberos from source (Debian/Ubuntu/Kali).
#
# Prefer the .deb from GitHub Releases if you just want to install it —
# this script is for building and installing directly from a source
# checkout.
#
# Run as root:  sudo ./scripts/install.sh

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
CYN='\033[0;36m'; BLD='\033[1m';    RST='\033[0m'

ok()   { echo -e "${GRN}[OK]${RST}  $*"; }
info() { echo -e "${CYN}[--]${RST}  $*"; }
warn() { echo -e "${YLW}[!!]${RST}  $*"; }
die()  { echo -e "${RED}[XX] FATAL: $*${RST}"; exit 1; }

INSTALL_DIR="/opt/pqkerberos"
CONFIG_DIR="/etc/pqkerberos"
PAM_MODULE_DIR="/lib/x86_64-linux-gnu/security"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ $EUID -eq 0 ]] || die "Please run as root: sudo ./scripts/install.sh"

echo -e "${BLD}${CYN}"
echo "======================================================"
echo "   PQ-Kerberos — install from source"
echo "======================================================"
echo -e "${RST}"

echo -e "\n${BLD}[1/7] Installing system packages${RST}"
apt-get update -q
apt-get install -y -q \
    default-jdk maven gcc libpam0g-dev libpam-runtime pamtester netcat-openbsd curl
ok "Packages installed"
info "Java: $(java -version 2>&1 | head -1)"

echo -e "\n${BLD}[2/7] Creating directories${RST}"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/users.conf" ]]; then
    cat > "$CONFIG_DIR/users.conf" << 'EOF'
# PQ-Kerberos user store — FOR DEMO/TESTING ONLY.
# Format: username=password (plaintext — see SECURITY.md before real use)
alice=alice123
bob=bob456
EOF
    chmod 600 "$CONFIG_DIR/users.conf"
    ok "Created $CONFIG_DIR/users.conf (edit to add/change users)"
else
    info "$CONFIG_DIR/users.conf already exists — leaving untouched"
fi

echo -e "\n${BLD}[3/7] Building Java fat-JAR${RST}"
cd "$SCRIPT_DIR"
mvn -q clean package -DskipTests
cp target/pqkerberos.jar "$INSTALL_DIR/"
ok "JAR installed: $INSTALL_DIR/pqkerberos.jar"

echo -e "\n${BLD}[4/7] Building PAM module${RST}"
cd "$SCRIPT_DIR/pam"
make clean
make
make install
ok "PAM module: $PAM_MODULE_DIR/pam_pqkerberos.so"
cd "$SCRIPT_DIR"

echo -e "\n${BLD}[5/7] Configuring PAM service${RST}"
cp packaging/deb/etc/pam.d/pqkerberos /etc/pam.d/pqkerberos
ok "Created /etc/pam.d/pqkerberos"

echo -e "\n${BLD}[6/7] Installing helper commands${RST}"
install -m 755 scripts/pqk-exec /usr/local/bin/pqk-exec
install -m 755 scripts/pqkerberos-login /usr/local/bin/pqkerberos-login
cat > /usr/local/bin/pqkerberos-attack << SCRIPT
#!/usr/bin/env bash
java -cp $INSTALL_DIR/pqkerberos.jar pqkerberos.Demo attacks
SCRIPT
chmod +x /usr/local/bin/pqkerberos-attack
cat > /usr/local/bin/pqkerberos-demo << SCRIPT
#!/usr/bin/env bash
java -cp $INSTALL_DIR/pqkerberos.jar pqkerberos.Demo "\$@"
SCRIPT
chmod +x /usr/local/bin/pqkerberos-demo
ok "Commands: pqkerberos-login  pqk-exec  pqkerberos-demo  pqkerberos-attack"

echo -e "\n${BLD}[7/7] systemd service${RST}"
sed "s#/usr/share/pqkerberos/pqkerberos.jar#${INSTALL_DIR}/pqkerberos.jar#" \
    packaging/deb/etc/systemd/system/pqkerberos.service > /etc/systemd/system/pqkerberos.service
systemctl daemon-reload
ok "Created /etc/systemd/system/pqkerberos.service"

echo ""
echo -e "${BLD}${GRN}======================================================"
echo    "   Installation complete"
echo -e "======================================================${RST}"
echo ""
echo -e "  ${BLD}Start it:${RST}       sudo systemctl start pqkerberos"
echo -e "  ${BLD}Follow logs:${RST}    journalctl -fu pqkerberos"
echo -e "  ${BLD}Try it:${RST}         pqkerberos-login alice   (password: alice123)"
echo -e "  ${BLD}Attack demo:${RST}    pqkerberos-demo attacks"
echo ""
echo -e "  ${YLW}Demo users live in /etc/pqkerberos/users.conf — change them"
echo -e "  before using this anywhere but a lab/VM. See SECURITY.md.${RST}"
echo ""
