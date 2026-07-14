#!/usr/bin/env bash
# uninstall.sh — remove a PQ-Kerberos install done via scripts/install.sh.
# If you installed the .deb instead, use: sudo apt remove pqkerberos

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo ./scripts/uninstall.sh"; exit 1; }

echo "Stopping and disabling service..."
systemctl stop pqkerberos.service 2>/dev/null || true
systemctl disable pqkerberos.service 2>/dev/null || true
rm -f /etc/systemd/system/pqkerberos.service
systemctl daemon-reload || true

echo "Removing binaries and PAM module..."
rm -rf /opt/pqkerberos
rm -f /usr/local/bin/pqkerberos-login /usr/local/bin/pqk-exec \
      /usr/local/bin/pqkerberos-demo /usr/local/bin/pqkerberos-attack
rm -f /lib/x86_64-linux-gnu/security/pam_pqkerberos.so
rm -f /etc/pam.d/pqkerberos

read -rp "Remove /etc/pqkerberos (including users.conf)? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    rm -rf /etc/pqkerberos
fi

echo "Done."
