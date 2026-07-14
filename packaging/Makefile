# Makefile — pam_pqkerberos.so
#
# Builds and installs the PAM module for PQ-Kerberos authentication.
# Must be run as root for the install target.
#
# Targets:
#   all     — build pam_pqkerberos.so
#   install — copy to PAM module directory
#   clean   — remove build artefacts
#   test    — verify the .so links correctly
#   check   — smoke-test with pamtester (requires pamtester package)

CC       = gcc
CFLAGS   = -fPIC -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS  = -shared -lpam

MODULE   = pam_pqkerberos.so
SRC      = pam_pqkerberos.c

# Debian/Kali/Ubuntu 64-bit PAM module directory
PAM_DIR  = /lib/x86_64-linux-gnu/security
# Fallback for 32-bit or other distros:
# PAM_DIR = /lib/security

.PHONY: all install clean test check

all: $(MODULE)

$(MODULE): $(SRC)
	@echo "[CC] Compiling PAM module..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[OK] Built: $(MODULE)"
	@ls -lh $(MODULE)

install: $(MODULE)
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Run as root: sudo make install"; exit 1; fi
	@echo "[INSTALL] Copying to $(PAM_DIR)/"
	cp $(MODULE) $(PAM_DIR)/
	chmod 644 $(PAM_DIR)/$(MODULE)
	@echo "[OK] Installed: $(PAM_DIR)/$(MODULE)"

clean:
	rm -f $(MODULE)
	@echo "[CLEAN] Done."

# Verify the .so has no broken symbol links
test: $(MODULE)
	@echo "[TEST] Checking library dependencies..."
	ldd $(MODULE) || true
	@echo "[TEST] Checking exported PAM symbols..."
	nm -D $(MODULE) | grep pam_sm || true

# Quick PAM stack test — requires: apt install libpam-runtime pamtester
check:
	@echo "[CHECK] Testing PAM stack for service 'pqkerberos'..."
	@echo "        Make sure SystemDaemon is running first."
	pamtester pqkerberos alice authenticate
