# PQ-Kerberos

**A Kerberos-style authentication protocol built on NIST post-quantum cryptography.**

[![CI](https://github.com/nemal2/KerbPQ/actions/workflows/ci.yml/badge.svg)](https://github.com/nemal2/KerbPQ/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nemal2/KerbPQ?include_prereleases)](https://github.com/nemal2/KerbPQ/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

PQ-Kerberos re-implements the classic Kerberos AS → TGS → AP exchange with
**Kyber-768 (NIST FIPS 203)** for key encapsulation and **Dilithium-3 (NIST
FIPS 204)** for signatures, instead of RSA/DH. It ships as a runnable
system daemon, a Linux PAM module (so it can gate `sudo` / `login` / `su`),
and a command wrapper (`pqk-exec`) for protecting individual commands
behind a PQ-Kerberos challenge — plus a live attack simulator that exercises
replay, forgery, and tampering scenarios against the running protocol.

> ⚠️ **This is a reference / educational implementation**, built to
> demonstrate a post-quantum Kerberos flow end-to-end. It has not had a
> third-party security audit. Read [SECURITY.md](SECURITY.md) before
> pointing it at anything other than a lab or VM.

---

## What's actually post-quantum here

| Component | Classical Kerberos | PQ-Kerberos |
|---|---|---|
| Key exchange | RSA / Diffie-Hellman | **Kyber-768** (ML-KEM, FIPS 203) |
| Signatures | RSA / DSA | **Dilithium-3** (ML-DSA, FIPS 204) |
| Session encryption | DES/AES (legacy modes) | **AES-256-GCM** |
| Replay protection | Timestamp | Timestamp + sequence number, composite cache key |

No RSA or ECC appears anywhere in the authentication path.

## Features

- Full **AS-REQ / AS-REP → TGS-REQ / TGS-REP → AP-REQ / AP-REP** exchange
- **PAM module** (`pam_pqkerberos.so`) — drop it into `/etc/pam.d/sudo`,
  `login`, or any service for a second, quantum-resistant auth factor
- **`pqk-exec`** — run any command gated behind a live PQ-Kerberos challenge
  (`pqk-exec cat /etc/shadow`)
- **Attack simulator** — 8 live attacks (replay, MITM/forgery, ticket
  tampering, wrong-service ticket, KEM-ciphertext swap, clock-skew, ...) run
  against the actual daemon, not mocked, each reporting which line of code
  blocked it
- Single fat JAR, systemd service, and a `.deb` package for Debian/Ubuntu/Kali

## Quickstart

### Option A — install the `.deb` (Debian / Ubuntu / Kali, amd64)

```bash
curl -LO https://github.com/nemal2/KerbPQ/releases/latest/download/pqkerberos_<version>_amd64.deb
sudo apt install ./pqkerberos_<version>_amd64.deb
```

This installs the daemon to `/usr/share/pqkerberos/pqkerberos.jar`, the PAM
module, a systemd unit, and the `pqk-exec` / `pqkerberos-login` commands.
Check the [Releases page](https://github.com/nemal2/KerbPQ/releases) for
the exact filename of the latest version.

### Option B — build and install from source

```bash
git clone https://github.com/nemal2/KerbPQ.git
cd KerbPQ
sudo ./scripts/install.sh
```

Requires `default-jdk`, `maven`, `gcc`, and `libpam0g-dev` — the installer
installs these for you via `apt`.

### Run it

```bash
sudo systemctl start pqkerberos
journalctl -fu pqkerberos     # watch the live protocol exchange
```

or run it in the foreground to watch every step as it happens:

```bash
sudo java -jar /usr/share/pqkerberos/pqkerberos.jar
```

## Demo walkthrough

Open two terminals. **Terminal A** runs the daemon:

```bash
sudo java -jar /usr/share/pqkerberos/pqkerberos.jar
```

**Terminal B** drives the scenarios:

```bash
# --- Alice logs in normally ---
pqkerberos-login alice          # password: alice123

# --- Without protection, secrets are just... readable ---
cat ~/company_secrets.conf

# --- With pqk-exec, the same read requires PQ-Kerberos auth ---
pqk-exec cat ~/company_secrets.conf     # fails without the right password
pqk-exec cat ~/company_secrets.conf     # succeeds once authenticated

# --- Sensitive system files can require BOTH sudo and PQ-Kerberos ---
sudo pqk-exec cat /etc/shadow

# --- Attack simulator against the live daemon ---
pqkerberos-demo attacks
```

Demo credentials (`/etc/pqkerberos/users.conf`, change before real use):

| User | Password |
|---|---|
| alice | alice123 |
| bob | bob456 |

Watch Terminal A during any of this — it prints the full AS/TGS/AP exchange
(Kyber keygen, Dilithium signature verification, ticket decryption) for
every request.

See [docs/GUIDE.md](docs/GUIDE.md) for the full setup guide, PAM
integration options, architecture diagram, and troubleshooting.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  pqkerberos.jar  (SystemDaemon)                               │
│                                                                │
│   KDC / AS  :8888   KDC / TGS  :8889   FileService  :9999     │
│                                                                │
│   PAMAuthDaemon 127.0.0.1:7777  ← username:password over TCP  │
│   (runs the full PQ-Kerberos exchange internally)             │
└───────────────────────▲────────────────────────────────────────┘
                        │
        ┌───────────────┴────────────────┐
        │                                │
 pam_pqkerberos.so                pqkerberos-login / pqk-exec
 (sudo, login, su, ...)           (direct TCP client scripts)
```

## Repository layout

```
├── src/main/java/pqkerberos/   Java sources (KDC, client, PAM daemon, crypto, attack sim)
├── pam/                        C PAM module (pam_pqkerberos.c) + Makefile
├── scripts/                    install.sh, uninstall.sh, build-deb.sh, pqk-exec, pqkerberos-login
├── packaging/deb/              Debian package skeleton (control, postinst, systemd unit, pam.d)
├── docs/GUIDE.md               Full setup guide, demo script, troubleshooting
└── pom.xml                     Maven build (fat JAR via assembly plugin)
```

## Building the `.deb` yourself

```bash
sudo apt install -y default-jdk maven gcc libpam0g-dev dpkg-dev
./scripts/build-deb.sh          # -> dist/pqkerberos_<version>_amd64.deb
```

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please read [SECURITY.md](SECURITY.md) — in particular, the demo user
store is **plaintext** by design (it's a protocol demo, not a credential
vault) and this project has not been independently audited.

## License

[MIT](LICENSE)
