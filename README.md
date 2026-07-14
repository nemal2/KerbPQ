# 🔐 PQ-Kerberos

**Post-quantum Kerberos authentication — Kyber-768 (ML-KEM) · Dilithium-3 (ML-DSA) · AES-256-GCM**

[![CI](https://github.com/nemal2/KerbPQ/actions/workflows/ci.yml/badge.svg)](https://github.com/nemal2/KerbPQ/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nemal2/KerbPQ?label=release)](https://github.com/nemal2/KerbPQ/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A working reimplementation of the classic Kerberos protocol (AS → TGS → Service, all 6 message exchanges) with every quantum-vulnerable primitive swapped for a NIST-standardized post-quantum equivalent:

| Classical Kerberos | PQ-Kerberos |
|---|---|
| RSA / Diffie-Hellman | **Kyber-768 (ML-KEM, FIPS 203)** |
| ECDSA signatures | **Dilithium-3 (ML-DSA, FIPS 204)** |
| AES-128 | **AES-256-GCM** |
| SHA-1/MD5 | **HKDF-SHA256** |

Includes a runnable KDC, a file service, a client, and an **8-scenario attack simulator** (replay, MITM/signature forgery, ticket tampering, expired-ticket reuse, wrong-service ticket, KEM ciphertext swap, enumeration, clock-skew) that shows exactly which defense stops each attack.

📖 **[Read the full beginner-to-advanced guide → GUIDE.md](GUIDE.md)** — explains every field, every check, and every design decision from first principles.

---

## ⚠️ Security notice — please read before deploying anywhere

This is a **research / educational demonstration**, not a production-hardened authentication system. Known gaps, documented in [GUIDE.md, Chapter 9](GUIDE.md):

- **Java native serialization** (`ObjectInputStream`) is used on the wire for all protocol messages. This is a well-known deserialization attack surface. Do not expose the KDC/service ports to an untrusted network.
- No rate limiting or account lockout on the AS.
- A future-timestamp clock-skew check is documented as a known gap (see Attack 8 in the simulator).
- No production key management / PKI — keys are generated fresh in memory on each run.

**By default, everything binds to `localhost` and is meant to be run and explored on your own machine.** Treat it as a teaching tool and a base for experimentation, not something to put on the internet.

---

## Quick start

### Option 1 — Download and run (no build tools needed)

Grab the latest release: **[github.com/nemal2/KerbPQ/releases](https://github.com/nemal2/KerbPQ/releases)**

```bash
# Just need a JRE 17+ installed
java -jar pqkerberos-<version>-all.jar          # normal auth demo
java -jar pqkerberos-<version>-all.jar attacks  # + 8 attack simulations
```

### Option 2 — Debian / Ubuntu `.deb` install

```bash
wget https://github.com/nemal2/KerbPQ/releases/latest/download/pqkerberos_<version>_amd64.deb
sudo dpkg -i pqkerberos_<version>_amd64.deb
pqkerberos attacks
```

### Option 3 — Build from source

```bash
git clone https://github.com/nemal2/KerbPQ.git
cd KerbPQ
./run.sh              # builds with Maven and runs the demo
./run.sh attacks       # same, plus the attack simulator
```

Or manually:
```bash
mvn clean package
java -jar target/pqkerberos-*.jar attacks
```

Requires **JDK 17+** to build (JRE 17+ is enough to just run the released jar).

---

## What you'll see

Running the demo spins up, in-process:

- A **KDC** (Key Distribution Center) on ports `8888` (AS) and `8889` (TGS)
- A **FileService** on port `9999`
- A **client** ("alice") that runs the full 6-step exchange: AS-REQ → AS-REP → TGS-REQ → TGS-REP → AP-REQ → AP-REP

Every step prints what's happening and why — Kyber key encapsulation, Dilithium signature verification, AES-GCM ticket encryption/decryption, and the final mutual-authentication proof.

Add `attacks` to also run 8 live attacks against the running protocol and see exactly which check blocks each one.

---

## Project structure

```
src/main/java/pqkerberos/
  PQCrypto.java           # All crypto primitives: Kyber, Dilithium, AES-GCM, HKDF
  ProtocolMessages.java   # All wire message types (ASRequest, TGT, tickets, etc.)
  MessageIO.java          # Socket serialization helpers
  KDCServer.java          # Authentication Server + Ticket Granting Server
  PQKerberosClient.java   # Client-side protocol flow
  FileService.java        # Example service with the 8 ticket-validation checks
  Demo.java               # Runs the full end-to-end demo
  AttackSimulator.java    # 8 attack scenarios against the live protocol

packaging/
  build-deb.sh            # jpackage script → produces the .deb
  pam_pqkerberos.c         # OPTIONAL: PAM module stub for OS-level login integration
  Makefile                 # Builds the PAM module (separate from the Java release)

GUIDE.md                  # Full beginner-to-advanced protocol walkthrough
```

> **Note on the PAM module:** `packaging/pam_pqkerberos.c` is an experimental extra that expects a separate daemon listening on `127.0.0.1:7777` — that daemon isn't part of this release yet. Treat the PAM module as a design sketch for OS login integration, not a supported feature. It is not built or installed by the `.deb`.

---

## Algorithms & sizes reference

| Scheme | Purpose | Public Key | Private Key | Output | Quantum-safe |
|---|---|---|---|---|---|
| Kyber-768 | Key exchange (KEM) | 1,184 B | 2,400 B | 1,088 B ciphertext | ✅ |
| Dilithium-3 | Digital signature | 1,952 B | 4,000 B | 3,293 B signature | ✅ |
| AES-256-GCM | Symmetric encryption | — | 32 B key | +28 B overhead | ✅ |
| HKDF-SHA256 | Key derivation | — | — | 32 B | ✅ |

Both Kyber and Dilithium are NIST-standardized (FIPS 203 / FIPS 204) and based on lattice problems (Module-LWE), which have no known quantum speedup — Shor's algorithm, which breaks RSA and ECC, doesn't apply here.

---

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Good first areas: the future-timestamp clock-skew gap, rate limiting on the AS, and swapping `ObjectInputStream` for a safer wire format (e.g. Protocol Buffers).

## License

[MIT](LICENSE) — see file for details.
