# PQ-Kerberos — Full Setup & Demo Guide

This covers building from source, installing the PAM module, wiring it into
`sudo`, and running the demo/attack scenarios. For a quick install via
`.deb`, see the main [README](../README.md).

---

## 1. What's in the protocol

- **Kyber-768** (NIST FIPS 203 / ML-KEM) for key encapsulation.
- **Dilithium-3** (NIST FIPS 204 / ML-DSA level 3) for signatures.
- **AES-256-GCM** for session/ticket encryption (128-bit quantum security
  margin via Grover's algorithm).
- A composite replay-cache key (`clientId + timestamp + sequenceNumber`),
  stronger than a timestamp-only cache.
- KEM ciphertexts are signed, so swapping a Kyber ciphertext in transit is
  caught by signature verification, not just by decryption failing.

### Known gap

`ASRequest.isExpired()` currently only rejects timestamps that are too
**old** — it accepts timestamps arbitrarily far in the **future**. This is
deliberately left in and exercised by Attack 8 in the attack simulator, as
an example of a real, easy-to-miss protocol bug. The one-line fix:

```java
// Current — accepts future timestamps:
return (Instant.now().toEpochMilli() - timestamp) / 1000 > 300;

// Fixed — rejects both old AND far-future timestamps:
long ageSec = (Instant.now().toEpochMilli() - timestamp) / 1000;
return ageSec > 300 || ageSec < -300;
```

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Host / VM                                                   │
│                                                               │
│  Terminal A (daemon):                                        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  SystemDaemon (java -jar pqkerberos.jar)             │    │
│  │                                                       │    │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────┐     │    │
│  │  │ KDC AS   │  │ KDC TGS  │  │ FileService    │     │    │
│  │  │ :8888    │  │ :8889    │  │ :9999          │     │    │
│  │  └──────────┘  └──────────┘  └────────────────┘     │    │
│  │                                                       │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │  PAMAuthDaemon  127.0.0.1:7777              │    │    │
│  │  │  Receives username:password over TCP         │    │    │
│  │  │  Runs the full PQ-Kerberos exchange          │    │    │
│  │  │  Returns OK:principal or FAIL:reason         │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
│                            ▲                                 │
│                            │ TCP :7777                       │
│  ┌────────────────────────────────────────────────────┐     │
│  │  pam_pqkerberos.so  (loaded by libpam)              │     │
│  │  Called when:  pamtester / sudo / login / su        │     │
│  └────────────────────────────────────────────────────┘     │
│                                                               │
│  Terminal B (client):                                        │
│    pqkerberos-login alice      ← direct TCP client script   │
│    pamtester pqkerberos alice authenticate  ← via PAM stack │
│    pqkerberos-demo attacks     ← attack simulator            │
└─────────────────────────────────────────────────────────────┘
```

## 3. Building and installing from source

### 3.1 Prerequisites

```bash
sudo apt update
sudo apt install -y default-jdk maven gcc libpam0g-dev libpam-runtime pamtester netcat-openbsd
java -version     # 17+
mvn -version
gcc --version
```

### 3.2 One-shot install

```bash
git clone https://github.com/nemal2/KerbPQ.git
cd KerbPQ
sudo ./scripts/install.sh
```

This builds the fat JAR, builds and installs the PAM module, writes
`/etc/pam.d/pqkerberos`, creates `/etc/pqkerberos/users.conf` with demo
users, installs `pqkerberos-login` / `pqk-exec` / `pqkerberos-demo` /
`pqkerberos-attack`, and installs (but does not start) a systemd service.

### 3.3 Manual build (if you want to see each step)

```bash
mvn clean package
ls -lh target/pqkerberos.jar

cd pam
make
sudo make install
ls -la /lib/x86_64-linux-gnu/security/pam_pqkerberos.so
cd ..

sudo cp packaging/deb/etc/pam.d/pqkerberos /etc/pam.d/pqkerberos

sudo mkdir -p /etc/pqkerberos
sudo tee /etc/pqkerberos/users.conf << 'EOF'
alice=alice123
bob=bob456
EOF
sudo chmod 600 /etc/pqkerberos/users.conf
```

## 4. Running it

```bash
# Terminal A
sudo java -jar target/pqkerberos.jar
```

You should see key generation (slow the first time — a couple of seconds
is normal for Kyber-768 + Dilithium-3), then all four services come up:
KDC AS (`:8888`), KDC TGS (`:8889`), FileService (`:9999`), and the PAM
socket (`127.0.0.1:7777`, loopback only).

```bash
# Terminal B
pqkerberos-login alice      # password: alice123
pqkerberos-login bob        # password: bob456
pqkerberos-login alice      # wrong password → clean rejection
```

Watch Terminal A for the full AS → TGS → AP exchange on every login.

### Raw protocol test (no helper script)

```bash
echo "alice:alice123" | nc -q 2 127.0.0.1 7777     # -> OK:alice@PQKERBEROS.REALM
echo "alice:wrongpass" | nc -q 2 127.0.0.1 7777    # -> FAIL:Authentication failed
echo "nobody:password" | nc -q 2 127.0.0.1 7777    # -> FAIL:Unknown user
```

### Via the PAM stack

```bash
sudo pamtester pqkerberos alice authenticate
```

## 5. Demo scenario: protecting files with `pqk-exec`

```bash
echo "db_password=example" > ~/company_secrets.conf
echo "alice : \$85,000" > ~/payroll.txt

# Without protection, anyone at the terminal can read these:
cat ~/company_secrets.conf

# With pqk-exec, reading requires a live PQ-Kerberos challenge:
pqk-exec cat ~/company_secrets.conf     # prompts for password, then runs the command

# Sensitive system files can require BOTH sudo and PQ-Kerberos:
sudo pqk-exec cat /etc/shadow
```

## 6. Full PAM integration (`sudo` second factor)

> ⚠️ Test in a VM. Misconfiguring PAM can lock you out of `sudo`. Keep a
> root terminal open while editing PAM configs, and prefer `optional`
> over `required` while you're testing.

Edit `/etc/pam.d/sudo` and add one line after the first `@include`:

```
# /etc/pam.d/sudo
@include common-auth
auth    optional    pam_pqkerberos.so
@include common-account
@include common-session-noninteractive
```

Then, in the **same terminal** (keep it open):

```bash
sudo ls /root
# prompts for both the system password AND the PQ-Kerberos password
```

## 7. Attack simulator

With the daemon running:

```bash
pqkerberos-demo attacks
# or: java -cp target/pqkerberos.jar pqkerberos.Demo attacks
```

This runs 8 attacks against the **live** KDC and FileService — replay,
signature forgery/MITM, ticket bit-flip tampering, wrong-service ticket,
KEM-ciphertext swap, and clock-skew/timestamp manipulation (the one
documented gap) — and reports which line of code blocked each one.

### One-shot demo, no daemon or PAM required

`Demo.java` can start its own embedded KDC and service for a portable demo
on any machine with Java installed:

```bash
java -cp target/pqkerberos.jar pqkerberos.Demo
java -cp target/pqkerberos.jar pqkerberos.Demo attacks
```

## 8. Troubleshooting

**"Cannot connect to 127.0.0.1:7777"** — the daemon isn't running:
`sudo systemctl start pqkerberos` or `java -jar target/pqkerberos.jar`.

**"Unknown user: alice"** — the user isn't in `/etc/pqkerberos/users.conf`,
or the daemon needs restarting after you edited that file.

**`NoSuchAlgorithmException` for Kyber/Dilithium** — the BouncyCastle
provider isn't registering correctly. Try:
```bash
java -Djava.security.properties=/dev/null -jar target/pqkerberos.jar
```
If it still fails, try `bc.version` `1.72` in `pom.xml` instead of `1.77`.

**PAM module not found** —
```bash
ls /lib/x86_64-linux-gnu/security/pam_pqkerberos.so
cd pam && sudo make install
```
On ARM64 (e.g. Apple-silicon VMs), change `PAM_DIR` in `pam/Makefile` to
`/lib/aarch64-linux-gnu/security`.

**Slow startup (several seconds)** — normal. Kyber-768 and Dilithium-3 key
generation is deliberately not optimized away; keys are then reused until
the daemon restarts.

**`pamtester` says "auth stack did not pass"** — check the log:
```bash
journalctl -f | grep pam_pqkerberos
```
Common causes: daemon not running, wrong password in `users.conf`, or the
Linux user doesn't exist on the box (`sudo useradd alice`).

## 9. Suggested live-demo order (~8 minutes)

1. Start the daemon — show PQ keygen happening.
2. `pqkerberos-login alice` — walk through the 6-step exchange in the
   daemon's terminal.
3. `pqkerberos-login alice` with the wrong password — clean rejection.
4. `pamtester pqkerberos alice authenticate` — same flow via PAM.
5. `echo "alice:alice123" | nc 127.0.0.1 7777` — raw protocol, no helpers.
6. `pqkerberos-demo attacks` — walk through 2–3 attacks with commentary,
   and call out the future-timestamp gap in Attack 8 explicitly.
