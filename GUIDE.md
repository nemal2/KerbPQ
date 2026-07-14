# PQ-Kerberos — Complete Setup & Demo Guide
### Post-Quantum Authentication with Linux PAM Integration
### Kali Linux VM walkthrough

---

## 1. Quality Assessment of the Original Code

**What is genuinely good:**

- The PQC algorithm selection is correct and current — Kyber-768 (NIST FIPS 203) for key
  exchange and Dilithium-3 (NIST FIPS 204) for signatures are exactly what NIST standardised.
  AES-256-GCM for symmetric encryption is the right choice (128-bit quantum security via Grover).
- The attack simulator is thorough and pedagogically honest, including identifying its own gap
  (the future-timestamp clock-skew issue in Attack 8).
- Using KEM instead of DH/RSA is architecturally correct — Kyber's ciphertext is signed,
  so a KEM-ciphertext swap is caught (Attack 6).
- The replay cache uses a composite key (clientId + timestamp + sequenceNumber), which is
  stronger than timestamp-only approaches.
- AES-GCM authenticated encryption means ticket tampering (Attack 3) and wrong-service
  tickets (Attack 5) are caught at the crypto layer even before the explicit checks.

**What was fixed or improved in this package:**

| Issue | Fix |
|---|---|
| `getServiceKeyForDemo()` could generate a second random key on repeat calls | Changed to `computeIfAbsent` — same key returned every time |
| `KDCServer.registerUser()` was private | Added `addKerberosUser(String)` public method |
| No build system | `pom.xml` with Maven assembly plugin (fat JAR) |
| No PAM integration | `PAMAuthDaemon.java` + `pam_pqkerberos.c` |
| No single entry point for "run everything" | `SystemDaemon.java` |

**Known gap (documented in AttackSimulator Attack 8):**

`ASRequest.isExpired()` accepts future timestamps. Fix shown in the attack output; 
applying it to production code is a one-line change:

```java
// Current (accepts future timestamps):
return (Instant.now().toEpochMilli() - timestamp) / 1000 > 300;

// Fixed (rejects both old AND far-future timestamps):
long ageSec = (Instant.now().toEpochMilli() - timestamp) / 1000;
return ageSec > 300 || ageSec < -300;
```

---

## 2. Architecture After This Package

```
┌─────────────────────────────────────────────────────────────┐
│  Kali Linux VM                                              │
│                                                             │
│  Terminal A (daemon):                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  SystemDaemon (java -jar pqkerberos.jar)            │   │
│  │                                                     │   │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────┐   │   │
│  │  │ KDC AS   │  │ KDC TGS  │  │ FileService    │   │   │
│  │  │ :8888    │  │ :8889    │  │ :9999          │   │   │
│  │  └──────────┘  └──────────┘  └────────────────┘   │   │
│  │                                                     │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │  PAMAuthDaemon  127.0.0.1:7777              │   │   │
│  │  │  Receives username:password via TCP         │   │   │
│  │  │  Runs full PQ-Kerberos exchange internally  │   │   │
│  │  │  Returns OK:principal or FAIL:reason        │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                            ▲                                │
│                            │ TCP :7777                      │
│                            │                                │
│  ┌────────────────────────────────────────────────────┐    │
│  │  pam_pqkerberos.so  (loaded by libpam)             │    │
│  │  Called when:  pamtester / sudo / login / su       │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  Terminal B (test):                                         │
│    pqkerberos-login alice      ← bash script, direct TCP   │
│    pamtester pqkerberos alice authenticate   ← PAM stack   │
│    pqkerberos-demo attacks     ← attack simulator          │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Files in This Package

```
pqkerberos/
├── pom.xml                                    ← Maven build (BouncyCastle 1.77)
├── scripts/
│   └── install.sh                             ← One-shot installer
├── pam/
│   ├── pam_pqkerberos.c                       ← C PAM module
│   └── Makefile
└── src/main/java/pqkerberos/
    ├── MessageIO.java                         ← (unchanged from your original)
    ├── PQCrypto.java                          ← (unchanged)
    ├── ProtocolMessages.java                  ← (unchanged)
    ├── FileService.java                       ← (unchanged)
    ├── PQKerberosClient.java                  ← (unchanged)
    ├── AttackSimulator.java                   ← (unchanged)
    ├── Demo.java                              ← (unchanged)
    ├── KDCServer.java                         ← MODIFIED: addKerberosUser() + key fix
    ├── PAMAuthDaemon.java                     ← NEW: PAM bridge daemon
    └── SystemDaemon.java                      ← NEW: starts everything
```

Copy your existing unchanged files into `src/main/java/pqkerberos/`.

---

## 4. Step-by-Step Setup on Kali Linux

### 4.1 Prerequisites (one-time)

Open a root terminal in your Kali VM:

```bash
sudo apt update
sudo apt install -y default-jdk maven gcc libpam0g-dev libpam-runtime pamtester netcat-openbsd
```

Verify:
```bash
java -version     # should show 17 or higher
mvn -version      # should show 3.x
gcc --version
```

### 4.2 Build the project

```bash
# 1. Clone / copy the project somewhere
mkdir -p ~/pqkerberos && cd ~/pqkerberos

# 2. Put all .java files in place
mkdir -p src/main/java/pqkerberos
# Copy every .java file from this package into src/main/java/pqkerberos/
# (MessageIO.java, PQCrypto.java, ProtocolMessages.java, FileService.java,
#  PQKerberosClient.java, AttackSimulator.java, Demo.java,
#  KDCServer.java, PAMAuthDaemon.java, SystemDaemon.java)

# 3. Build the fat JAR
mvn clean package

# You should see:  BUILD SUCCESS
# Output:          target/pqkerberos.jar
ls -lh target/pqkerberos.jar
```

### 4.3 Build and install the PAM module

```bash
cd pam
make
sudo make install
# Should show: Installed pam_pqkerberos.so to /lib/x86_64-linux-gnu/security/
ls -la /lib/x86_64-linux-gnu/security/pam_pqkerberos.so
```

### 4.4 Configure PAM

```bash
sudo tee /etc/pam.d/pqkerberos << 'EOF'
#%PAM-1.0
auth    required    pam_pqkerberos.so
account required    pam_permit.so
EOF
```

### 4.5 Create the user config

```bash
sudo mkdir -p /etc/pqkerberos
sudo tee /etc/pqkerberos/users.conf << 'EOF'
alice=alice123
bob=bob456
EOF
sudo chmod 600 /etc/pqkerberos/users.conf
```

---

## 5. Running the Demo

### Terminal A — Start the daemon

```bash
cd ~/pqkerberos
java -jar target/pqkerberos.jar
```

You should see:
```
╔══════════════════════════════════════════════════════════╗
║   PQ-Kerberos System Daemon                              ║
║   Post-Quantum Authentication Infrastructure             ║
...
[KDC] Generating PQ keypairs...
[KDC] Dilithium-3 signing key generated.
[KDC] Kyber-768 KEM key generated.
[KDC] Keys ready in ~2000 ms          ← PQ keygen is slow first time
[KDC] Registered users: alice, bob
[AS]  Listening on port 8888
[TGS] Listening on port 8889
[System] ✓ FileService running — port:9999
[System] ✓ PAM Daemon running — 127.0.0.1:7777

Services:
  KDC AS      → localhost:8888
  KDC TGS     → localhost:8889
  FileService → localhost:9999
  PAM Socket  → 127.0.0.1:7777  (loopback only)
```

### Terminal B — Test with the login helper

```bash
# Install the helper script
sudo cp scripts/pqkerberos-login /usr/local/bin/
sudo chmod +x /usr/local/bin/pqkerberos-login

# Auth as alice
pqkerberos-login alice
# Password: alice123

# Auth as bob
pqkerberos-login bob
# Password: bob456

# Wrong password
pqkerberos-login alice
# Password: wrongpassword
```

Watch Terminal A — you will see the full PQ-Kerberos exchange for each login:
```
[PAMDaemon] ── Auth request ──────────────────────────
[PAMDaemon] User     : alice
[Client] === PQ-Kerberos authentication ===
[Client] --- Step 1+2: AS Exchange ---
[Client] Kyber-768 keypair generated.
[AS]  Request from: alice@PQKERBEROS.REALM
[AS]  TGT issued to: alice@PQKERBEROS.REALM
[Client] KDC Dilithium-3 signature verified ✓
[Client] Kyber-768 decapsulation successful ✓
[Client] --- Step 3+4: TGS Exchange ---
[TGS] Service ticket: alice@PQKERBEROS.REALM → fileservice@PQKERBEROS.REALM
[Client] --- Step 5+6: AP Exchange ---
[Service] ✓ Client authenticated: alice@PQKERBEROS.REALM
[PAMDaemon] ✓ SUCCESS — full Kerberos exchange completed
```

### Terminal B — Test PAM stack with pamtester

```bash
sudo pamtester pqkerberos alice authenticate
# Enter alice's password when prompted: alice123
# Should output: pamtester: successfully authenticated
```

Watch Terminal A — same full PQ-Kerberos exchange appears.

### Terminal B — Raw protocol test (no helper needed)

```bash
# Test the TCP socket directly
echo "alice:alice123" | nc -q 2 127.0.0.1 7777
# Expected: OK:alice@PQKERBEROS.REALM

echo "alice:wrongpass" | nc -q 2 127.0.0.1 7777
# Expected: FAIL:Authentication failed

echo "nobody:password" | nc -q 2 127.0.0.1 7777
# Expected: FAIL:Unknown user
```

---

## 6. Full PAM Integration (sudo / login)

> ⚠️ **Safety note:** Test in a VM. Misconfiguring PAM can lock you out of sudo.
> Always keep a root terminal open before modifying PAM configs.

### Option A: Add PQ-Kerberos as a second auth factor for sudo

Edit `/etc/pam.d/sudo` and add ONE line after the first `@include`:

```
# /etc/pam.d/sudo
@include common-auth
auth    optional    pam_pqkerberos.so    ← add this line (optional = won't lock out)
@include common-account
@include common-session-noninteractive
```

Then test in the SAME terminal (keep it open):
```bash
sudo ls /root
# You will be prompted for BOTH system password AND PQ-Kerberos password
```

### Option B: Dedicated pqkerberos-protected command

Create a wrapper that requires PQ-Kerberos auth before running anything:

```bash
sudo tee /usr/local/bin/pqk-exec << 'EOF'
#!/usr/bin/env bash
# Run a command only after successful PQ-Kerberos authentication
USERNAME=$(whoami)
read -rs -p "PQ-Kerberos password for $USERNAME: " PASSWORD
echo ""
RESP=$(printf '%s:%s\n' "$USERNAME" "$PASSWORD" | nc -q 2 127.0.0.1 7777 2>/dev/null)
if [[ "$RESP" == OK:* ]]; then
    echo "[PQ-Kerberos] Authenticated: $USERNAME"
    exec "$@"
else
    echo "[PQ-Kerberos] Authentication failed: ${RESP#FAIL:}"
    exit 1
fi
EOF
sudo chmod +x /usr/local/bin/pqk-exec

# Usage:
pqk-exec ls /root
pqk-exec cat /etc/shadow
```

---

## 7. Attack Simulator Demo

The daemon must be running. In Terminal B:

```bash
java -cp target/pqkerberos.jar pqkerberos.Demo attacks
```

Or after installing:
```bash
pqkerberos-demo attacks
```

This runs all 8 attacks against the **live** KDC and FileService and shows exactly
which line of code blocks each one. Expected terminal output:

```
┌─ ATTACK 1: Replay Attack
│  Resend a captured APRequest to the service
└─────────────────────────────────────────────
  ✓ BLOCKED — Replay cache caught duplicate authenticator.

┌─ ATTACK 2: MITM / Signature Forgery
...
  ✓ BLOCKED — PQCrypto.verify() returned false — Dilithium-3 signature mismatch.

┌─ ATTACK 3: Ticket Tampering (Bit-Flip Attack)
...
  ✓ BLOCKED — AES-GCM tag verification failed — ciphertext was tampered.

...

┌─ ATTACK 8: Clock-Skew / Timestamp Manipulation
...
  ⚠ GAP IDENTIFIED: future timestamps pass isExpired() check.
```

---

## 8. One-Shot Demo (No Daemon Needed)

If you just want to show the Kerberos protocol without PAM integration,
`Demo.java` starts its own embedded KDC and service:

```bash
# Normal auth demo
java -cp target/pqkerberos.jar pqkerberos.Demo

# Auth + all attacks
java -cp target/pqkerberos.jar pqkerberos.Demo attacks
```

This is useful for a portable demo on any machine with Java installed — 
no setup required.

---

## 9. Troubleshooting

### "Cannot connect to 127.0.0.1:7777"

The daemon is not running. Start it:
```bash
java -jar target/pqkerberos.jar
# or
systemctl start pqkerberos
```

### "Unknown user: alice"

The user is not in `/etc/pqkerberos/users.conf`. Check the file:
```bash
cat /etc/pqkerberos/users.conf
```

Or make sure the daemon was restarted after editing the file.

### Kyber/Dilithium `NoSuchAlgorithmException`

BouncyCastle provider not loading. Cause: fat JAR has a service file conflict.
Fix — run with explicit provider registration:
```bash
java -Djava.security.properties=/dev/null -jar target/pqkerberos.jar
```

If still failing, try downgrading to BC 1.72 in `pom.xml`:
```xml
<bc.version>1.72</bc.version>
```

### PAM module not found

```bash
ls /lib/x86_64-linux-gnu/security/pam_pqkerberos.so
# If missing:
cd pam && sudo make install
```

On ARM64 Kali (e.g., Apple Silicon VM):
```bash
# Change PAM_DIR in pam/Makefile to:
PAM_DIR = /lib/aarch64-linux-gnu/security
```

### Slow startup (10+ seconds)

Normal — Kyber-768 and Dilithium-3 key generation is intentionally slow on first run.
Subsequent requests are fast (keys are reused until daemon restart).

### pamtester says "auth stack did not pass"

Check syslog to see why:
```bash
tail -f /var/log/auth.log | grep pqkerberos
# or
journalctl -f | grep pam_pqkerberos
```

Common causes:
- Daemon not running → `AUTHINFO_UNAVAIL`
- Wrong password in users.conf
- Linux user doesn't exist (add with `useradd alice`)

---

## 10. Recommended Demo Script (8-minute presentation)

```
Minute 1:   Show SystemDaemon starting — PQ keygen visible
Minute 2:   pqkerberos-login alice — show full 6-step exchange in daemon terminal
Minute 3:   pqkerberos-login alice (wrong password) — show clean rejection
Minute 4:   pamtester pqkerberos alice authenticate — show PAM integration
Minute 5:   echo "alice:alice123" | nc 127.0.0.1 7777 — show raw protocol
Minute 6-8: pqkerberos-demo attacks — walk through attacks 1, 2, 3 with commentary
            Highlight the GAP in attack 8 (future timestamp) — shows intellectual honesty
```

**Key talking points:**
- No RSA, no ECC anywhere — entirely post-quantum
- NIST FIPS 203 + 204 + 197 throughout
- PAM means this slots into any Linux auth stack
- Attack simulator runs against the live system, not a mock
- Service never contacts KDC during auth — Kerberos scalability property
