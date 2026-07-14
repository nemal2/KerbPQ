# Security

PQ-Kerberos is a **reference / educational implementation** of a
Kerberos-style protocol over post-quantum primitives. It's built to be
readable and demonstrable end-to-end, not to be a hardened credential
store. Please read this before using it outside a lab or VM.

## Known limitations (by design, not oversights)

- **`/etc/pqkerberos/users.conf` stores passwords in plaintext.** This is a
  demo user store for the protocol exchange, not a password vault. Do not
  reuse real account passwords in it, and restrict its permissions
  (the installer sets `chmod 600`, root-owned).
- **The PAM socket (`127.0.0.1:7777`) is loopback-only** but unauthenticated
  at the transport level beyond the PQ-Kerberos exchange itself — anything
  running as a local user that can reach the loopback interface can talk to
  it. Don't expose it beyond loopback.
- **Clock-skew handling is incomplete.** The current expiry check accepts
  timestamps that are unexpectedly far in the future, not just ones that are
  too old. This is called out deliberately in the attack simulator
  (Attack 8) as a known gap, along with the one-line fix. See
  [`docs/GUIDE.md`](docs/GUIDE.md#known-gap) for the fix.
- **No independent security audit** has been performed on the protocol
  implementation, the PAM module (C code, always higher stakes), or the
  packaging scripts. Treat this as you would any unaudited crypto code.
- **PAM integration can affect system login.** Adding `pam_pqkerberos.so`
  to `/etc/pam.d/sudo` or similar stacks incorrectly can lock you out.
  Always keep a root shell open while testing PAM changes, and prefer
  `optional` over `required` while experimenting.

## Reporting a vulnerability

If you find a security issue in the protocol logic, the PAM module, or the
packaging, please open a GitHub issue with the `security` label, or contact
the maintainer directly via the profile listed on the repository, rather
than filing a public issue with exploit details for anything that could
affect real deployments. There is no bug bounty — this is a personal/
educational project.

## Recommended safe usage

- Run it in a disposable VM or container, not a production or shared host.
- Change the demo credentials before showing this to anyone else.
- If you build on this for a real system, get the crypto and PAM module
  independently reviewed first — particularly the C code, which runs with
  the privileges of whatever process loads it.
