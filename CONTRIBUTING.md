# Contributing to PQ-Kerberos

Thanks for your interest — this project started as a learning exercise in post-quantum cryptography and Kerberos internals, and contributions that improve its correctness, security, or clarity are welcome.

## Getting set up

```bash
git clone https://github.com/nemal2/KerbPQ.git
cd KerbPQ
mvn clean package
java -jar target/pqkerberos-*.jar attacks
```

Requires JDK 17+.

## Good first contributions

These are documented, known gaps (see `GUIDE.md`, Chapter 9 and the Attack Simulator):

- **Future-timestamp clock skew bug** — `isExpired()` in `ProtocolMessages.java` only rejects old timestamps, not far-future ones. See Attack 8 in `AttackSimulator.java` for the exact fix needed.
- **No rate limiting** on `KDCServer`'s AS endpoint.
- **Java native serialization** (`MessageIO.java` uses `ObjectInputStream`) is a known deserialization risk. A PR migrating the wire format to something safer (Protocol Buffers, a hand-rolled binary format, etc.) would be a significant, welcome improvement.
- **In-memory replay cache** doesn't survive a KDC restart — could be backed by Redis or similar.

## Reporting a security issue

This is a demo project, not a hardened product — see the Security Notice in the README. That said, if you find a flaw in the *protocol logic itself* (as opposed to the already-documented deployment gaps above), please open an issue describing it. No need for private disclosure on a project explicitly labeled research/educational.

## Pull requests

- Keep changes focused — one concern per PR.
- If you touch `PQCrypto.java` or the protocol message flow, please explain the security reasoning in the PR description, not just the code change.
- Match the existing style (the codebase favors explicit, readable steps over cleverness — see `GUIDE.md` for the reasoning behind that).

## Code of conduct

Be respectful. Assume good faith. That's it.
