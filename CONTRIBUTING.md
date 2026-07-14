# Contributing

Thanks for considering a contribution to PQ-Kerberos.

## Getting set up

```bash
git clone https://github.com/nemal2/KerbPQ.git
cd KerbPQ
sudo apt install -y default-jdk maven gcc libpam0g-dev pamtester netcat-openbsd
mvn clean package
make -C pam
```

Run the daemon locally with `java -jar target/pqkerberos.jar`, and the
one-shot protocol demo (no daemon/PAM needed) with:

```bash
java -cp target/pqkerberos.jar pqkerberos.Demo
java -cp target/pqkerberos.jar pqkerberos.Demo attacks
```

## Pull requests

- Keep changes focused — one topic per PR.
- If you touch the protocol logic (`KDCServer`, `ProtocolMessages`,
  `PQCrypto`), run the attack simulator (`Demo attacks`) and confirm
  nothing regresses; note in the PR description which attacks you checked.
- If you touch `pam/pam_pqkerberos.c`, mention how you tested it
  (`pamtester`, a real `sudo`/`login` stack in a VM, etc.) — PAM bugs can
  lock people out of their machine, so test coverage matters more than
  style here.
- Update `docs/GUIDE.md` / `README.md` if you change setup steps, ports, or
  file paths.

## Reporting bugs

Open an issue with:
- What you ran and what you expected
- The daemon log output (Terminal A) around the failure
- Your OS/distro and Java version (`java -version`)

For anything security-sensitive, see [SECURITY.md](SECURITY.md) first.
