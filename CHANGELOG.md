# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — Unreleased

### Added
- Initial public packaging: Maven fat JAR, PAM module, systemd service,
  `.deb` package, `pqk-exec` / `pqkerberos-login` command wrappers.
- GitHub Actions CI (build + PAM module compile check) and release
  workflow (builds and attaches `.deb` + `.jar` to tagged releases).
- `docs/GUIDE.md` full setup/demo guide, `SECURITY.md` disclosures,
  `CONTRIBUTING.md`.

### Known issues
- `ASRequest.isExpired()` accepts far-future timestamps in addition to
  rejecting old ones — see Attack 8 in the attack simulator and
  [`docs/GUIDE.md`](docs/GUIDE.md#known-gap) for the one-line fix.
