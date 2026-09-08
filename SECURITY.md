# Security Policy

RAZVILKA is a network control plane. Security issues may affect routing, credentials, proxy profiles, or router availability.

## Current status

`v0.18.1-rc.2` is a prerelease for public testing; `v0.18.0` remains the latest
stable-tagged release. The current acceptance scope and open hardware scenarios
are listed in the [release notes](docs/releases/0.18.1-rc.2.md).
Safe Mode is the default on a new installation; explicit Active Apply
uses command-allowlisted transactional adapters, native validation, health
evidence, reverse rollback and committed-plan boot recovery. Local registration,
PBKDF2 passwords, revocable sessions, Origin/JSON checks, encrypted private
backups and privacy-safe diagnostics are implemented.

Release bundles receive GitHub/Sigstore artifact attestations. `1.0.0` remains
blocked on the documented cross-architecture, power-loss, low-memory and LAN
security hardware matrix.

## Reporting a vulnerability

Please do not publish credentials, private proxy URIs, WireGuard keys, cookies, router backups, or private network topology in a public issue.

For now, open a GitHub issue containing only non-sensitive reproduction details and explicitly mark it as a security report. A private reporting channel can be added before the first public stable release.

## Secrets

Never commit real sing-box/Xray proxy credentials, WARP/WireGuard private keys, router passwords, session cookies, or exported production configs.
