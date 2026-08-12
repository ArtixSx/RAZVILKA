# Security Policy

RAZVILKA is a network control plane. Security issues may affect routing, credentials, proxy profiles, or router availability.

## Current status

The project is pre-release. Safe Mode is the default and active dataplane changes remain gated until authentication, CSRF protection, rollback, version checks, and real-hardware tests are complete.

## Reporting a vulnerability

Please do not publish credentials, private proxy URIs, WireGuard keys, cookies, router backups, or private network topology in a public issue.

For now, open a GitHub issue containing only non-sensitive reproduction details and explicitly mark it as a security report. A private reporting channel can be added before the first public stable release.

## Secrets

Never commit real sing-box/Xray proxy credentials, WARP/WireGuard private keys, router passwords, session cookies, or exported production configs.
