# Security Policy

RAZVILKA is a network control plane. Security issues may affect routing, credentials, proxy profiles, or router availability.

## Current status

The project is pre-release. v0.0.8-security-gate requires a local Bearer token,
JSON content type and a matching browser Origin for every state-changing request.
The token is generated locally with mode `0600`; secret engine fields are not
returned to the browser.

Safe Mode is the default. Active dataplane changes remain gated until
least-privilege engine adapters, strict command allowlists, signed catalog and
update manifests, per-engine transactional rollback/watchdogs, and expanded
real-hardware validation are complete.

## Reporting a vulnerability

Please do not publish credentials, private proxy URIs, WireGuard keys, cookies, router backups, or private network topology in a public issue.

For now, open a GitHub issue containing only non-sensitive reproduction details and explicitly mark it as a security report. A private reporting channel can be added before the first public stable release.

## Secrets

Never commit real sing-box/Xray proxy credentials, WARP/WireGuard private keys, router passwords, session cookies, or exported production configs.
