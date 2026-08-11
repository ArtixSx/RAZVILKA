# Security model (prototype)

v0.0.2 is intentionally Safe Mode and does not modify dataplane rules.

Implemented now:

- UI listener is bound by the Entware init script to a detected private LAN address, not intentionally exposed on WAN.
- restrictive browser security headers (CSP, frame denial, no-referrer, Permissions-Policy).
- request body limits for mutable API calls.
- source IDs are predefined; the browser cannot submit arbitrary fetch URLs.
- HTTPS-only source registry.
- source byte limits, syntax validation and atomic cache replacement.
- config files installed with mode 0600.

Required before active routing:

- login/session authentication,
- CSRF tokens for all state changes,
- privilege separation between Web manager and dataplane helper where feasible,
- command allowlist only; no arbitrary shell from Web input,
- signed RAZVILKA catalog/update manifests,
- rollback watchdog and last-known-good startup generation.
