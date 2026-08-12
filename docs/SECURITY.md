# Security model (v0.0.8-security-gate)

v0.0.8-security-gate is intentionally in Safe Mode and does not modify firewall, DNS, policy-routing or engine dataplane rules.

Implemented now:

- UI listener is bound by the Entware init script to a detected private LAN address, not intentionally exposed on WAN.
- A random 256-bit administrator token is created locally with mode `0600`.
- Every state-changing request requires Bearer authentication, JSON content type and a matching browser Origin.
- The Web UI keeps the token only in the current tab's `sessionStorage`; read-only endpoints do not return engine secrets.
- restrictive browser security headers (CSP, frame denial, no-referrer, Permissions-Policy).
- request body limits for mutable API calls.
- source IDs are predefined; the browser cannot submit arbitrary fetch URLs.
- HTTPS-only source registry.
- source byte limits, syntax validation and atomic cache replacement.
- config files installed with mode 0600.
- Safe Mode rejects live dataplane writes while retaining validated drafts.

Required before active routing:

- privilege separation between Web manager and dataplane helper where feasible,
- per-engine adapters with strict command allowlists; no arbitrary shell from Web input,
- signed RAZVILKA catalog/update manifests,
- transactional rollback watchdogs and last-known-good startup generation per engine,
- expanded real-hardware fault and recovery tests.

If cookie-based login sessions are introduced later, they must add CSRF tokens; the current API uses an explicit Bearer header plus Origin validation instead of ambient cookie credentials.
