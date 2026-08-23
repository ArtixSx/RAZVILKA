# Security model (`v0.10.0`)

RAZVILKA runs locally on a router and may control privileged networking objects. Safe Mode is enabled by default, but an administrator can explicitly enable transactional Active Apply.

## Control plane

- Entware init binds the UI to a detected private LAN address, not intentionally to WAN.
- First install creates a 256-bit recovery key (`0600`) and prints a setup/recovery URL; the user then creates a separate RAZVILKA login/password.
- SSH/Entware/router credentials are never read or reused.
- Passwords use PBKDF2-SHA256; sessions are time-limited `HttpOnly`, `SameSite=Strict` cookies and can be revoked.
- Login attempts are throttled by source IP. Mutations additionally require JSON and a matching browser Origin.
- CSP, frame denial, no-referrer, Permissions-Policy and bounded request bodies reduce browser attack surface.

## Dataplane

- Browser input selects allowlisted service/route IDs; it cannot submit shell commands, file paths, executable names or arbitrary probe URLs.
- Every Active Apply freezes a deterministic plan and runs snapshot, stage, native validation, activation, health and commit under one operation lock.
- Any failure rolls prepared adapters back in reverse order. Boot recovery acts only on the last committed plan.
- Runtime files, processes, interfaces, tables and rule priorities are namespaced. Deactivation targets exact recorded RAZVILKA ownership.
- Tunnel/proxy endpoints are checked against routed prefixes to prevent self-loop; TUN sidecars do not own the default route. sing-box 1.14+ DNS mode is explicitly disabled for the managed sidecar.
- NFQWS2 uses bounded managed blocks in official list files and the official init lifecycle; it does not claim exclusive ownership of a third-party NFQWS2 installation.

## Data and supply chain

- Source URLs are fixed by local registries, HTTPS-only, redirect-allowlisted, size-limited, syntax-validated and atomically cached.
- Public profile export rejects known secret files/content. Private backup uses AES-256-GCM, PBKDF2-HMAC-SHA256, random salt/nonce and an authenticated SHA-256-sealed payload.
- Diagnostic export omits credentials, config contents, device identity, source scopes, history and public IP data.
- Release CI publishes checksums and GitHub/Sigstore artifact attestations. `usque-keenetic` is installed through its fixed opkg feed; the external `wgcf` binary requires the checksum shipped in the same official upstream release.
- The Web UI checks the official RAZVILKA GitHub release only on user request and never executes a root update automatically.

## Remaining `1.0.0` gate

The code-level controls do not replace LAN penetration, power-loss, low-memory, multi-engine and cross-architecture tests on real Keenetic/Netcraze hardware. See [PRODUCT_GAPS_RU.md](PRODUCT_GAPS_RU.md).
