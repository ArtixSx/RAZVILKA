# Changelog

## v0.0.9-ui-layout — compact, non-overlapping control panels

- Fixed sticky panel headers being offset inside clipped panels and covering the first rows of Services, Connections, Engines and Test Lab.
- Removed viewport-forced minimum heights from full-page panels and the engine workspace so pages size to their real content.
- Reduced the oversized Devices empty state while retaining a readable responsive minimum.
- Added versioned asset URLs to prevent a router upgrade from reusing stale CSS or JavaScript from browser cache.
- Added embedded Web UI regression tests for panel-header positioning, forced heights and cache keys.

## v0.0.8-security-gate — authenticated control plane hardening

- Added a persistent random 256-bit administrator token with owner-only permissions.
- Protected every state-changing API request with Bearer authentication, JSON content type and browser Origin validation.
- Added Web UI token prompting with tab-scoped session storage and fixed a stored-XSS path in service route labels.
- Made config-store updates transactional so concurrent writes cannot lose revisions or corrupt JSON.
- Added exact /proc process detection, negative init-status handling and timeouts to prevent false engine readiness.
- Restricted routes to selectable installed adapters and safe bounded profile IDs; AUTO now skips unavailable engines.
- Serialized engine config operations, added native-validator timeouts, fsync staging/apply and unique backups.
- Added strict config schema inspection, read-only `-check`, atomic `-migrate-config` and rejection of unknown/future schemas.
- Added a transactional Entware upgrader with dry-run, explicit ARTEM Flow handover, root-only snapshots and automatic rollback on failed health checks.
- Added an init boot-loop guard plus an exact built-in HTTP health check with a four-second timeout and RAZVILKA/version/PID identity verification.
- Added an explicit rollback command that restores the previous binary, init, config, catalog, sources, token and prior running service state.
- Added a CI transaction test, also verified on ARM64 BusyBox, for dry-run, apply, snapshot modes, port-conflict auto-rollback, manifest injection, path traversal and manual rollback.
- Replaced the incompatible Entware BusyBox wget bootstrap probe and made uninstall restore the recorded pre-install snapshot instead of orphaning a disabled legacy service.
- Prefer Entware's `/opt/bin/sh` for shell validation because Keenetic's system `/bin/sh` rejects the POSIX `-n` check.
- Added tested candidate lifecycle scripts based on BusyBox `start-stop-daemon`, without a `nohup` dependency.
- Hardened source refresh against path traversal, HTTPS downgrade redirects, concurrent temp collisions and tampered startup cache.
- CI now rejects unformatted source and runs the Go race detector.
- Updated CI and release builds to Go 1.26.5, Node.js 24 and SHA-pinned official GitHub Actions with non-persistent checkout credentials.
- Fixed release MIPS and MIPSLE binaries to use the Entware-compatible `softfloat` ABI.
- Added security, concurrency, timeout, route, process and cache regression tests.

## v0.0.7-control-lab — RAZVILKA GitHub foundation

- Project renamed to **RAZVILKA**.
- Binary/runtime paths renamed from the internal prototype name to `razvilka`.
- Go module prepared for `github.com/ArtixSx/razvilka`.
- GitHub repository hygiene added: CI, `.gitignore`, security and contribution notes.
- Real Netcraze/Entware lab findings recorded for the next engine-integration iteration:
  - BusyBox `ip` does not support `-br` on the tested router;
  - existing KeeneticOS tunnels/routes can contaminate naive DIRECT tests;
  - per-engine service tests must be route-isolated;
  - runtime logging and lifecycle evidence need to be first-class.
- Follow-up hardening from the first real Netcraze bootstrap:
  - preflight now uses BusyBox-compatible `ip -o` commands;
  - external tunnel routes are surfaced as possible Test Lab contamination;
  - bootstrap creates its log directory before the first redirected preflight;
  - `rc.func` is required before install;
  - installer no longer hides a failed manager start.

## v0.0.6-control-lab — internal prototype

- Service selectors with desired/planned/applied state.
- Config Center with staged validation and Safe Mode write gate.
- Current-routing service probe and non-faked route matrix readiness states.
- Multi-architecture Entware lab bootstrap and preflight.
