# RAZVILKA roadmap

## Completed milestones

- `v0.0.2–v0.0.10`: source/control plane, clean Entware Lab, service selectors, honest telemetry model, multi-architecture CI, security gate, transactional installer and component versions/updates.
- `v0.1.0`: registration/password UI, installer-visible recovery URL, service-first redesign, guided/expert engine editors, custom services, WARP generator and one-command install.
- `v0.2.0`: allowlisted community catalog, provenance/conflict preview and guarded WARP candidate rotation.
- `v0.3.0`: Engine Lab, isolated evidence, persistent Smart Route, session controls and 35 Russia-oriented manifests.
- `v0.4.0`: secret-free profile exchange, draft-only preview/import, recovery-key reset/reissue and domain/IP inspector.
- `v0.5.0–v0.5.1`: deterministic dataplane plan, ownership, preflight/blockers and truthful installed/configured/running/Safe Mode state.
- `v0.9.0–v0.9.1`: active transactional adapters, recovery, device policy,
  diagnostics, release verification and real-Keenetic compatibility fixes.
- `v0.10.0`: z2k discovery/NFQUEUE ownership protection, guided Safe Mode
  results, resilient WARP registration and user-facing «Обходы» terminology.

## `v0.11.0` — on-demand bypasses and Strategy Lab

The tracked implementation, router-test matrix and release gate are maintained
in [V0.11.0_RELEASE_PLAN_RU.md](V0.11.0_RELEASE_PLAN_RU.md).

Key scope: UI-only base install, on-demand bypass lifecycle, NFQWS2 strategy
selection, safe z2k migration, real router resource/traffic metrics, simplified
first-run UI and expert Strategy Lab.

## `v0.9.0` — software-complete release candidate

- Runtime adapters for NFQWS2, usque, WARP-WG, AmneziaWG, sing-box and Xray.
- One locked transaction: snapshot, stage, native validation, activation, route/service health, adapter commit and reverse rollback.
- Atomic execution/recovery/policy/deactivation journals and committed-plan boot recovery.
- Exact process/PID ownership, isolated interfaces/tables/priorities and endpoint/self-loop guards.
- DNS-to-IP policy refresh, IPv4/IPv6 kernel route evidence and source-scoped device policies for tunnel adapters.
- LAN device discovery/names/groups and confirmed conntrack Connections producer.
- Encrypted private backup, privacy-safe diagnostic report and official application update notification.
- GitHub/Sigstore artifact attestations for release bundles.
- Graceful shutdown, slower-router recovery allowance and non-blocking transaction status.

## `v0.9.x` — hardware release-candidate fixes

Only evidence-driven fixes found by the release matrix belong here. Compatible corrections increment the patch (`0.9.1`, `0.9.2`). A format/behavior redesign increments the minor.

Required matrix:

- ARM64 plus MIPS or MIPSLE Keenetic/Netcraze;
- clean install, upgrade, rollback and uninstall;
- NFQWS2, WARP and proxy adapter individually and simultaneously;
- IPv4/IPv6, PPPoE/regular WAN, NFQUEUE/TUN and offload modes;
- power loss/kill at every transaction phase, manager crash and reboot order;
- port/TUN/table/DNS/third-party engine conflicts;
- low-memory/OOM, large lists/conntrack and multi-day soak;
- LAN authentication/origin/permissions/backup/diagnostic security review.

## `v1.0.0` — first mass-use release

Tag only after the supported-device matrix is recorded as passing. The default remains Safe Mode; the UI must never convert desired/planned state into observed evidence.

Post-1.0 candidates:

- priority-aware schema for different routes of the same service on different device groups;
- signed third-party community publisher workflow beyond the attested bundled catalog;
- optional bounded traffic history and richer protocol-aware TCP/UDP/QUIC decisions;
- additional engines only when they implement the same ownership/rollback/evidence contract.
