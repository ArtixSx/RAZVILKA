# RAZVILKA roadmap

> Актуальный подробный план реализации находится в
> [MASTER_PLAN_RU.md](MASTER_PLAN_RU.md). Этот файл сохраняет историю уже
> выпущенных этапов и релизные ворота.

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
- `v0.11.0–v0.12.x`: on-demand bypasses, Strategy Lab, resource/traffic UI,
  WARP workflow and real-router usability fixes.
- `v0.13.0–v0.14.0`: route-quality evidence, WARP recovery, official Telegram
  CIDR coverage, explicit tunnel roles and pre-Apply transport diagnostics.

## Current development — evidence hardening and adaptive routing

The next implementation sequence is P0 truth/safety, network-aware NFQWS2,
provider/subscription management, the DNS control surface and AutoPilot. See
[MASTER_PLAN_RU.md](MASTER_PLAN_RU.md) for acceptance criteria.

Implemented in the current development cycle: ordered route evidence,
automatic DIRECT controls, Apply conflict gates, a bounded local audit,
Recovery Safe Mode with a boot-loop guard, WAN-scoped Smart Route memory and a
non-live DNS profile/probe/ownership plan. Telegram route tests use several
required scenarios instead of one landing page. Transactional DNS activation
remains deliberately disabled until the platform adapter and rollback are
proven on hardware.

Evidence is now visible per service and per transaction in the UI and in the
privacy-safe diagnostic report. Desired or reviewed plans cannot promote it.
The journal also keeps the latest reviewed plan separate from the last
successfully committed plan, so a Safe Mode preview cannot hide the route used
for reboot recovery or AUTO evidence.

Apply preflight now also reads IPv4/IPv6 policy rules and routing tables in the
adapter-owned ranges. A foreign rule becomes an explicit adapter blocker;
RAZVILKA reports it and never deletes it automatically.

## Implemented dataplane foundation

- Runtime adapters for NFQWS2, usque, WARP-WG, AmneziaWG, sing-box and Xray.
- One locked transaction: snapshot, stage, native validation, activation, route/service health, adapter commit and reverse rollback.
- Atomic execution/recovery/policy/deactivation journals and committed-plan boot recovery.
- Exact process/PID ownership, isolated interfaces/tables/priorities and endpoint/self-loop guards.
- DNS-to-IP policy refresh, IPv4/IPv6 kernel route evidence and source-scoped device policies for tunnel adapters.
- LAN device discovery/names/groups and confirmed conntrack Connections producer.
- Encrypted private backup, privacy-safe diagnostic report and official application update notification.
- GitHub/Sigstore artifact attestations for release bundles.
- Graceful shutdown, slower-router recovery allowance and non-blocking transaction status.

## Hardware release-candidate fixes

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
