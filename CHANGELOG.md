# Changelog

## Unreleased — isolated canary foundation

- Added an adapter-scoped neutral RoutePlan contract. A candidate receives
  only its own services, actions and resource claims, never unrelated routing
  intent or manager journal authority.
- Added a real pre-activation canary phase with rollback-before-activation on
  failure. The existing post-activation health check remains mandatory.
- sing-box, Xray and USQUE/MASQUE now start a temporary loopback-only SOCKS
  candidate on a separate port, verify service egress and remove it before the
  working TUN or policy rules can be changed.
- Plans explicitly report adapters that still lack a separate canary instead
  of presenting post-activation health as equivalent protection.
- Service route drafts and device/source policy drafts now have independent
  Apply and Discard transactions. Applying one page preserves the other page's
  pending fields.
- Dataplane adapters may read a staged engine file only when that exact
  `engine/file` is explicitly included in the transaction plan. A device-only
  change can no longer activate an unrelated engine draft.
- The device policy dialog now owns only the client/group scope. It shows the
  current route as read-only and directs route changes to the Services page.
- DNS selections now have an independent pending-state indicator and their own
  Apply/Discard workflow. They no longer disappear into the global routing
  draft or block an unrelated service/device transaction.
- DNS Apply is deliberately disabled with the exact missing-adapter reason for
  non-system profiles. The draft is preserved, while the Automatic profile can
  be confirmed without falsely claiming that router DNS was changed.

## v0.16.0 — verified component setup and recoverable scoped drafts

- Component cards now separate availability, installation, configuration,
  runtime state and a verified lifecycle receipt instead of treating them as
  one generic status.
- The last install, update or removal failure is saved locally and remains
  visible after a page reload. A stale running operation is reported as
  interrupted instead of pretending that installation succeeded.
- Clean-router installation instructions now cover Entware prerequisites,
  missing `curl`/`wget`, TLS packages, SHA-256 tools and post-install health
  checks. Keenetic documentation now lists only the verified aarch64, mips and
  mipsel Entware installer lines; amd64 is explicitly limited to other systems.
  The bootstrap prints exact recovery commands for missing tools.
- A service can no longer enable or switch to an unavailable route. Existing
  stale selections remain recoverable: the service can still be disabled and
  the UI links directly to the required component installation.
- Unused engine drafts have an explicit explanation, assignment action and
  scoped discard action. They no longer look like an Apply button that silently
  does nothing.
- Service/device routing and engine configuration keep independent Apply and
  Discard controls, with regression coverage for unrelated draft conflicts.

## v0.15.1 — independent page apply and clearer route controls

- Service and device routing drafts now have their own visible Apply/Discard
  controls inside the relevant page.
- Applying routing changes includes only engine drafts used by the selected
  routes. An unrelated or unfinished WARP profile no longer blocks Telegram,
  DIRECT or another independent service edit.
- Applying one page reports success for that scope even when an unrelated
  engine draft remains pending elsewhere.
- Engine configuration Apply is scoped to the selected engine and refuses to
  absorb unrelated service edits; the UI points to the exact page that must be
  resolved first.
- Unavailable bypasses remain visible for explanation but disabled in service
  route selectors and explicitly labelled as not installed.
- Added regression coverage for the original unused-WARP-draft conflict and
  browser-tested both Services and Devices flows.

## v0.15.0 — evidence hardening, WAN profiles and DNS preview

- Added automatic DIRECT control to isolated comparisons and plain-language
  conclusions that distinguish a useful bypass from ordinary reachability.
- Smart Route evidence is now isolated by a privacy-safe WAN profile. Results
  from one provider or gateway cannot silently select a route on another
  network; schema v1 data migrates as unscoped history only.
- Engine Lab port, interface and NFQUEUE conflicts now block the real Apply
  plan instead of remaining advisory diagnostics. Port 53 ownership is scoped
  to the DNS adapter and identifies common router resolvers when process
  metadata is available.
- Added a bounded, secret-safe local action journal and a boot-loop guard that
  enters Recovery Safe Mode after an unsuccessful dataplane recovery.
- Added the first DNS control surface with Automatic, Private, Security,
  Ad-block, Family and Unfiltered profiles plus bounded direct resolver probes.
  It now builds a six-stage ownership-aware snapshot/canary/rollback preview;
  live DNS remains disabled until the router-specific adapter passes hardware
  recovery tests.
- Catalog services can define several fixed required probe scenarios. Telegram
  checks its site, Web client and Core/API independently, and Smart Route/WARP
  health consume a conservative aggregate that cannot hide one failed required
  scenario behind another successful endpoint.
- Added one ordered assurance model shared by Test Lab and Smart Route:
  catalog/configured/runtime/route-confirmed/service-confirmed.
- Current-path HTTP success is now explicitly runtime reachability and cannot be
  presented as proof of a particular bypass; isolated successful probes carry
  service-and-route confirmation.
- Smart Route rejects explicitly weaker evidence and persists the accepted
  assurance level for UI and diagnostics.
- Conflicting dataplane operations now wait through a context-aware gate instead
  of an uninterruptible mutex. A cancelled Apply still performs rollback through
  a fresh bounded recovery context.
- Live Apply has an explicit eight-minute safety deadline and returns a concise
  cancellation/rollback explanation instead of an unbounded request.
- Consolidated the active roadmap, including the transactional DNS control
  surface, in `docs/MASTER_PLAN_RU.md`.

## v0.14.0 — full-block routing and honest tunnel guidance

- Official Telegram IPv4/IPv6 CIDRs now enter the actual service route instead of remaining source-status metadata.
- Source lists can enrich only explicitly associated services, preventing broad community lists from leaking into unrelated routes.
- Telegram AUTO prefers available tunnel transports for full IP blocks while retaining NFQWS2 and direct fallbacks.
- Component cards now explain what each bypass solves and what it requires; Sing-box and Xray are identified as clients for a user-provided server.
- Added an explicit Cloudflare connectivity check for profile registration and MASQUE TCP/443; WireGuard remains confirmed only by a real transactional handshake.
- USQUE now follows its upstream MASQUE transport by default and proves the selected service through its own SOCKS5 candidate; policy-rule evidence is validated separately.
- Service cards show domain/IP coverage and technical details explain when a tunnel is required.

## v0.13.1 — WARP handshake recovery and clear rollback state

- WARP WireGuard now retries Cloudflare's documented UDP fallback ports `500`, `1701` and `4500` when the configured endpoint does not complete a handshake.
- The first working WARP endpoint port is committed atomically with the profile; all failed candidates are removed by the existing rollback transaction.
- Handshake errors no longer include peer identifiers in the public API or UI.
- A failed Apply is now shown as a successful safety rollback: the UI explains that internet access was restored, keeps the draft intentionally and offers clear retry or discard actions.
- The UI explains that Cloudflare WARP cannot be converted into AmneziaWG without a compatible AmneziaWG server and suggests independent MASQUE, AmneziaWG or sing-box routes instead.

## v0.13.0 — route quality evidence and compatibility advisor

- Extended current and isolated service tests with TTFB, total response time, bytes read and a bounded 32 KiB stream-integrity sample.
- Interrupted or stalled response bodies no longer become false successful tests merely because HTTP headers arrived.
- Strategy Lab now records HTTP status, TTFB, read duration, bytes and stream state and shows average TTFB next to reproducibility.
- Added read-only TProxy, socket match, ipset and conntrack capability checks so UDP/QUIC and transparent-proxy readiness is visible before installing a profile.
- Kept all probes bounded, catalog-only and rollback-safe; no remote relay, universal credential or competitor runtime is bundled.

## v0.12.4 — WARP MASQUE TCP fallback

- WARP · MASQUE now runs USQUE over HTTP/2 on TCP/443 with automatic reconnect, avoiding the blocked or throttled UDP transports observed during hardware testing.
- Installing WARP · MASQUE also installs the managed sing-box TUN dependency.
- Transaction snapshots now detect the `usque-keenetic` package runtime, suspend it before RAZVILKA starts its isolated SOCKS/TUN pair, and restore it after rollback.
- Added regression tests for the HTTP/2 command line, dependency graph and package-runtime lifecycle.

## v0.12.3 — first WARP Apply without a circular blocker

- A structurally valid staged WARP · WireGuard profile can now be assigned to a service before its first transactional Apply.
- Keenetic/Entware can start the owned WARP interface with native `ip` + `wg setconf` when the optional `wg-quick` helper is not packaged.
- WARP health checks now confirm the WireGuard handshake before probing a service, so failures identify the actual layer.
- The staged tunnel remains excluded from AUTO until it has actually started, so an untested profile cannot be selected implicitly.
- Invalid or incomplete staged WARP profiles remain unavailable.

## v0.12.2 — resilient and clearer Web UI

- The dashboard now keeps available sections working when one optional API request fails, and reports the unavailable part without blanking the whole page.
- User-facing statuses and safety controls use clear Russian wording; technical details remain available on demand.
- Unsaved WARP policy and bypass configuration edits now trigger a browser leave warning.
- Route selectors and icon-only controls have accessible names, keyboard focus is visible, and the active mobile navigation item follows the selected page.

## v0.12.1 — honest WARP Apply and clearer bypass settings

- Fixed the WARP policy/profile flow: an engine draft can no longer look applied when no enabled service uses that bypass.
- Unified route and bypass drafts under one transactional Apply with a clear `ENGINE_DRAFT_UNUSED` blocker, backup, health-check and rollback.
- The global pending state now includes engine configuration drafts, and global discard removes both route and engine drafts.
- Added visible save feedback for WARP autocontrol and protected unsaved policy fields from background refreshes.
- Reworked WARP setup into a four-step flow with plain-language thresholds and clearer next actions.
- Added the RAZVILKA application icon, browser favicon, Apple touch icon and a Telegram-ready avatar.

## v0.12.0 — human-readable tests and release-ready installation

- Replaced raw route-comparison JSON with a concise decision, per-bypass result cards, latency/HTTP evidence and an optional collapsed technical payload.
- Replaced the top-bar temperature value with live RAM utilization sourced from the same router metrics snapshot as the resource dashboard.
- Reworked the one-command Entware bootstrap into a guided five-step console with architecture checks, verified release download, rollback messaging and a clear first-login URL.
- Print the setup/recovery key only for a fresh account; upgrades preserve the existing UI credentials without echoing the secret again.
- Rebuilt the public documentation around quick installation, real UI screenshots, Safe Mode, selective bypass installation and tested hardware.

## v0.11.3 — unified UI generation and stale-cache protection

- Unified Diagnostics, Test Lab and Devices with the current graphite component system and responsive content density.
- Removed nested scrolling from the apply-readiness plan and arranged transaction steps as readable responsive cards.
- Added explicit no-store headers and an embedded UI version response header so router upgrades cannot keep serving an old HTML/CSS generation.

## v0.11.2 — split bypass workflow and unified mode control

- Split component installation/update and bypass configuration into separate navigation views.
- Replaced duplicate top-bar Safe Mode indicators with one state block and a confirmed mode switch.
- Added component status counters, filters, empty states and direct links between installation and configuration.

## v0.11.1 — balanced semantic UI palette

- Replaced the monochrome navy/cyan presentation with neutral graphite surfaces and softer borders.
- Reserved green for healthy state and primary actions, turquoise for routes, violet for tunnels/WARP and amber for warnings.
- Added varied service and dashboard-card accents while preserving contrast, Safe Mode visibility and responsive layouts.

## v0.11.0 — UI-only install, NFQWS2 Strategy Lab and hardware verification

- Changed the default Entware install to the RAZVILKA UI/control plane only; bypasses are installed individually from «Обходы», with versions, update notifications, resource budgets and transactional plans.
- Added a navy/cyan responsive dashboard, an original router/fork SVG mark, truthful CPU/RAM/temperature/Entware/WAN traffic metrics and persistent hour/day/week traffic totals.
- Integrated z2k-inspired capabilities into ordinary NFQWS2 without installing or exposing z2k as another bypass: native candidate validation, TCP/TLS stage evidence, true HTTP/3/QUIC probes, repeated evidence and draft-only selection.
- Added a serialized per-service NFQWS2 Smart Route probe using an exact temporary destination/source-port chain. Global NFQUEUE counter deltas are no longer accepted as route evidence.
- Added draft candidate deletion with removal of only its own evidence/selections; live NFQWS2 configuration is never touched.
- Verified on Netcraze Ultra NC-1812 (ARM64, KeeneticOS 5.1.3): transactional install/update, existing NFQWS2 preservation, scoped Discord NFQUEUE probe, YouTube HTTP/3 probe, router metrics, component refresh and WARP registration/profile generation.
- Kept Safe Mode as the default and reserved `1.0.0` for wider reboot/fault/low-memory/IPv6 and multi-model testing.

## v0.10.0 — z2k-aware control center

- Added read-only discovery for an installed z2k/Zapret2 runtime, including external ownership metadata and version evidence.
- Prevented an active z2k NFQUEUE process from being misreported as the standalone RAZVILKA NFQWS2 runtime.
- Added an explicit `EXTERNAL_NFQUEUE_OWNER` plan blocker when z2k already owns packet interception.
- Retried transient Cloudflare WARP registration failures and returned a typed, concise recovery response instead of the wgcf stack trace.
- Reworked Safe Mode Apply feedback into a guided review notice with optional technical details.
- Added local SVG icons, a Telegram support link and user-facing «Обходы» terminology.

## v0.9.1 — Keenetic integration patch

- Added integrity-bound version receipts for verified upstream binaries such as `wgcf`, whose official CLI intentionally has no version command; update status now remains exact without rejecting a valid binary.
- Reused existing official opkg feed declarations instead of creating duplicate NFQWS2/usque repository entries on Keenetic.
- Corrected source readiness to count enabled downloadable lists separately from disabled lists and reference-only links; the dashboard now reports the actionable denominator.
- Made the WARP card use the verified `wgcf` component receipt and taught Engine Lab to select the actual usque semantic-version line instead of its preceding config diagnostics.
- Reported missing Cloudflare Terms acceptance as an explicit precondition instead of disguising it as an upstream gateway failure.
- Made ARTEM Flow handover detect and stop a legacy process even when it was left running under a previously disabled init controller.
- Fixed strict post-upgrade PID discovery on Entware and added an init-level owned PID query.

## v0.9.0 — software-complete release candidate

- Added native `usque-keenetic` compatibility: the component is installed/updated through its fixed opkg feed without overwriting a package-owned binary, and `/opt/etc/usque/session.conf` is detected and edited as the secret JSON session instead of being misreported as unconfigured.
- Made ARTEM Flow handover recoverable when a previous migration left the legacy process running under `S99artem-flow.razvilka-disabled`; upgrade now stops that exact controller and rollback restores its original disabled/running state.
- Fixed the strict post-upgrade PID check to obtain the owned process from the init controller instead of assuming a state-directory PID path that differs from Entware `/opt/var/run`.
- Added active transactional adapters for NFQWS2, usque/MASQUE, WARP WireGuard, AmneziaWG, sing-box and Xray with snapshot, stage, validation, activation, health, commit, rollback, recovery and owned deactivation.
- Added RAZVILKA-owned process/PID files, TUN interfaces, policy tables/priorities, endpoint loop guards, DNS policy refresh and IPv4/IPv6 kernel-route evidence.
- Added LAN device discovery from neighbor/ARP/DHCP data, persistent friendly names/groups and source-scoped tunnel service policies.
- Replaced placeholder Connections data with a bounded conntrack collector that publishes only unambiguous service matches confirmed by the actual kernel route.
- Added encrypted private backup using AES-256-GCM and PBKDF2-HMAC-SHA256; secrets restore to draft only and never include UI credentials or live routes.
- Added a privacy-safe diagnostic report and an official-release check that reports `installed → latest` without automatically executing a privileged update.
- Added graceful shutdown, committed-plan boot recovery, non-blocking transaction status and a longer init health allowance for slower routers.
- Added version-aware sing-box TUN generation; 1.14+ sidecars explicitly disable DNS ownership while older supported schemas remain valid.
- Added GitHub/Sigstore artifact attestations for binaries, checksums and Entware release bundles.
- Updated product/security/architecture documentation to distinguish software completeness from the remaining real-hardware `1.0.0` gate.

## v0.5.1 — truthful runtime and Safe Mode state

- Corrected Entware package IDs and added the official `nfqws2-keenetic` feed.
- Split installed runtime, configured profile and active process/interface detection.
- AUTO now falls back only to a route with live runtime evidence.
- Safe Mode reviews non-direct plans without advancing applied state.
- Engine Lab no longer reports READY when no engine can run.
- Unresolved profile route IDs and uncoordinated live config writes are blocked.

## v0.5.0 — transactional dataplane readiness gate

- Added a deterministic, SHA-256 identified dataplane plan for every enabled service and resolved AUTO route.
- The plan exposes `plan → snapshot → stage → validate → activate → health → commit-or-rollback`, RAZVILKA ownership, adapter actions, warnings and actionable blockers.
- Added read-only NFQWS2 host inventory for `ip`, iptables/ip6tables, the kernel NFQUEUE target, the canonical nfqws2 config/init paths and unconfirmed offload state.
- Added adapter-specific safety gates for usque/MASQUE, WARP WireGuard, AmneziaWG, sing-box and Xray, including endpoint bootstrap and self-proxy-loop requirements.
- Live Apply no longer advances `applied_services` when Safe Mode is disabled but the transaction is blocked. Safe Mode still allows committing control-plane intent without claiming a live route.
- Added a root-only atomic `latest-plan.json` journal and an authenticated dataplane-status endpoint.
- Replaced the raw JSON dry-run in Diagnostics with a readable readiness panel showing blockers, resolutions, owned steps, route mappings and plan digest.
- Added a low-latency engine inventory for selectors and route plans so ordinary UI refreshes do not execute slow version/init probes; exact probes remain in Engine Lab.

## v0.4.0 — portable profiles, recovery UX and domain inspector

- Added a portable `razvilka-profile` format with schema/version metadata, canonical SHA-256 digest and strict size/item limits.
- Safe profile export includes desired service routes, custom services and explicitly non-sensitive engine files; WARP, WireGuard, VLESS/Xray/sing-box/usque credentials are never exported.
- Added profile preview with service diffs, custom-service update warnings, engine-file validation and installed-engine warnings before import.
- Profile import is draft-only: it atomically merges custom services and desired routes, stages public engine files, and never applies firewall, DNS, routes or live engine configs.
- Added recovery-key password reset and authenticated recovery-key rotation; the new key and recovery URL are shown once in the Web UI.
- Kept RAZVILKA authentication separate from Entware/SSH so a panel flaw cannot become SSH credential reuse and router variants do not need `/etc/shadow` access.
- The transactional installer now prints a first-setup URL for new accounts and a recovery URL for existing accounts.
- Added a domain/IP inspector that explains catalog matches, suffix/CIDR rules, conflicts, desired/applied state and calculated AUTO route without pretending it is live traffic evidence.
- Added Settings UI for safe profile exchange, preview/import, password recovery and recovery-key reissue.

## v0.3.0 — Engine Lab, isolated probes and Smart Route

- Added a read-only Engine Lab registry with exact discovered versions, schema/probe capabilities, native/basic validation results and port/TUN/NFQUEUE ownership conflicts.
- Added isolated route probes for loopback SOCKS5 adapters and source-bound WireGuard/AmneziaWG interfaces. Route confirmation requires explicit transport or matching kernel route evidence and never changes the default route.
- Added DNS-resolution SSRF protection for service probes and bounded SOCKS5 support with optional authentication.
- Added persistent Smart Route evidence with latency/cost scoring, 12-point hysteresis, a 10-minute switch cooldown, 24-hour evidence expiry and immediate confirmed failover.
- Connected confirmed WARP route evidence to manual and 15-minute guarded health monitoring; automatic recovery may stage a fresh candidate but cannot delete or replace live routing without validation and Apply.
- Added administrator password changes, active-session inventory/revocation and per-IP login throttling.
- Expanded guided sing-box and Xray editing to named inbound/outbound/VLESS blocks while preserving unknown JSON fields and retaining full expert mode.
- Expanded the Russia-oriented community catalog from 9 to 35 service manifests with separate `blocked`, `throttled`, `partial`, `provider-limited` and `variable` status metadata.
- Community imports can now be refreshed from their pinned source without losing the service ID or desired routing state.
- Added an Engine Lab/Smart Route UI, isolated comparison controls and account/session settings.

## v0.2.0 — community catalog and guarded WARP health policy

- Added an allowlisted community service catalog with search, source/license display, live preview and local domain/CIDR validation.
- Added SHA-256 provenance to imported services and persistent source metadata that survives later manual edits.
- Added conflict detection against built-in and user services; imports with overlapping domains or networks require a separate confirmation.
- Unsupported regex, keyword and unresolved include rules are skipped and counted instead of being silently translated incorrectly.
- Added a WARP health policy with configurable consecutive-failure threshold, minimum failed services, cooldown and daily rotation limit.
- Automatic WARP candidate generation requires explicit Cloudflare terms acceptance and confirmed route evidence from an isolated adapter. Ordinary current-route tests cannot arm profile replacement.
- A generated profile always remains a candidate awaiting validation; the working WARP profile is never deleted on a single failure.
- The Entware transaction now installs, preflights, snapshots and rolls back the community registry alongside the core catalog.

## v0.1.0 — first product preview

- Reworked the Web UI into a clear service-first control center inspired by router dashboards while keeping every status value evidence-based.
- Added first-run administrator registration, password login, hardened local sessions and an installer-visible recovery key/link; the router SSH password is never reused.
- Added guided configuration forms for NFQWS2, usque/MASQUE, WARP WireGuard, AmneziaWG, sing-box and Xray, plus an authenticated expert editor that preserves unknown fields and secrets.
- Added persistent custom services with validated domains and public IP/CIDR ranges, edit/delete controls and separate upgrade-safe storage.
- Added a WARP WireGuard lifecycle: detect `wgcf`, accept terms explicitly, generate/import, validate and stage a candidate without overwriting the live profile.
- Extended the Entware component manager to NFQWS2, usque, sing-box, Xray, WireGuard, AmneziaWG and wgcf with installed/available versions and update notifications.
- Added a one-command network bootstrap which selects the router architecture, verifies the release SHA-256 and delegates writes to the transactional installer.
- Replaced browser `confirm`/`prompt` interactions with accessible in-page dialogs.
- Safe Mode remains the default: active firewall, DNS and policy-route adapters are not claimed as complete in this preview.

## v0.0.10-components — Entware component installation and updates

- The Entware installer now attempts to install recommended bypass components when their packages exist for the current feed and architecture.
- Added an authenticated allowlisted component API backed by `opkg`; browser input can never select an arbitrary package or command.
- Added installed and available versions, update notifications such as `1.1.0 → 1.2.0`, and install/update buttons to the Engines page.
- Component installation remains separate from activation and never changes firewall, DNS or routes automatically.
- A missing component package is reported without rolling back a healthy RAZVILKA Manager installation.

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
