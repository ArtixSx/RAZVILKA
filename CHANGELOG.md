# Changelog

The release workflow stages a draft; promotion follows verification of the exact attached router artifacts.

## 0.18.4 — Service setup, connection checks and configuration tools

Source revision c7ea788 passed full CI and local-build ARM64 router checks:
Discord service verification, a route scoped to one PC, manual A/B switching,
application restart and complete removal of owned routes. Final GitHub release
artifacts still require their own verification before publication. Detailed
[validation and limits](docs/EXT5_REVIEW_2026-09-19_RU.md) are tracked separately
from the [short release notes](docs/releases/0.18.4.md).

### Added

- Autopilot setup with selected devices and services, permitted sources,
  scheduled checks, subscription refill and stable/preview update channels.
- Connection browsing with readable country names, node and service checks,
  and selection of permitted fallback candidates.
- Passive Mihomo configuration export, experimental HEV profile generation
  and manual import/export of NFQWS2 strategy packs.

### Fixed

- Panel loading, complete multiline NFQWS2 editing and unnecessary password
  minimum length restrictions.
- Wizard selections and consent after catalog changes, saved-state readback,
  stale login messages and stale content during file replacement.
- Lossy Mihomo conversion, invalid server addresses, strategy signatures,
  export size checks and signing-key validation.
- Recovery admission between node checks, fatal cleanup diagnostics and
  restoration of fully vanished owned firewall chains.
- Prevent the stock Sing-box example from starting automatically after package
  installation or update; preserve external ownership.
- Fix false service failures when an HTML response exceeds the sample limit
  and the server ignores Range. JSON validation and blocking checks remain strict.
- Admit bounded CDN answers of up to eight IPv4 addresses while requiring every
  address to pass within the overall 45-second budget; persist IP-path failures
  and return structured timeout/cancellation reports without recording them
  (`recorded:false`). Diagnostic
  text bounded to 240 Unicode characters without splitting UTF-8.

## 0.18.3 — Unpublished tagged build

Exact-artifact router checks exposed a four-address DNS limit that rejected
Discord's five-address CDN answer, and missing IP-path stages in the node-store
contract. Its unpublished draft was removed; the tag is retained and 0.18.4 includes the fixes.

## 0.18.2 — Unpublished tagged build

The tagged build completed Release CI and exact-artifact router installation,
but remained a draft after real VLESS checks exposed the large-HTML sampling
failure described above. It was not published as a stable release. Its Git tag
is retained unchanged; the unpublished draft was removed. Version 0.18.3 carries the correction. See the
[historical draft notes](docs/releases/0.18.2.md) and
[validation report](docs/EXT5_REVIEW_2026-09-19_RU.md).

On 19 September 2026, seven old prerelease entries were removed from Releases:
0.18.1-rc.1/rc.2 and 0.18.2-rc.2 through rc.6. Git tags, source history and stable
releases were retained. The entries below document those historical revisions.

## 0.18.2-rc.6 — Restore vanished owned firewall rules

- Restore a fully absent proxy firewall chain from the committed creation lease
  on the existing background schedule, including an unchanged WAN.
- Preserve client scope, current ACL precedence, intact tables, processes and
  pending settings. Partial or foreign rules require review instead of overwrite.
- Report failed restoration as retry/backoff; clean up only objects created by
  the failed attempt. See the [release notes](docs/releases/0.18.2-rc.6.md).

## 0.18.2-rc.5 — Responsive settings and flexible passwords

- Read node route eligibility and public metadata from one storage generation
  per selector request, retaining exact service/network/freshness checks.
- Render independent panel reads as they arrive, bound GET timeouts and retries,
  preserve prior data, and distinguish unavailable data from empty settings.
- Preserve complete multiline NFQWS2 assignments and use multiline strategy
  fields; refuse unsupported shell syntax instead of partially rewriting it.
- Remove password minimum length for setup, change and recovery. Require only
  nonempty exact input within the existing 256-byte resource bound.
- See the [release notes](docs/releases/0.18.2-rc.5.md).

## 0.18.2-rc.4 — Scoped policy precedence and current runtime status

CI and Release CI passed for the exact published commit. SSH upgrade,
application restart and fresh client TUN paths, including a controlled packet-mark
case, passed on Netcraze ARM64. See the
[validation report and limits](docs/releases/0.18.2-rc.4-validation.md).

- Introduce policy layout 2 with shared adapter slots 60–69, keeping scoped
  exclusions before the corresponding service rules. Earlier matching firmware
  mark policies must not silently override an accepted managed route.
- Bind early exclusions to the selected client scope. Migrate and clean up only
  exact owned legacy tuples; recorded rollback snapshots retain their original
  kernel coordinates.
- Refuse occupied slots, duplicate or unknown selectors, and earlier foreign
  rules that may intercept the selected traffic. Unrelated rules are preserved.
- Require current observation of the owned runtime for live status; a historical
  committed transaction alone no longer certifies the running path.

rc.3 passed SSH installation and application restart. Fresh unmarked client
connections were observed through its TUN, while the marked-policy case could
select the previous Keenetic VPN before the old RAZVILKA priorities. A conntrack
mark alone is not proof of the packet's routing mark. rc.4 passed both client
path scenarios. The out-of-scope client check was a synthetic route query;
a physical second client and the full hardware matrix remain unverified.
See the [rc.4 notes](docs/releases/0.18.2-rc.4.md).


## 0.18.2-rc.3 — Wait for applied-route recovery during upgrade

- Wait up to nine minutes for asynchronous recovery of the committed node route
  before strict startup/dataplane acceptance; one recovery operation is bounded
  to eight minutes. If the API still confirms a busy private recovery at the
  deadline, exit with code `75`, leave the process running and report readiness
  as unconfirmed. This is neither success nor rollback. Once the operation is
  released, a non-live route follows the normal rollback path.
- Keep the application version, interface cache keys and installation guidance
  aligned with the new candidate.
- Let startup recovery of the already applied node routes reuse the UI updater's
  exclusive admission. Keep other writers blocked until recovery cleanup joins;
  a replaced or failed helper cannot keep authorizing work.

The published `v0.18.2-rc.2` passed Release CI, but a real router upgrade with
an applied VLESS route rolled back because acceptance ran before recovery
completed. The rollback restored the previous installation. rc.3 passed its
[Release CI](https://github.com/ArtixSx/RAZVILKA/actions/runs/34783345534), SSH
installation and application restart. Later client-path testing found the
conditional policy precedence issue described under rc.4; successful unmarked
TUN traffic does not close the marked-policy case.
See the [rc.3 notes](docs/releases/0.18.2-rc.3.md).


## 0.18.2-rc.2 — Reviewed DC1 prerelease

The reviewed DC1 source integrates the imported A1/UI2/R3/AWG31 work while
preserving the earlier main history. Stable `latest` remains `v0.18.0`.
`v0.18.2-rc.1` was not published: its release run stopped at the WARP cancellation
test. `rc.2` was published from `de8bafa` after successful
[Release CI](https://github.com/ArtixSx/RAZVILKA/actions/runs/34781604595).
The existing tags and release assets are retained. Its real router upgrade
exposed the premature recovery check addressed by `rc.3`.

- Integrated router-side Autopilot consent and client scope, persisted checks
  and subscriptions, and the refreshed local dashboard on port 8787.
- Hardened live-runtime recovery after isolated node checks, per-job deadlines
  and cancellation. AWG canaries recheck profile and runtime capabilities.
- Added bounded DNS A/AAAA wire validation and DNS-only comparison. Combined
  DNS/route/service proof, scoped DNS application and automatic pair selection
  remain DC2–DC4. Community recipe hints remain offline and cannot apply routes.
- Rejected ambiguous signed-catalog and provider-key JSON field aliases without
  changing the exact signed payload or granting downloaded nodes service proof.
- Made the selected upgrade binary's SHA-256 entry mandatory and unambiguous
  before live changes; restored the CSS build entry point and its check mode.
- Fixed stale session/UI states, theme and asset checks, metrics presentation
  and mobile/first-run issues documented in the DC1 review.

Source `09730c7` passed the complete
[Linux CI](https://github.com/ArtixSx/RAZVILKA/actions/runs/34779255292), including
tests, race detection, vet, frontend checks and four Linux architecture builds.
Release CI success did not prove a successful router upgrade: the rc.2 hardware
attempt restored the previous installation after premature acceptance failed.
Hardware failover, WAN reconnect, router reboot, low-memory operation, DNS
migration/rollback and prolonged autonomy remain separate acceptance scenarios.

See the [DC1 review](docs/DC1_REVIEW_2026-09-13_RU.md) and
[current status](docs/CURRENT_STATUS_RU.md).


## 0.18.1-rc.2 — Service controls, connection browser and guarded recovery

Prerelease for public testing, built from the `0.18.1-dev` source line after
Release CI. Hardware acceptance remains incomplete; see the
[release notes](docs/releases/0.18.1-rc.2.md) for the tested scope and limitations.
Earlier core acceptance below does not certify the final release artifact.

- Added global Autopilot/Manual controls, transactional stop/resume of owned
  routes, compact service cards, separate TCP/service checks, bounded candidate
  selection and a persisted router-side check schedule. Client scopes and
  unrelated pending edits survive stop, resume and failed application.
- Simplified home/navigation, made overview cards actionable, added website
  lookup and displayed installed component versions with available upgrades.
  Proxy version/check processes no longer appear as running bypasses.
- Added reviewed application updates from official GitHub assets with mandatory
  digest/architecture/archive validation, restart-spanning write admission and
  transactional installer handoff. Candidate layouts and untrusted path owners
  are refused; an actual production upgrade remains a release acceptance gate.
- Added a canonical development version consumed by local builds and CI, plus
  a release guard that rejects tags which do not match the source version.
- Added a verified capability matrix and a roadmap rebased on the published
  `v0.18.0`; older gap documents are now explicitly historical.
- Removed the stale Source Hub `0.2.0` identity and exposed version, commit,
  build date and source state together in Settings.
- Added automated consistency and current-document link checks.
- Added shared strict HTTP predicates for Test Lab, isolated route probes and
  candidate health checks: redirects, block pages, policy statuses, JSON fields
  and content types no longer count as service success without validation.
- Added explicit probe verdicts and redacted redirect/content-fingerprint
  metadata; declared success without an HTTP response is now inconclusive.
- Prevented route mismatches and blocked required scenarios from inheriting a
  successful result. Smart Route revokes observed misrouted evidence and ignores
  inconclusive high-score candidates.
- Clarified that the YouTube connectivity probe requires HTTP 204 but does not
  prove video playback.
- Added managed proxy launch receipts and local route passports: boot/PID start,
  config/argv digests, executable, network namespace and listening socket owner
  are checked before and after a SOCKS service probe. Unowned or changed
  runtimes no longer inherit a successful route result; Smart Route revokes
  their previous proof and the UI distinguishes missing proof from an outage.
- Added conservative static-outbound inspection for Sing-box/Xray and managed
  USQUE. DIRECT exits, local relays, dynamic pools and unverified chains cannot
  masquerade as a proven remote path. Existing profiles are not rewritten.
- Bounded every SOCKS handshake stage and closed cancelled connections; failed
  managed startup now reaps its child and invalidates its launch receipt.
- Added an exact single-node checker for saved Sing-box outbounds. It isolates
  one node on a loopback-only SOCKS port, pins the resolved public endpoint,
  verifies process/route ownership, compares proxy and direct egress, and runs
  a catalog-owned service canary before recording availability.
- Added bounded node health history with service, network-profile and TTL
  binding. Direct leaks, protocol-only success, stale evidence, disabled nodes
  and cleanup failures cannot make a node selectable; private endpoint and
  credentials remain outside the API.
- Added reviewed single-node route application with a one-use confirmation,
  fresh exact service proof, preserved client scope and rollback. Group choices
  are first saved to the service draft and require explicit application.
- Added a connection browser with country/transport labels, source and status
  filters, search, selection and pagination. TCP connection time is separate
  from exact service availability; expired, wrong-network and future results
  do not remain valid. Background redraws preserve focus and expanded cards.
- Added five public feed presets and saved private HTTPS subscriptions with
  opt-in scheduled refresh, cancellation and explicit partial-import consent.
  Feed updates retain existing nodes and never grant route or service proof.
- Added bounded automatic replacement only within an explicitly applied
  fallback group. The current runtime is checked separately from an isolated
  remote node; failed repair or replacement uses guarded rollback. Pending
  service drafts and other client scopes are preserved.
- Kept login, operation status and cancellation available while a detached
  check owns the configuration stores. UI polling stops on logout and ignores
  late responses from the previous session.
- Verified the exact VLESS → Sing-box → Telegram path on Keenetic ARM64,
  including distinct direct/proxy egress, route ownership and cleanup. Route
  passports now safely support older kernels built without network namespaces
  only when both procfs namespace entries are absent with `ENOENT`; partial,
  permission and mismatch failures remain fail-closed.
- On 8 September, a separate ARM64 core build passed mandatory service-domain
  and literal public-IPv4 checks with the original TLS/Host, scoped Telegram
  traffic from the selected PC, a negative client control, application restart
  and recovery after controlled loss of its owned processes/TUN/policy. Fresh
  proof was required and the user's original state was restored. This did not
  reboot the router or disconnect WAN.
- Preserved native WARP enrollment and pending registration through encrypted
  backup/restore. Install and downgrade check private-state schema support
  before replacing a binary. WARP WireGuard remains unconfirmed in the tested
  network; repeated MASQUE results were mixed.
- Added the English README and a private-file/link guard to release archives.
  Builds include ARM64, MIPS and MIPSel/Go `mipsle`; MIPS hardware acceptance
  remains open. Final candidate HIL and Linux Release CI remain release gates.

## v0.18.0 — Autopilot and honest route checks

- Fixed NFQWS2 activation on Entware: generated host/IP lists are readable by
  the unprivileged `nobody` process, and activation now fails if the init script
  returns success but the daemon immediately exits.
- Made NFQWS2 rollback idempotent when the saved state is already stopped.
- Added bounded background Autopilot reconciliation for applied AUTO services.
  It checks at most four services per cycle and only the current route, DIRECT
  control and one alternative; explicit routes and pending drafts are never
  changed automatically.
- Reduced the Services workflow to one section action. Routine service-only
  changes no longer open a second review dialog, and global draft controls stay
  hidden on tabs that own their own changes.
- Multi-node Sing-box imports now use a bounded local URLTest pool with manual
  fallback nodes. Public checker pages are rejected in favour of actual share
  keys, and failures explain that TCP reachability is not a VLESS/TLS/Reality
  handshake.
- Verified on Keenetic ARM64: transactional upgrade, NFQWS2 process state,
  readable runtime lists and YouTube `generate_204` through the committed route.

## v0.17.0 — Hardware truth and safe canaries

- Hardware testing now detects the official USQUE `nativetun` runtime and
  probes it by a source address plus matching kernel-route evidence instead of
  assuming that every running USQUE process exposes SOCKS on port 1080.
- A refused or failed SOCKS connection can no longer be labelled
  `route-confirmed`; confirmation is granted only after the proxy returns a
  real HTTP response. The USQUE component also no longer installs Sing-box as
  a false dependency because `usque-keenetic` owns `opkgtun0` itself.
- Route-test results now explain route evidence and service availability
  separately, so a confirmed TUN path with a Telegram timeout is no longer
  presented like a successful bypass.
- Route selectors now distinguish a missing bypass package from an installed
  component that still needs a profile. Unconfigured routes are disabled in
  isolated comparison instead of being presented as ready to test.
- WARP WireGuard gained a pre-activation canary: a temporary interface and a
  source-only policy rule verify Cloudflare `warp=on`, a real handshake and a
  catalog-owned service probe, then are removed before any live Apply. The UI
  can run this check for Telegram or another selected service without changing
  working routes.
- ARM64 hardware validation confirmed the canary's failure path: when the
  provider rejected WireGuard on UDP `2408`, `500`, `1701` and `4500`, the
  temporary interface, source rule and route table were removed and the live
  route remained untouched. Candidate validation and the UI now direct users
  to this safe check instead of implying that Apply is the first handshake test.
- The login and first-run screens now display the running server version and
  current Safe Mode state instead of retaining the static development fallback.

- Entware archives no longer fail preflight when an unpacker loses executable
  mode bits on the bundled init or rollback scripts. The installer requires
  readable sources, invokes rollback through `sh` and atomically installs the
  live init with mode `0755`. After checksum verification it also restores the
  extracted candidate binary's executable bit, so a clean-router installation
  no longer needs a manual `chmod` after unpacking on Windows or NAS tools.
- The transactional installer now prints seven explicit progress stages and
  the expected waits for graceful shutdown, dataplane deactivation and boot
  reconciliation. A normal 10–130 second quiet period is no longer presented
  like a frozen installation, reducing unnecessary user interrupts while the
  existing rollback behavior remains unchanged.
- Unreleased builds now identify themselves as `0.17.0-dev` (or
  `0.17.0-dev+<commit>` in CI) instead of claiming to be the published
  `0.16.0`. Status, Settings and redacted diagnostics expose commit, build time
  and whether dirty-state is known; tag builds still report the exact tag.
- USQUE Doctor now reports missing init, empty `IFACE` and unavailable route
  tooling explicitly. Dependent checks become `SKIPPED` with a reason, while a
  new backward-compatible readiness field distinguishes `READY`, `DEGRADED`,
  `BLOCKED` and `UNKNOWN`.
- USQUE Doctor v2 now separates package, core and config versions, exposes only
  a small redacted environment summary and labels TUN ownership as unconfirmed
  unless the init/TUN observations agree. A Cloudflare endpoint routed back
  through the same USQUE TUN is treated as a blocking dependency loop. Tests
  assert that Doctor leaves files unchanged and invokes only fixed read-only
  commands. File permissions, owner UID, timestamps and SHA-256 values plus the
  latest known backup are reported without returning file contents.
- USQUE Doctor now includes a read-only `ndmc` repair preview. It counts command
  sites without exposing the init script, detects already scoped system-library
  calls and forbidden global `LD_LIBRARY_PATH`, and lists the future
  backup/patch/validate/rollback steps while making no changes.
- DNS state schema 4 removes obsolete plaintext port 53 endpoints from
  UncensoredDNS and invalidates matching stale probe evidence without losing
  the user's draft. FlashStart is now a lab-only negative control and is
  ineligible for USQUE bootstrap and AutoPilot.
- DNS providers expose typed transport endpoints and explicit production/lab
  policy. Quad9 secure, unfiltered and ECS profiles include separate diagnostic
  alternate-port endpoints rather than silently replacing the defaults.
- Custom DNS probes now reject local/private, link-local, multicast,
  unspecified and other non-public destinations unless the user explicitly
  marks their own LAN resolver as trusted. DNS names are resolved and checked
  again immediately before each connection.
- DoH probes allow at most two same-origin HTTPS redirects, keep certificate
  verification mandatory and block untrusted redirect targets. Probe timeout
  text now uses the actual timeout, bounded workers limit concurrency, and the
  UI describes the resolver-reported AD bit without claiming local DNSSEC
  validation.
- Added backward-compatible Evidence v2 records with probe ID, timestamps,
  route path, outcome, source, latency, HTTP status, confidence and error code.
  Existing evidence levels remain in the API, but are now derived conservatively
  from the structured result.
- HTTP 403/451, TLS/certificate mismatch, policy responses and unsuitable edges
  can prove only the isolated route, never successful service access. Smart
  Route retains those facts for diagnosis but cannot select them as a working
  bypass. The UI shows the outcome, source and age and marks expired facts as
  stale.

- Expanded the USQUE recovery specification from real Keenetic troubleshooting:
  package/feed checks, secret-safe session inspection, `ndmc` library isolation,
  stale TUN detection, Cloudflare API/TLS checks, endpoint routing, IPv6 leakage,
  `warp=on` versus service evidence, and a guarded repair ladder.
- Added a read-only USQUE Doctor to Diagnostics. It reports safe package/config
  metadata, validates that required session fields exist without returning their
  values, checks supported Keenetic architectures and duplicate official feed
  declarations, checks init/TUN, compares normal and clean-library `ndmc`,
  probes the Cloudflare registration API and explains the public endpoint route.
- USQUE canary now proves Cloudflare `warp=on` first and the selected service
  second. The committed evidence stores the transport, POP/location, safe
  egress metadata and confirmed service names; Diagnostics displays technical
  WARP, Telegram/service proof and IPv4/IPv6 endpoint routes separately.
- Service cards now use an explicit **Lists** action for their domains and
  IP/CIDR ranges, including catalog/source freshness, instead of hiding this
  information behind an unexplained `i` button.
- The Services page links directly to bypass installation. WARP WireGuard now
  explains that the component and profile must be installed before it becomes
  selectable, and its profile check is disabled until there is something real
  to validate.

- Added an adapter-scoped neutral RoutePlan contract. A candidate receives
  only its own services, actions and resource claims, never unrelated routing
  intent or manager journal authority.
- Added a real pre-activation canary phase with rollback-before-activation on
  failure. The existing post-activation health check remains mandatory.
- sing-box, Xray and USQUE/MASQUE now start a temporary loopback-only SOCKS
  candidate on a separate port, verify service egress and remove it before the
  working TUN or policy rules can be changed.
- USQUE canary now inherits the safe SNI setting from the Entware package,
  verifies real service traffic over both QUIC and HTTP/2, and persists only
  the transport that actually passed. A successful MASQUE connection message
  without Telegram egress is no longer accepted as route evidence.
- A failed USQUE canary now keeps the specific Russian WARP · MASQUE guidance
  in the notice instead of replacing it with a generic technical failure.
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
- Added verified catalog entries for Control D Unfiltered/Uncensored, Xbox DNS,
  UncensoredDNS and FlashStart alongside Quad9, Cloudflare and Google. Provider
  warnings call out UDP/53 interception, Smart DNS uncertainty and the explicit
  ban on using FlashStart for USQUE registration.
- Added persistent per-service DNS drafts. A service may inherit the global
  profile or select its own resolver, but the UI and API keep every binding
  non-live until a tested Keenetic DNS dispatcher exists.
- Downloadable Sources now have persisted desired/applied selections and their
  own Save/Discard controls. A draft never changes active service enrichment;
  only the confirmed selection is refreshed and consumed.
- Source selection state is included in upgrade snapshots and rollback, while
  source refresh remains a separate, explicit network action.
- Global route/engine Discard now preserves independent DNS and Sources drafts;
  those drafts can only be cancelled from their own page.
- Every routing Apply now opens a human-readable preview with included changes,
  deferred page-scoped drafts, required verification, rollback behaviour and
  blockers before the user can confirm the operation.
- Switching a service to DIRECT, another engine or the disabled state now
  snapshots and retires an unused previous adapter transactionally; a later
  failure restores it instead of leaving a hidden stale route active.

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
