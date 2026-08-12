# RAZVILKA roadmap

## Completed foundation

### v0.0.2 — sources/control-plane
- Service catalog.
- Engine detection.
- Validated atomic list cache.
- Dark target dashboard foundation.
- Multi-architecture build/test pipeline.

### v0.0.3 — clean Entware Lab
- Safe bootstrap.
- Detailed preflight before/after manager install.
- Clean-environment test workflow.

### v0.0.4 — selectors + telemetry model
- Per-service AUTO/fixed route selector.
- Engine-agnostic connection model.
- SSE live stream.
- No synthetic connection rows.

### v0.0.6 — Vision Lab
- UI restructured close to target product.
- Desired / planned / applied service state.
- Draft → Apply / Discard workflow.
- System preflight API in UI.
- Devices/Outbounds/Diagnostics/Sources product structure.
- Config export.
- Compatibility-gate model.

### v0.0.7 — RAZVILKA GitHub foundation
- Product rebrand and repository normalization.
- Real Netcraze lab baseline validated on clean Entware.
- BusyBox-compatible preflight (`ip -o` instead of unsupported `ip -br`).
- External tunnel/route contamination detection (`nwg*`, `wg*`, `tun*`, `opkgtun*`, `awg*`).
- Bootstrap creates its log directory before redirecting the first preflight.
- Entware init framework (`rc.func`) is checked before install.
- GitHub-first development workflow.

### v0.0.8 — Security Gate
- Persistent 256-bit local administrator token.
- Bearer + JSON + Origin enforcement for state-changing API calls.
- Transactional config persistence and serialized engine/source writes.
- Exact engine process/status detection and native validator timeouts.
- Strict selectable route/profile validation with honest AUTO fallback.
- Startup cache revalidation, safe source IDs and HTTPS redirect policy.
- Race detector and security/concurrency regression suite.

## Next: Engine Lab

### Engine capability registry
- Detect exact engine version, architecture and relevant capabilities.
- Version/schema matrix.
- Native `check`/dry-run command where supported.
- Explicit port/TUN/NFQUEUE ownership inventory.

### NFQWS2 adapter
- Discover existing install without modifying it.
- RAZVILKA-owned isolated configuration directory/profile.
- Strategy/service mapping.
- Netfilter/offload preflight.
- Native/runtime checks.
- First route evidence adapter.

### usque / WARP Provider
- Detect/install usque only after clean-Lab approval.
- MASQUE registration/import flow.
- Isolated SOCKS/tunnel health test.
- `warp=on`/egress observation and service-aware probes.
- No account regeneration loops for geography hunting.

### WARP WireGuard
- Local legal profile enrollment/import.
- Isolated interface and route test.
- Never hijack default route during probe.

### sing-box adapter
- URI/subscription import after parser/security review.
- VLESS/Reality/Hysteria2/TUIC/Shadowsocks outbounds.
- Version-aware generation.
- `sing-box check` before runtime.
- Concrete selector IDs (`sing-box:<node-id>`).
- Clash/native API telemetry where available.

## Smart Route Engine

- Service-aware probe matrix per route.
- Cost + health + latency score.
- Cooldown/hysteresis to prevent route flapping.
- Protocol-aware TCP/UDP/QUIC decisions.
- Bootstrap route for tunnel endpoints when the endpoint itself is filtered.
- Explicit failover evidence in Connections.

## Devices

- Friendly client names.
- Per-device/group route policy.
- “who → service → route” activity view.
- Bounded privacy-respecting history; no cloud telemetry.

## Active Apply gate

No general active-routing release until all of these pass on real Keenetic/Netcraze hardware:

- authenticated mutation + Origin gate survives reboot, token-permission and LAN penetration tests,
- version/schema/native config checks,
- snapshot + generation rollback,
- boot-loop prevention,
- WAN/LAN binding,
- DNS ownership/coexistence,
- IPv4 + IPv6,
- hardware acceleration/offload checks,
- low-memory tests,
- simultaneous nfqws2 + usque + sing-box compatibility,
- manager crash test (internet must survive),
- reboot/start-order test,
- uninstall restores only RAZVILKA-owned changes.
