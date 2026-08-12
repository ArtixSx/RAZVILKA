# RAZVILKA architecture

## Product split

RAZVILKA separates three truths that must not be confused:

1. **Desired state** — what the user selected.
2. **Planned state** — what AUTO currently resolves to.
3. **Applied/runtime evidence** — what was committed and what actual traffic used.

The UI should never label a planned route as an observed connection.

## Control plane

```text
Browser
  ↕ REST + SSE
RAZVILKA manager
  ├── Config store (draft + applied generation)
  ├── Service catalog
  ├── Validated source cache
  ├── System/capability probe
  ├── Engine inventory + version matrix (next)
  ├── Route planner / AUTO policy
  ├── Normalized telemetry store
  ├── Health/service probes (next)
  └── Transaction coordinator (next)
```

The Web UI is embedded static HTML/CSS/JS. No Node/PHP/frontend runtime is required on the router.

## Dataplane adapters

```text
classifier (service/domain/IP/device/protocol)
  → policy generation
    ├── DIRECT
    ├── NFQWS2 / local DPI
    ├── usque / WARP MASQUE
    ├── WARP WireGuard
    ├── sing-box outbounds
    ├── optional Xray outbounds
    └── optional AmneziaWG / other adapter
```

Adapters must expose a normalized contract instead of leaking engine-specific state into the UI:

- detect + version
- capabilities
- generate
- native validation
- isolated probe
- apply generation
- rollback
- health
- telemetry/evidence

## Engine schema/capability gate

A binary being present is not sufficient. Before generation:

```text
engine binary
  → exact version
  → RAZVILKA capability matrix
  → generate only supported schema
  → engine-native config check
```

This avoids coupling a newer config generator to an older core that rejects newer fields.

## Apply transaction

Target transaction:

```text
1. Freeze draft revision
2. Resolve AUTO routes
3. Check engine/version/capabilities
4. Generate all artifacts into generation-N.tmp
5. Run native syntax/config checks
6. Check ports/TUN/NFQUEUE/route-loop constraints
7. Snapshot RAZVILKA-owned + touched system state
8. Start/test isolated adapters where possible
9. Run network/service-aware probes
10. Apply atomically
11. Verify post-apply health
12. Commit generation-N
13. On failure: rollback snapshot + previous generation
```

RAZVILKA-owned rules/configs must be clearly namespaced so uninstall/rollback can remove only RAZVILKA changes.

## Telemetry

Every adapter publishes the same connection/evidence model:

- service
- host / destination IP / port
- protocol
- source IP / friendly device name
- selected route
- actual chain
- upload/download counters where available
- timestamps
- evidence source

The UI receives normalized data over SSE and a REST snapshot fallback.

## Device layer

Future device discovery can merge data from Keenetic host/device information, neighbor tables, DHCP/DNS sources and adapter telemetry. Identity must be cached and bounded; IP alone is not a permanent identity.

Per-device routing must remain independent from per-service routing so the final rule can express:

```text
(device/group) + service + protocol → route policy
```

## AI/service-aware health

AI services are not ordinary TCP reachability targets. Probe state should distinguish:

- DNS failure
- route/connect failure
- TLS failure
- HTTP/application failure
- authentication-required but reachable
- region/egress rejection
- healthy service

AUTO must use `service_ok`, not merely low ping.

## Resource strategy

- Go manager: single native binary.
- Static embedded UI, system fonts, no CDN requirement.
- SSE instead of high-frequency full REST polling.
- Bounded telemetry history/caches.
- Expensive charts/history are optional/advanced.
- Hardware profile can disable heavy probes on low-memory routers.
