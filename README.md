# RAZVILKA

[Русский](README_RU.md) · English

**Universal multi-engine routing hub for Keenetic / Netcraze + Entware.**

RAZVILKA is an open-source local-first routing hub and control plane that unifies multiple bypass/routing engines behind one service-oriented Web UI. It keeps service intent separate from engine internals and is designed to choose, validate, apply and observe the best available route without hiding uncertainty.

> **Current status: v0.0.7-control-lab / Safe Mode.** Service-route drafts, engine-config drafts, validation, import/export, diagnostics and current-routing probes work. Safe Mode intentionally blocks writes to live engine configs and does not modify firewall, DNS or policy routes.

## v0.0.7 Control Lab

### Service routing

- 16-service catalog and per-service `AUTO / DIRECT / engine` selectors.
- Desired / planned / applied state kept separate.
- Draft / Apply / Discard workflow for service routing.
- Engine-agnostic Connections model + SSE stream for future real dataplane evidence.

### Config Center

Each supported engine has one management workspace instead of requiring reinstall/repackaging after every configuration change.

- NFQWS2: `nfqws2.conf`, `user.list`, `auto.list`, `exclude.list`, `ipset.list`, `ipset_exclude.list`.
- usque/MASQUE: `usque.conf`.
- WARP WireGuard, sing-box, Xray and AmneziaWG manifests are registered, but their secret content is deliberately hidden from the unauthenticated browser UI.
- Fixed file manifests only: the browser cannot request arbitrary filesystem paths.
- Maximum draft size 2 MiB, atomic staging and mode `0600`.
- Draft -> basic/native validation -> backup -> live apply model.
- JSON validation and native `sing-box check` / Xray test where the binary supports it.
- Shell syntax validation for NFQWS2/usque configs.
- Domain/CIDR list validation.
- Import/export for non-sensitive files.
- Safe Mode blocks live writes and preserves drafts.

### Bypass Test Lab

- `Current routing` test performs real HTTP probes for catalog services through the configuration currently applied on the router.
- Results are `PASS / PARTIAL / FAIL / NOT READY` with HTTP status and latency.
- The route matrix is already present but does **not** invent per-engine results. Until an isolated adapter exists, cells show engine readiness (`NOT READY / ADAPTER`).
- The API accepts catalog service IDs only, not arbitrary browser-supplied URLs.
- Future route-specific sweep will isolate each engine, run service-aware probes, record evidence and rollback without changing the user's normal route.

### Device safety

- Detects architecture, RAM, `/opt`, opkg, WAN, TUN, iptables/ip6tables/nft and NFQUEUE.
- Detects NFQWS2, usque, WARP-WG, sing-box, Xray and AmneziaWG.
- Detects existing external tunnel routes and warns when CURRENT tests may be contaminated by them.
- Source lists are downloaded to temporary storage, validated and atomically cached.
- Control plane is separate from future dataplane.
- UI should stay LAN-only. Mandatory session authentication + CSRF protection is the next gate before secret-config editing or active dataplane writes.

## Development run

```sh
go run ./cmd/razvilka \
  --config ./configs/config.example.json \
  --catalog ./configs/service-catalog.json \
  --sources ./configs/sources.json \
  --cache /tmp/razvilka-cache \
  --stage /tmp/razvilka-stage \
  --backups /tmp/razvilka-backups \
  --listen 127.0.0.1:8787
```

## Checks

```sh
./scripts/check.sh
```

The check script runs Go tests/vet, shell and JavaScript syntax checks, cross-builds linux amd64/arm64/mips/mipsle and verifies binary checksums.

## Entware Lab install

A source checkout does **not** commit generated binaries. Build them first:

```sh
./build.sh
./scripts/lab-bootstrap.sh
```

GitHub Releases package the cross-built binaries automatically. The bootstrap runs preflight before/after install and installs only the RAZVILKA Manager. It does not install or activate bypass engines.
