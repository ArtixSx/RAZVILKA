# RAZVILKA

![RAZVILKA — service-first routing hub](docs/assets/razvilka-banner.png)

[![CI](https://github.com/ArtixSx/RAZVILKA/actions/workflows/ci.yml/badge.svg)](https://github.com/ArtixSx/RAZVILKA/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ArtixSx/RAZVILKA?include_prereleases)](https://github.com/ArtixSx/RAZVILKA/releases)
[![License](https://img.shields.io/github/license/ArtixSx/RAZVILKA)](LICENSE)

[Русский](README_RU.md) · English

**Universal multi-engine routing hub for Keenetic / Netcraze + Entware.**

RAZVILKA is an open-source local-first routing hub and control plane that unifies multiple bypass/routing engines behind one service-oriented Web UI. It keeps service intent separate from engine internals and is designed to choose, validate, apply and observe the best available route without hiding uncertainty.

> **Current status: v0.0.9-ui-layout / Safe Mode.** Authenticated service-route drafts, engine-config drafts, validation, import/export, diagnostics and current-routing probes work. Safe Mode intentionally blocks dataplane changes to firewall, DNS and policy routes.

## v0.0.9 UI Layout

- Full-page panels now size to their content instead of reserving most of the viewport.
- Section headers no longer shift down and cover the first rows inside clipped panels.
- Web assets use versioned URLs so an upgraded router cannot serve stale layout CSS from browser cache.

## v0.0.8 Security Gate

### Security Gate

- A random 256-bit administrator token is created at `/opt/etc/razvilka/admin.token` with mode `0600`.
- Every state-changing API request requires `Authorization: Bearer`, `application/json` and a matching browser `Origin`.
- The Web UI asks for the token on the first write and keeps it in `sessionStorage` only for the current tab.
- Read-only status endpoints remain available on the LAN so the dashboard can load before authentication.
- Configuration persistence, engine staging and source caches use unique atomic transactions with `fsync`.
- Secret engine configurations remain redacted; v0.0.8 does not expose private keys or proxy credentials to the browser.

### Service routing

- 16-service catalog and per-service `AUTO / DIRECT / engine` selectors.
- Desired / planned / applied state kept separate.
- Draft / Apply / Discard workflow for service routing.
- Engine-agnostic Connections model + SSE stream for future real dataplane evidence.

### Config Center

Each supported engine has one management workspace instead of requiring reinstall/repackaging after every configuration change.

- NFQWS2: `nfqws2.conf`, `user.list`, `auto.list`, `exclude.list`, `ipset.list`, `ipset_exclude.list`.
- usque/MASQUE: `usque.conf`.
- WARP WireGuard, sing-box, Xray and AmneziaWG manifests are registered, but their secret content is deliberately redacted even for the authenticated UI.
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
- Source lists enforce safe IDs/redirects, are size/type validated, atomically cached and revalidated after restart.
- Control plane is separate from future dataplane.
- UI stays LAN-only. Bearer authentication and Origin checks are mandatory for mutations; active dataplane writes still require transactional adapters and rollback.

## Development run

```sh
go run ./cmd/razvilka \
  --config ./configs/config.example.json \
  --catalog ./configs/service-catalog.json \
  --sources ./configs/sources.json \
  --cache /tmp/razvilka-cache \
  --stage /tmp/razvilka-stage \
  --backups /tmp/razvilka-backups \
  --token-file /tmp/razvilka-admin.token \
  --listen 127.0.0.1:8787
```

## Checks

```sh
./scripts/check.sh
```

The check script runs Go tests, the race detector, vet, shell/JavaScript syntax checks, cross-builds linux amd64/arm64/mips/mipsle, verifies binary checksums and exercises the full Entware apply/rollback transaction without rewriting source files.

## Entware Lab install

A source checkout does **not** commit generated binaries. Build them first:

```sh
./build.sh
./scripts/lab-bootstrap.sh
```

GitHub Releases package the cross-built binaries automatically. The bootstrap runs preflight before/after install and installs only the RAZVILKA Manager. It does not install or activate bypass engines.

## Transactional Entware upgrade

Upgrade defaults to a read-only dry-run. An active ARTEM Flow instance requires an explicit, reversible handover flag:

```sh
./scripts/upgrade-entware.sh --dry-run --from-artem-flow
./scripts/upgrade-entware.sh --apply --from-artem-flow
```

Preflight verifies the architecture, optional release checksum, candidate binary, config schema, service catalog and sources registry before writing. Apply creates a root-only snapshot, installs files atomically, migrates the config and rolls back automatically unless the exact RAZVILKA/version health check succeeds.

Manual rollback uses the recorded snapshot:

```sh
./scripts/rollback-entware.sh "$(cat /opt/var/lib/razvilka/current-backup)"
```
`uninstall-entware.sh` uses the same snapshot automatically. After an ARTEM Flow handover it restores the previous binary, init and running state instead of leaving the legacy service disabled.


Service lifecycle and boot guard:

```sh
/opt/etc/init.d/S99razvilka status
/opt/etc/init.d/S99razvilka restart
/opt/etc/init.d/S99razvilka guard-status
/opt/etc/init.d/S99razvilka clear-guard
```

Three failed starts within five minutes block further automatic starts until the failure is inspected and the guard is explicitly cleared. The built-in health check has a four-second timeout and accepts only the exact current RAZVILKA name, version and pidfile process ID.
