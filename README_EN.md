<p align="center"><img src="docs/assets/razvilka-banner.png" alt="RAZVILKA routing control center" width="100%"></p>

<p align="center"><strong>Select a service. RAZVILKA finds, verifies and safely applies a suitable route.</strong></p>

<p align="center"><a href="README.md">Русский</a> · <a href="https://t.me/RAZVILKA_UI">Telegram</a> · <a href="https://github.com/ArtixSx/RAZVILKA/releases">Releases</a> · <a href="SECURITY.md">Security</a></p>

# RAZVILKA

RAZVILKA is a free local-first routing control center for Keenetic/Netcraze routers with Entware. Users enable Telegram, YouTube, Discord, ChatGPT or a custom service; RAZVILKA manages its domains and IP networks, compares available bypasses and applies the selected route with backup and automatic rollback.

The UI, credentials, configurations and diagnostics remain on the router. No RAZVILKA cloud account is required.

![RAZVILKA overview](docs/screenshots/overview-v0.14.0.png)

![Service catalog and IP-network coverage](docs/screenshots/services-v0.14.0.png)

## Install

Enable Entware storage, connect over SSH as `root`, then run:

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

The installer verifies the release checksum, snapshots the previous installation, starts the local UI and prints its URL plus a one-time setup key. Only the control plane is installed by default; add the required bypasses from the UI.

## Choosing a route

| Bypass | Best for | Requirement |
|---|---|---|
| NFQWS2 | DPI throttling and domain filtering | no remote server |
| WARP · MASQUE | full IP blocks over MASQUE QUIC/UDP 443, with TCP/443 checked as a fallback | Cloudflare reachability |
| WARP · WireGuard | free split tunnel where Cloudflare UDP works | generated profile and real handshake |
| Sing-box / Xray | VLESS, Reality, Hysteria2, TUIC, Shadowsocks | your remote server/profile |
| AmneziaWG | networks that identify ordinary WireGuard | compatible server and runtime |

Telegram routing includes its web domains and official IPv4/IPv6 MTProto/media networks. Service-scoped source lists cannot leak into unrelated routes.
Its Test Lab scenarios check the public site, Web client and Core/API independently; one successful landing page cannot hide a required scenario failure.

WARP checks distinguish registration TLS, MASQUE TCP/443 connectivity and a real WireGuard handshake. Failed activation rolls back temporary interfaces and rules before reporting the error.

The DNS tab offers system, Cloudflare, Quad9, AdGuard and Google profiles with direct resolver probes and an ownership-aware preview plan. Live DNS replacement remains disabled until the Keenetic/Netcraze system-resolver adapter passes hardware rollback tests.

## Safety and status

Safe Mode is enabled by default. Changes follow `plan → snapshot → validate → health → commit/rollback`. Version `1.0.0` is reserved for the wider multi-router, reboot, IPv6, low-memory and recovery release gate.

See [README.md](README.md), [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md) and [security policy](SECURITY.md). Support: [@RAZVILKA_UI](https://t.me/RAZVILKA_UI).
