<p align="center"><img src="docs/assets/razvilka-banner.png" alt="RAZVILKA routing control center" width="100%"></p>

<p align="center"><strong>Select a service. RAZVILKA verifies available bypasses and helps apply a suitable route safely.</strong></p>

<p align="center"><a href="README.md">Русский</a> · <a href="https://github.com/ArtixSx/RAZVILKA/releases">Releases</a> · <a href="docs/CURRENT_STATUS_RU.md">Verified status</a> · <a href="https://t.me/RAZVILKA_UI">Telegram</a> · <a href="SECURITY.md">Security</a></p>

# RAZVILKA

RAZVILKA is a free local-first routing panel for Keenetic/Netcraze routers with Entware. Enable Telegram, YouTube, Discord, ChatGPT or a custom resource; the panel collects its domains and IP networks, compares available bypasses and prepares a safe apply plan.

Credentials, configurations and diagnostics stay on the router. No RAZVILKA cloud account is required.

> The project is still undergoing hardware testing. Version `1.0.0` is reserved for the multi-router, IPv4/IPv6, reboot, low-memory and recovery release gate.

The latest stable release is `v0.18.0`; `main` is the `0.18.1-dev` development
cycle. The [verified status](docs/CURRENT_STATUS_RU.md) separates implemented,
CI-tested, router-tested and experimental capabilities.

## Install

Enable Entware, connect over SSH as `root`, then run:

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

The installer verifies the router architecture and release checksum, creates a rollback snapshot, starts the local UI and prints its URL plus a one-time setup key. Only the UI is installed by default; add the required bypasses later from the **Bypasses** page.

## Basic workflow

1. Install the required component from **Bypasses**.
2. Enable a resource in **Services** and keep **Autopilot (AUTO)**, or pin a route manually.
3. Click **Save and verify**. RAZVILKA validates the candidate, applies it transactionally and restores the previous route on failure. The separate test lab remains available for manual diagnostics.

Safe Mode is enabled after installation and prevents unconfirmed firewall, DNS, TUN and policy-routing changes.

## Supported routes

| Bypass | Intended use |
|---|---|
| **NFQWS2** | DPI throttling and domain filtering without a remote server |
| **WARP · MASQUE** | Full IP blocks through Cloudflare MASQUE when the transport is reachable |
| **WARP · WireGuard** | Free split tunnel after a confirmed handshake |
| **Sing-box** | VLESS/Reality, Hysteria2, TUIC and Shadowsocks using your server or profile |
| **Xray** | Alternative VLESS/Reality client |
| **AmneziaWG** | A compatible AmneziaWG server when ordinary WireGuard is identified by the network |

RAZVILKA also includes custom domain/IP/CIDR services, Telegram Web and Core/API scenarios, verified NFQWS2 strategy memory, DNS profiles, device-scoped routes, router resource/traffic metrics, public profile exchange, encrypted private backups and transactional `plan → snapshot → validate → health → commit/rollback`.

## Recommendations

- Keep the UI on the LAN; do not expose its port to the internet.
- Keep Safe Mode enabled until diagnostics and route tests pass.
- Use a confirmed tunnel for full IP blocking; NFQWS2 primarily addresses DPI scenarios.
- Save a backup before upgrades.

Release notes, compatibility information and downloads live in [GitHub Releases](https://github.com/ArtixSx/RAZVILKA/releases). Support: [@RAZVILKA_UI](https://t.me/RAZVILKA_UI). Issues: [GitHub Issues](https://github.com/ArtixSx/RAZVILKA/issues).
