> **DC1 review · 0.18.2-dev.** Reviewed candidate with dark-first UI and fixes for autonomy, DNS, AWG, authentication and update checksums. See [review status and remaining work](docs/DC1_REVIEW_2026-09-13_RU.md). Historical release results below do not establish hardware readiness for this candidate.

> **Local Autonomy A1 source candidate (0.18.2-dev), not a release.** The integrated backend has not been built or hardware-tested. See [A1 scope and validation report](docs/AUTONOMY_A1_RU.md). Historical release/HIL claims below describe the rc.2 baseline, not this candidate.

<p align="center"><img src="docs/assets/razvilka-banner.png" alt="RAZVILKA routing control center" width="100%"></p>

<p align="center"><strong>Select a service. RAZVILKA verifies available bypasses and helps apply a suitable route safely.</strong></p>

<p align="center"><a href="README.md">Русский</a> · <a href="https://github.com/ArtixSx/RAZVILKA/releases">Releases</a> · <a href="docs/CURRENT_STATUS_RU.md">Verified status</a> · <a href="https://t.me/RAZVILKA_UI">Telegram</a> · <a href="SECURITY.md">Security</a></p>

# RAZVILKA

RAZVILKA is a free local-first routing panel for Keenetic/Netcraze routers with Entware. Enable Telegram, YouTube, Discord, ChatGPT or a custom resource; the panel collects its domains and IP networks, compares available bypasses and prepares a safe apply plan.

Credentials, configurations and diagnostics stay on the router. No RAZVILKA cloud account is required.

> The project is still undergoing hardware testing. Version `1.0.0` is reserved for the multi-router, IPv4/IPv6, reboot, low-memory and recovery release gate.

The stable release is `v0.18.0`. The
[0.18.1-rc.2 prerelease](docs/releases/0.18.1-rc.2.md) is for public testing:
a VLESS browser, scheduled subscriptions, fallback groups, persisted Autopilot
and manual modes, compact service cards, router-side check timers and an app
update workflow.

All 47 Go packages passed local tests and Windows race tests, alongside 21 UI
tests. The final ARM64 candidate passed mode persistence, checks with the
browser closed, component status and update refusal tests. Its fresh saved
VLESS check was INCONCLUSIVE; applied routes stayed empty. A working route and
A → B failover have not been verified for this release. MIPS/MIPSel hardware,
WARP, reboot and extended testing remain open. See the
[release notes](docs/releases/0.18.1-rc.2.md) and
[verified status](docs/CURRENT_STATUS_RU.md) for the exact boundaries.

The command below installs latest stable. To test rc.2, download its versioned
prerelease archive and use the bundled install instructions.

For MIPS, `uname -m = mips` does not distinguish byte order. Use the official
Entware package for your firmware and confirmed BE/LE architecture. The
RAZVILKA installer checks the running shell's ELF header before choosing a
MIPS binary and refuses an unknown result; this is not MIPS hardware acceptance.

## Install

Enable Entware, connect over SSH as `root`, then run:

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

The installer verifies the router architecture and release checksum, creates a rollback snapshot, starts the local UI and prints its URL plus a one-time setup key. Only the UI is installed by default; add the required bypasses later from the **Bypasses** page.

## Basic workflow

1. Install the required component. VLESS uses Sing-box.
2. Import your profile or fetch candidates from a public subscription.
3. Check a node against the service you need. Connection time and service
   health are separate: low latency does not prove that a service works.
4. Select the service and devices, review the route and apply it. The
   transaction checks the candidate and verifies the result, with rollback
   if activation fails.

Automatic replacement uses an explicitly selected fallback group. A
subscription refresh only fetches candidates; it does not itself authorize
traffic switching. Autopilot follows saved permissions for the selected
Sing-box fallback group and devices. Manual mode is separate from Safe Mode.
Check timers persist on the router and run with the browser closed; an
inconclusive check is not reported as a working route.

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

Exact node checks verify the protocol, a separate egress, the service hostname
and its public IPv4 using the original TLS identity. Applied node recovery
performs a new check after application restart and preserves user drafts.
Native WARP enrollment supports account reuse and encrypted state backup;
creating an account does not establish a working tunnel.

Hardware evidence is tracked per build. The current rc.2 candidate passed
control and timer checks, but its fresh VLESS check was inconclusive and no
routes were applied. Earlier successful core tests do not establish hardware
acceptance for this release. Reliable WARP fallback and MIPS/MIPSel hardware
operation are not claimed.

## App updates

The version button in rc.2 prepares a compatible official stable release.
After archive and compatibility checks, a separate install action invokes the
transactional installer with a backup, startup healthcheck and rollback.
Older stable releases cannot replace newer development builds. Isolated test
instances and unsafe ownership or paths are refused. SHA256 integrity checking
is not described as signature verification. An actual production upgrade
through this button still needs hardware acceptance.

## Recommendations

- Keep the UI on the LAN; do not expose its port to the internet.
- Keep Safe Mode enabled until diagnostics and route tests pass.
- Use a confirmed tunnel for full IP blocking; NFQWS2 primarily addresses DPI scenarios.
- Save a backup before upgrades.

Release notes, compatibility information and downloads live in [GitHub Releases](https://github.com/ArtixSx/RAZVILKA/releases). Support: [@RAZVILKA_UI](https://t.me/RAZVILKA_UI). Issues: [GitHub Issues](https://github.com/ArtixSx/RAZVILKA/issues).
