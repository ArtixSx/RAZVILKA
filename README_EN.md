# RAZVILKA

A local control panel for Keenetic/Netcraze routers with Entware. Configure
services, devices and connections; review and apply routes, manage backups
and grant bounded Autopilot permissions. The application runs on the router,
and saved schedules continue when the browser is closed.

The panel uses the router's LAN address on port **8787**, commonly
`http://192.168.1.1:8787`. Credentials and private profiles stay locally;
no RAZVILKA cloud account is required.

[Русский](README.md) · [Downloads](https://github.com/ArtixSx/RAZVILKA/releases) ·
[Verified status](docs/CURRENT_STATUS_RU.md) · [Security](SECURITY.md)

## Candidate status

The current candidate is [**v0.18.2-rc.6**](https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.18.2-rc.6).
It includes the panel, NFQWS2 editor and password fixes from rc.5, and adds
restoration of fully vanished owned firewall chains. See the
[release notes](docs/releases/0.18.2-rc.6.md). Full CI and hardware acceptance
of the official archive are separate requirements.

Continued rc.5 testing found loss of its owned filter chain after initial
successful checks. See the [rc.5 report](docs/releases/0.18.2-rc.5-validation.md).
Previous rc.4 results remain [historical evidence](docs/releases/0.18.2-rc.4-validation.md).

The latest stable release remains
[`v0.18.0`](https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.18.0).
Pin the candidate version explicitly using the instructions below.

The control plane supports scoped service routes, exact node checks,
subscriptions, permitted fallback, schedules, encrypted backups and component
workspaces. Available adapters include NFQWS2, Sing-box/Xray, USQUE, WARP and
AmneziaWG; actual use depends on installed capabilities and a verified profile.
Safe Mode is enabled by default. Importing or refreshing a subscription does
not itself authorize route changes.

DNS comparison currently returns A/AAAA results for a catalog service using
selected DoH profiles. Combined DNS + route + service proof, scoped DNS Apply
and automatic pair selection remain **DC2–DC4**. Recipe hints are an offline
library; cloud catalog downloads and result uploads are not enabled.

## Install

Install the appropriate Entware package for your router and firmware first.
An ambiguous `uname -m = mips` does not distinguish BE from LE; RAZVILKA checks
the running shell's ELF identity and refuses an unknown byte order.
Prepare the tools over SSH as `root`:

```sh
test -d /opt && command -v opkg
opkg update
opkg install curl ca-certificates coreutils-sha256sum tar
```

**Latest stable** (currently `v0.18.0`):

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

**DC1 prerelease `v0.18.2-rc.6`**:

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/v0.18.2-rc.6/scripts/bootstrap.sh | RAZVILKA_VERSION=v0.18.2-rc.6 sh
```

Alternatively, extract that release's Entware bundle and run
`sh scripts/upgrade-entware.sh --dry-run`, then `--apply` after successful
preflight. The installer verifies SHA256, saves a snapshot and checks startup.
Keep the printed snapshot path. The default installation adds the panel;
install the required bypass components separately and set your own login.

## Open the panel

```sh
/opt/bin/razvilka -version
/opt/etc/init.d/S99razvilka status
LAN_IP=$(/opt/etc/init.d/S99razvilka lan-ip)
/opt/bin/razvilka -healthcheck "http://$LAN_IP:8787/api/v1/status"
```

Open `http://<LAN_IP>:8787` from the LAN and test the intended service.
Do not expose the panel's port to the internet. A running process, DNS answer
or reachable TCP port alone does not establish a working service route.

Hardware acceptance remains specific to each binary. AWG 3.1/WARP, WAN
reconnect, reboot, IPv6 HTTPS, low-memory operation and a 24–72 hour soak need
their own results. ARM64/MIPS/MIPSle/amd64 builds do not certify every device.
Public nodes can become unavailable after a successful check.

[DC1 changes and remaining work](docs/DC1_REVIEW_2026-09-13_RU.md) ·
[Roadmap](docs/ROADMAP_2026-08-30_RU.md) · [Changelog](CHANGELOG.md) ·
[Issues](https://github.com/ArtixSx/RAZVILKA/issues) · [MIT license](LICENSE)
