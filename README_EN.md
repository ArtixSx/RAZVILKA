# RAZVILKA

A local control panel for Keenetic and Netcraze routers with Entware.
Manage services, connections, bypass components and devices in one place.
Select the sites and devices you need, verify a connection and apply its route
manually or allow Autopilot to find a verified fallback. The application and
saved schedules run on the router when the browser is closed.
No RAZVILKA cloud account is required.

[Русский](README.md) · [Downloads](https://github.com/ArtixSx/RAZVILKA/releases) ·
[Current status (RU)](docs/CURRENT_STATUS_RU.md) · [Changelog](CHANGELOG.md) ·
[Report an issue](https://github.com/ArtixSx/RAZVILKA/issues)

**RAZVILKA 0.18.4** provides Autopilot, connection checks, bypass settings
and local configuration tools. [Verified scenarios and limitations (RU)](docs/CURRENT_STATUS_RU.md)
are documented separately. The installation command downloads the published stable release.

## Features in the current project

- Service routes for selected devices, with checks, explicit application and
  restoration of previous settings on failure.
- VLESS, Hysteria2, TUIC and Shadowsocks connections: imports, subscriptions,
  readable country names, node checks and permitted fallback candidates.
- NFQWS2, Sing-box/Xray, USQUE, WARP and AmneziaWG workspaces, subject to the
  capabilities of the installed component and profile.
- An Autopilot setup wizard with device scope, permitted sources and
  scheduled checks.
- Diagnostics, component versions, DNS response comparison and private
  backups. Dark appearance is the default.

Version 0.18.4 also adds **Mihomo configuration export**, an **experimental HEV profile
generator**, and **manual import/export of NFQWS2 strategy packs**. Mihomo and
HEV are not yet available as complete managed routes; generating a file does
not start them on the router. An imported strategy is a candidate requiring
separate validation. Automatic software installation is not enabled: scheduled
maintenance can check versions and prepare an application archive.
[EXT5 scope and remaining work (RU)](docs/extensions/EXT5_RU.md).

## Fresh installation

Install Entware for your router model and firmware first. After clearing a USB
drive, restore Entware and the `/opt` mount before installing RAZVILKA.
Run these commands over SSH as `root`:

```sh
test -d /opt && command -v opkg
opkg update
opkg install curl ca-certificates coreutils-sha256sum tar
```

Install the latest **stable** release:

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

The installer selects the router architecture, checks SHA256, installs the panel
and verifies startup. Supported binary targets are `arm64` (aarch64), `mipsle`
(mipsel), `mips` and `amd64`. Install the required bypass components separately;
their compatibility also depends on the router model and kernel.

## First use of version 0.18.4

These steps describe setup for version 0.18.4.

1. Open `http://192.168.1.1:8787` from the LAN, substituting your router's LAN
   address if different. Set your own username and password.
2. Use the wizard to choose devices, services, available methods and sources.
   A fresh 0.18.4 catalog contains six NFQWS2 groups; add other services separately.
3. Configure a bypass component or import a connection, then check it against
   the intended service.
4. Apply changes or authorize Autopilot for the selected scope. Safe Mode is
   enabled by default and requires a separate action to release.

A running process, DNS answer or reachable port does not establish that a site
works through the intended route. Check the result shown for the service itself.

Read the installed version, panel status and LAN address:

```sh
/opt/bin/razvilka -version
/opt/etc/init.d/S99razvilka status
/opt/etc/init.d/S99razvilka lan-ip
```

## Updates and documentation

Published archives are available in [Releases](https://github.com/ArtixSx/RAZVILKA/releases).
For a manual update, extract the chosen release's Entware archive and run these
commands from its directory, proceeding to installation only after successful
preflight:

```sh
sh scripts/upgrade-entware.sh --dry-run
sh scripts/upgrade-entware.sh --apply
```

Keep a private backup and the snapshot path printed by the installer for rollback.
Updates preserve the existing user catalog.

See [current results and limitations (RU)](docs/CURRENT_STATUS_RU.md) and the
[EXT5 development plan (RU)](docs/extensions/CODEX_EXT5_RU.md). Historical versions
and test reports are kept in the [Changelog](CHANGELOG.md) and
[release reports](docs/releases). Results from an older build do not validate
a newer one; an architecture build does not certify a particular router.

[Security](SECURITY.md) · [News and support](https://t.me/RAZVILKA_UI) ·
[MIT license](LICENSE)
