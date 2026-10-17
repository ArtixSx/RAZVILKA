<p align="center">
  <img src="docs/assets/razvilka-banner.png" alt="RAZVILKA — router connection management" width="960">
</p>

# RAZVILKA

> Documentation for the upcoming **0.20.0**: a clean installation and subsequent
> updates to **0.20+** releases. End-to-end list and exclusions acceptance and the
> one-hour Telegram over VLESS check remain incomplete. [Current status (RU)](docs/CURRENT_STATUS_RU.md).

**Choose which services use which connection, directly on your router.**

A local web panel for **Keenetic and Netcraze with Entware**. Manage services,
devices, NFQWS2, WARP and VPN connections in one place. The panel and saved
schedules run on the router without an open browser.

[Published releases](https://github.com/ArtixSx/RAZVILKA/releases) ·
[Install](#install) · [Documentation](docs/README.md) · [Русский](README.md) ·
[News and support](https://t.me/RAZVILKA_UI)

The banner is project artwork, not a screenshot of a running panel. Screenshots
of the clean 0.20.0 installation will follow verification; unfinished tests are
not presented as completed results.

## Features

| Panel section | Purpose |
| --- | --- |
| Home and Autopilot | View network state and choose services, devices and permitted connections |
| Services | Assign a route to a site or application, check access and apply changes |
| Connections | Import VLESS and other profiles, refresh subscriptions, select nodes by country and check results, and open bypass settings |
| Devices | Choose the home network and excluded devices, or limit bypass to individual devices when needed |
| Events and settings | Review errors, install and update components, manage access and backups |

Autopilot operates within your settings. Access depends on the node, provider
and router capabilities; a running process alone does not establish a working
connection. [Verified results and limitations (RU)](docs/CURRENT_STATUS_RU.md).

## How traffic is selected

For 0.20.0, the approved policy is **bypass only for the active list** of services,
domains and supported IP/CIDR rules in selected home networks. The list can cover
an entire selected network without assigning every service to every device.
For example, enabled YouTube applies to that network while an excluded TV keeps
its ordinary route. An excluded site also keeps its ordinary route even when
it belongs to an enabled service. This is the intended behavior; end-to-end
router verification of the shared network mode remains incomplete.

- Device exclusions, manual resource exclusions and the accepted Russian resource
  list take priority over positive rules and a pinned connection.
- An empty list and traffic without a match use the router's ordinary policy.
- Downloading a catalog or updating its definitions does not activate bypass.

Applying a plan depends on the engine, firmware and selected scope.
[Full list and exclusions contract (RU)](docs/delivery-2026-10-03/LIST_MODE_CORRECTION_RU.md).

## Install

These instructions cover a **clean installation of 0.20.0** on Entware without
an existing RAZVILKA installation. Migration from 0.19.3 is outside this scope.
The installation command below requires the published `v0.20.0` tag in
[Releases](https://github.com/ArtixSx/RAZVILKA/releases); this version cannot be
installed before that release is published.

### 1. Prepare Entware

Install **Entware**, mount `/opt`, and connect to its shell over SSH as `root`.
[Entware preparation (RU)](docs/INSTALL_RU.md#подготовка-entware).
The firmware's `(config)>` prompt is a different console; use the Entware shell
for the commands below.

| Platform | Entware installer | RAZVILKA binary |
| --- | --- | --- |
| AArch64 / ARM64 | [aarch64-k3.10](https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz) | `arm64` |
| MIPS | [mipssf-k3.4](https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz) | `mips`, soft-float |
| MIPSel | [mipselsf-k3.4](https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz) | `mipsle`, soft-float |

> The three architectures are build targets. Current managed LIST startup is
> tied to the reviewed stock NC-1812 profile; other ARM64, MIPS and MIPSel targets
> are refused for this mode. [Runtime support matrix (RU)](docs/RUNTIME_SUPPORT_RU.md).

Check that Entware is available:

```sh
export PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:$PATH
test -d /opt && command -v opkg
```

If no path to `opkg` appears, finish setting up Entware. Then prepare HTTPS downloads:

```sh
export PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:$PATH
opkg update && opkg install curl wget-ssl ca-certificates ca-bundle
```

### 2. Download and run the installer

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/v0.20.0/scripts/bootstrap.sh &&
RAZVILKA_VERSION=v0.20.0 sh /opt/tmp/razvilka-setup.sh
```

The script runs only after a successful download. It adds missing basic tools,
selects the architecture, checks the selected release checksums and starts the panel.
Install the required bypass components separately.

Settings and connections for 0.20+ are stored in `/opt/etc/razvilka`; working
data is stored in `/opt/razvilka/{state,run,cache,log}`. Update snapshots are
stored in `/opt/razvilka/state/update-backups`.

### 3. Open the panel and configure a connection

Open **[http://192.168.1.1:8787](http://192.168.1.1:8787)**, or your router's LAN
address on port `8787`. The installer prints the actual address.

1. Use the first-run key or setup link to create your login and password.
   Keep the recovery key somewhere safe.
2. Use the Autopilot wizard to choose services and devices, or configure them manually.
3. Install the required component through component settings and add VLESS or another
   profile in the connections section.
4. Check the selected connection for the service, review the plan and apply it
   after enabling routes. Nothing is applied before this review and your confirmation.
   A node check from the router and access from the selected client device are checked separately.

## Subsequent updates to 0.20+ releases

An installed 0.20+ release updates from the panel: «Обновления» (Updates) → check
the version → install the selected release, or automatically on schedule. The panel
downloads the verified release from GitHub, keeps settings, creates a snapshot and
returns the previous version on failure.

Bootstrap and the manual archive installer are for new installations. On an
installed 0.20+ release the installer refuses ("Use matching self update recovery…"
or "This controller requires the journaled self update workflow…") and changes
nothing: a raw binary replacement would bypass the update journal and its rollback.

Scheduled update settings are located separately under «Обновления»
(Updates) → «Окна обслуживания» (Maintenance windows) → «Изменить расписание»
(Change schedule). The interface distinguishes checking, preparing and installing
application updates automatically. Scheduled automatic installation is implemented.
End-to-end installation and rollback acceptance on the target Entware system for
0.20.0 (D11) remains incomplete; readiness is recorded in [current status (RU)](docs/CURRENT_STATUS_RU.md).

Wait for the check result and retain the printed snapshot path. If the route is
not confirmed after the update, inspect the installation result and diagnostics;
a working panel does not establish that its bypass has recovered.

Check the installed version and panel state:

```sh
/opt/bin/razvilka -version
/opt/etc/init.d/S99razvilka status
```

## Uninstall

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/v0.20.0/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh --uninstall
```

This removes the panel, its startup service and its own active routes. Settings,
connections and backups are retained. Entware and separately installed engines
remain. Reinstalling over the retained data is not yet supported by the installer:
the update control journal (`/opt/razvilka/state/self-update-stop`) is retained and
the installer refuses. Do not delete that directory by hand.

## Further reading

- [Upcoming 0.20.0 release notes (RU)](docs/RELEASE_0.20.0_RU.md).

- [Installation, manual updates, removal and rollback (RU)](docs/INSTALL_RU.md).
- [Current status and verified results (RU)](docs/CURRENT_STATUS_RU.md).
- [Repository files explained (RU)](docs/FILES_RU.md).
- [Roadmap (RU)](docs/ROADMAP.md) · [Changelog](CHANGELOG.md).
- [Contributing and bug reports (RU)](CONTRIBUTING.md).
- [Security (RU)](SECURITY.md) · [Third-party components](THIRD_PARTY.md) · [MIT license](LICENSE).

## Recommendations and support

Start with one service and one connection, then test access from the intended
home device. Saved settings, an applied route and verified service access are
different facts; a retained snapshot does not establish current availability.
Keep the panel on your trusted LAN, store the recovery key separately and make
a backup before changes. Preserve recovery journals; do not run a global
`opkg upgrade` just to update the panel.

News, questions and contributions: [RAZVILKA on Telegram](https://t.me/RAZVILKA_UI).
[Donate](https://dalink.to/artixsx).
