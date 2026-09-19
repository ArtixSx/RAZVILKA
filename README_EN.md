<p align="center">
  <img src="docs/assets/razvilka-banner.png" alt="RAZVILKA — router connection management" width="960">
</p>

# RAZVILKA

**Choose which services use which connection, directly on your router.**

A local web panel for **Keenetic and Netcraze with Entware**. Manage services,
devices, NFQWS2, WARP and VPN connections in one place. The panel and saved
schedules run on the router without an open browser.

[Download stable release](https://github.com/ArtixSx/RAZVILKA/releases/latest) ·
[Install](#install) · [Documentation](docs/README.md) · [Русский](README.md) ·
[News and support](https://t.me/RAZVILKA_UI)

## Features

| Panel section | Purpose |
| --- | --- |
| Home and Autopilot | View network state and choose services, devices and permitted connections |
| Services | Assign a route to a site or application, check access and apply changes |
| Connections | Import VLESS and other profiles, refresh subscriptions and select nodes by country and check results |
| Bypasses | Install and configure the required NFQWS2, WARP, Sing-box or other components |
| Devices | Restrict a route to selected devices |
| Events and settings | Review errors, component versions and backups |

Autopilot operates within your settings. Access depends on the node, provider
and router capabilities; a running process alone does not establish a working
connection. [Verified results and limitations (RU)](docs/CURRENT_STATUS_RU.md).

## Install

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
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh
```

The script runs only after a successful download. It adds missing basic tools,
selects the architecture, checks the stable release checksums and starts the panel.
Install the required bypass components separately.

### 3. Open the panel and configure a connection

Open **[http://192.168.1.1:8787](http://192.168.1.1:8787)**, or your router's LAN
address on port `8787`. The installer prints the actual address.

1. Use the first-run key or setup link to create your login and password.
   Keep the recovery key somewhere safe.
2. Use the Autopilot wizard to choose services and devices, or configure them manually.
3. Install the required component in the bypass section and add VLESS or another
   profile in the connections section.
4. Check access to the selected service and apply its route. Safe Mode is enabled
   on a fresh installation; enabling routes requires a separate action.

## Update

Run the installer again to get the latest stable release. It preserves settings
and creates a rollback snapshot:

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh
```

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
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh --uninstall
```

This removes the panel, its startup service and its own active routes. Settings,
connections and backups are retained for reinstalling. Entware and separately
installed engines remain.

## Further reading

- [Installation, manual updates, removal and rollback (RU)](docs/INSTALL_RU.md).
- [Current status and verified results (RU)](docs/CURRENT_STATUS_RU.md).
- [Repository files explained (RU)](docs/FILES_RU.md).
- [Roadmap (RU)](docs/ROADMAP.md) · [Changelog](CHANGELOG.md).
- [Contributing and bug reports (RU)](CONTRIBUTING.md).
- [Security (RU)](SECURITY.md) · [Third-party components](THIRD_PARTY.md) · [MIT license](LICENSE).
