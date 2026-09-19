<p align="center">
  <img src="docs/assets/razvilka-banner.png" alt="RAZVILKA — router connection management" width="960">
</p>

# RAZVILKA

**Choose which services use which connection, directly on your router.**

A local web panel for **Keenetic and Netcraze with Entware**. Manage services,
devices, NFQWS2, WARP and VPN connections in one place. Choose routes manually
or let Autopilot select verified connections within your settings. The panel
and saved schedules run on the router without an open browser.

[Download](https://github.com/ArtixSx/RAZVILKA/releases/latest) ·
[Documentation](docs/README.md) · [Русский](README.md) ·
[News and support](https://t.me/RAZVILKA_UI)

## Install

First install Entware for your router, mount `/opt`, and connect to its Entware
shell over SSH as `root`. [Entware preparation and detailed instructions](docs/INSTALL_RU.md).

| Platform | Entware installer | RAZVILKA binary |
| --- | --- | --- |
| AArch64 / ARM64 | [aarch64-k3.10](https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz) | `arm64` |
| MIPS | [mipssf-k3.4](https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz) | `mips`, soft-float |
| MIPSel | [mipselsf-k3.4](https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz) | `mipsle`, soft-float |

Run these **two commands** in the SSH shell:

```sh
opkg update && opkg install curl ca-certificates ca-bundle
```

```sh
mkdir -p /opt/tmp && curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh && sh /opt/tmp/razvilka-setup.sh
```

The installer adds missing basic utilities, selects the architecture, checks
the stable release checksums, and starts the panel.

Open **[http://192.168.1.1:8787](http://192.168.1.1:8787)**, or your router's LAN
address on port `8787`. Use the first-run key or setup link printed by the
installer to create your login and password. Use the Autopilot wizard
or configure routes manually. Install the required engine in the bypass section
and add VLESS or other profiles in the connections section. Routes are enabled
after configuration and checks.

## Update

Run the same installer to update to the latest stable release. It preserves
settings and creates a rollback snapshot:

```sh
mkdir -p /opt/tmp && curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh && sh /opt/tmp/razvilka-setup.sh
```

Check the installed version and service:

```sh
/opt/bin/razvilka -version
/opt/etc/init.d/S99razvilka status
```

## Uninstall

```sh
mkdir -p /opt/tmp && curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh && sh /opt/tmp/razvilka-setup.sh --uninstall
```

This removes the panel, its startup service and its own active routes. Settings,
connections and backups are retained for reinstalling. Entware and separately
installed engines remain. [Utilities, manual installation and rollback](docs/INSTALL_RU.md).
