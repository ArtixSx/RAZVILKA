<p align="center">
  <img src="docs/assets/razvilka-banner.png" alt="RAZVILKA — router connection management" width="960">
</p>

<h3 align="center">The services you choose, through the right connection — on the router itself</h3>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#update">Update</a> ·
  <a href="#uninstall">Uninstall</a> ·
  <a href="#recommendations">Recommendations</a> ·
  <a href="docs/INSTALL_RU.md">Detailed guide (RU)</a> ·
  <a href="README.md">Русский</a>
</p>

RAZVILKA is a local web panel for **Keenetic and Netcraze routers with Entware**.
You pick services and devices; the panel chooses and checks how to reach them:
NFQWS2, VLESS, WireGuard/AmneziaWG or WARP. It runs on the router itself and
keeps working on schedule with the browser closed.

Downloads and version changes — [Releases](https://github.com/ArtixSx/RAZVILKA/releases).

## How it works

<p align="center">
  <img src="docs/assets/razvilka-how-it-works.svg" alt="Traffic to enabled services takes the bypass; everything else uses the router's ordinary route" width="960">
</p>

- **Bypass only what you enabled.** Unlisted sites and apps keep the router's ordinary route,
  including your own VPN. An empty list does not change that route.
  NFQWS2 device exclusions use Keenetic policy; RAZVILKA's own device
  exclusions are not supported yet.
- **Site exclusions depend on the bypass method.** NFQWS2 leaves excluded
  domains and their subdomains untouched. For VPN and proxy routes, exclude
  an IP address, IP network or service: these routes cannot distinguish
  domain exclusions. An excluded address or service overlapping a VPN or
  proxy route blocks application with an explanation.
- **No capture of unrelated sites.** Services defined by domain names use only
  a method that checks the site name in every connection (NFQWS2). IP routing
  through a VPN or proxy is disabled for them: one IP can host unrelated sites.

## What it does

| | |
| --- | --- |
| 🧭 **Autopilot** | Checks the chosen services, selects a working path and reserve; lets you put your permitted sources first in the search order |
| 🧩 **Services** | Ready-made catalog and your own services; groups; access checks from the router |
| 🔌 **Connections** | VLESS/Xray, WireGuard, AmneziaWG, WARP; subscriptions, country filtering from publisher labels and separate access checks |
| 🛡️ **DPI bypass** | Managed NFQWS2 HTTPS profiles for domain lists, compatibility checks and rollback on failure |
| 📱 **Devices** | Experimental device selection on the exact NC-1812 profile; NFQWS2 uses Keenetic policy |
| 🧾 **Log and diagnostics** | Clear error causes, a support report, backups |
| 🔄 **Updates** | Available-release checks; the Test release requires a clean installation |

"Configured", "route applied" and "service reachable" are shown separately:
a running process alone does not prove that the bypass works.
The "Проверять сначала" setting orders permitted connection sources ahead
of the standard search when no working path exists or the current one fails.
A healthy connection stays in place; an empty list keeps the default order.
Full hardware acceptance of WireGuard, WARP and AmneziaWG is still pending;
listing a component does not establish support for every mode.

## Recommendations

- **Router.** Keenetic or Netcraze with a USB drive and [Entware](docs/INSTALL_RU.md#подготовка-entware).
  Best verified on **Netcraze Ultra (NC-1812), ARM64**. MIPS and MIPSel builds
  are published, but managed routes on MIPS/MIPSel are not available yet;
  a successful build does not establish runtime support.
- **Storage.** At least 1 GB free; a dedicated USB stick or SSD is better.
- **Router DNS must work** before installation: catalogs, subscriptions and
  checks rely on it. A DNS failure looks like an unreachable service.
- **One DPI bypass at a time.** Do not run z2k or a second nfqws2 next to
  RAZVILKA: two handlers of the same queue break connections.
- **Start small.** One service and one connection; test from the device you
  need, then add the rest.
- **Telegram goes through a VPN or proxy.** Add "Telegram · через VPN или прокси"
  from the catalog (Telegram's own networks only) and choose a VLESS node for it.
  Services defined by domains (YouTube, Discord and others) use NFQWS2.
- **Banks and government sites go to "Сайты без обхода".** If a site works
  without the bypass but worse with it, add it under "Исключения → Сайты без
  обхода" and press "Применить".
- **Security.** Do not expose the panel port `8787` to the Internet. Keep the
  recovery key away from the router. Do not run a general `opkg upgrade` for
  the panel's sake.

## Install

<p align="center">
  <img src="docs/assets/razvilka-install-steps.svg" alt="Three steps: Entware, one command, the panel on port 8787" width="960">
</p>

**1. Prepare Entware.** You need `/opt`, SSH access to the Entware shell as
`root`, and HTTPS download tools:

```sh
opkg update && opkg install curl wget-ssl ca-certificates ca-bundle
```

| Router architecture | Entware package | RAZVILKA build |
| --- | --- | --- |
| AArch64 / ARM64 | [aarch64-k3.10](https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz) | `arm64` |
| MIPS | [mipssf-k3.4](https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz) | `mips`, soft-float |
| MIPSel | [mipselsf-k3.4](https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz) | `mipsle`, soft-float |

**2. Install Test on a router without an existing RAZVILKA installation:**

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/v0.20.0-rc.71/scripts/bootstrap.sh &&
RAZVILKA_VERSION=v0.20.0-rc.71 sh /opt/tmp/razvilka-setup.sh
```

The explicit `RAZVILKA_VERSION` is required: it pins the archive to the same Test
release as the script. The installer detects the architecture, verifies SHA-256
and starts the service. Bypass components are installed later from the panel.
See the [release notes (RU)](https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.20.0-rc.71) for Test limitations.

**3. Open the panel** at **http://192.168.1.1:8787** (or your router's address
with port `8787`; the exact link is printed by the installer). Sign in with the
issued key, set a password, store the recovery key and follow the wizard:
devices → services → bypass methods.

Where things live: settings — `/opt/etc/razvilka`, runtime data —
`/opt/razvilka/{state,run,cache,log}`, update snapshots —
`/opt/razvilka/state/update-backups`.

## Update

**Upgrading to this Test from 0.19.x or another prerelease is unsupported.**
Save the settings you need, follow the removal instructions for your installed
version and install Test from scratch. Old control journals are not imported.
The default stable channel skips prereleases; an explicitly selected preview
channel may offer them. That does not establish support for installing over an RC.

The installer refuses to run over a working 0.20+ and changes nothing, so an
update never bypasses its own journal and rollback. To check the version:

```sh
/opt/bin/razvilka -version
/opt/etc/init.d/S99razvilka status
```

### Moving from 0.19.3 and older

0.20.0 is installed **from scratch**, without migrating old settings. The
installer refuses when it finds an old installation. Remove the old version with
its own uninstaller, then install 0.20.0 —
[step by step (RU)](docs/INSTALL_RU.md#переход-с-0193-и-более-ранних-версий).

## Uninstall

The command below is for an installed `0.20.0-rc.71`. For another version,
use the bootstrap and explicit `RAZVILKA_VERSION` from its release.

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/v0.20.0-rc.71/scripts/bootstrap.sh &&
RAZVILKA_VERSION=v0.20.0-rc.71 sh /opt/tmp/razvilka-setup.sh --uninstall --purge
```

Save the settings and connections you need first. This removes the panel,
its autostart and its own routes, then **moves** (does not erase) all data to
`/opt/razvilka-removed-<date>`, readable by `root` only. Entware, third-party
programs and installed bypass packages are not touched.
For a clean installation, repeat the Install command and configure the panel
again. The archive preserves your original data but is not an automatic import
package; do not copy its control journals into the new installation.

Without `--purge`, managed 0.20 removal refuses **before stopping the panel**:
reinstalling over retained data is currently unsupported. The panel and data
stay in place.

## Supported routers

| | Status |
| --- | --- |
| Netcraze Ultra (NC-1812), ARM64, firmware 5.01.C.6.0-1 | main test router |
| Other Keenetic / Netcraze ARM64 with Entware | panel startup does not establish bypass support; managed routes require an exact supported profile, see the support matrix |
| MIPS / MIPSel | builds available; managed routes unavailable |

More — [support matrix (RU)](docs/RUNTIME_SUPPORT_RU.md).

## Security and privacy

The panel works only inside your network and is password-protected. Updates are
downloaded over HTTPS with SHA-256 and architecture checks; releases carry GitHub
build attestations. Keys, passwords and node links never appear in logs or reports.
More — [SECURITY](SECURITY.md).

## Documentation

- [Install, update, uninstall and rollback (RU)](docs/INSTALL_RU.md)
- [Compatibility and limitations (RU)](docs/CURRENT_STATUS_RU.md)
- [Test release notes (RU)](https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.20.0-rc.71) · [Changelog](CHANGELOG.md)
- [Roadmap](docs/ROADMAP.md) · [Two DPI engines idea (RU)](docs/DUAL_DPI_ARCHITECTURE_RU.md)
- [Files and folders (RU)](docs/FILES_RU.md) · [Third-party components](THIRD_PARTY.md)
- [Contributing](CONTRIBUTING.md)

## Support the project

News, questions and ideas — on Telegram **[@RAZVILKA_UI](https://t.me/RAZVILKA_UI)**.
If RAZVILKA helps you — **[support the project](https://dalink.to/artixsx)**.

<p align="center"><sub>MIT · RAZVILKA ("razvilka" means "fork in the road"): every service gets its own path.</sub></p>
