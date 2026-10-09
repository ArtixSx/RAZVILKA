# RAZVILKA

> Draft homepage for the future 0.20.0 release, 9 October 2026. Release acceptance is pending.
> Installation commands retrieve a published stable release; this file does not establish that 0.20.0 is available.

**Selected services through your chosen connection, directly on your router.**

A local web panel for **Keenetic and Netcraze with Entware**. Manage the service
list, VLESS/VPN connections, NFQWS2, access checks, components and backups.
The panel and saved schedules run on the router.

[Published releases](https://github.com/ArtixSx/RAZVILKA/releases) ·
[Install](#install) · [Documentation (RU)](../../../docs/README.md) ·
[Русский draft](README_020_DRAFT_RU.md)

## How traffic is selected

For 0.20.0, the approved policy is **bypass only for the active list**:

- Bypass applies to matching services, domains and supported IP/CIDR rules
  in the selected home networks. The list can cover an entire selected network
  without assigning every service to every device.
- Devices outside the selected scope or in device exclusions use the router's
  ordinary policy. Manual resource exclusions and the currently enabled approved
  Russian resource list also take priority over positive rules and a manually pinned bypass.
- Traffic that does not match uses the router's ordinary policy. An empty
  active list does not enable bypass.
- One connection can serve several list entries. Selecting an entire home
  network as the device scope does not turn it into a VPN for all internet traffic.

[Full list and exclusions contract (RU)](../LIST_MODE_CORRECTION_RU.md).
A running process or an accepted request does not establish service access;
the result of applying the plan and the access check are shown separately.

## Install

Prepare **Entware for your model**, a mounted `/opt`, and SSH access to its shell
as `root`. The commands below are for the Entware shell, not the firmware console
with a `(config)>` prompt. [Entware preparation (RU)](../../../docs/INSTALL_RU.md#подготовка-entware).

Prepare HTTPS downloads:

```sh
export PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:$PATH
opkg update && opkg install curl wget-ssl ca-certificates ca-bundle
```

Download the installer and run it after the download succeeds:

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh
```

The installer selects the architecture and verifies the release archive's SHA256.
Bypass components are installed separately; installing the panel alone does not enable routes.

Open `http://<router-LAN-address>:8787`, for example
[http://192.168.1.1:8787](http://192.168.1.1:8787). The installer prints the actual address.
Use the first-run key or setup link to create your login and password, and keep
the recovery key. Choose services and device scope, add a connection or install
the required component, check access and apply the plan.
Safe Mode is enabled on a fresh installation; permission to change working routes
is configured separately in settings.

## Update

Download and run the installer again:

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh
```

The ordinary update path is designed to preserve settings and create a rollback snapshot.
Wait for the result, retain the printed snapshot path and check route state.
A working panel does not establish that bypass has recovered.
Migration from 0.19.3 to the future 0.20.0 still needs separate acceptance; see below.
[Update and rollback details (RU)](../../../docs/INSTALL_RU.md#обновление).

## Uninstall

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh --uninstall
```

On successful removal, the script stops the panel and removes its own routes,
binary and startup service. Settings, connections and snapshots are retained;
Entware and separately installed components remain. A stop or cleanup failure
halts removal and keeps the panel files.
[Removal and rollback (RU)](../../../docs/INSTALL_RU.md#удаление-и-откат).

## Quick diagnostics

```sh
/opt/bin/razvilka -version
/opt/etc/init.d/S99razvilka status
```

For name resolution errors, inspect the router's DNS settings and the error
reported by the panel or installer. For HTTPS download errors, check the clock
and certificates. [Panel does not open (RU)](../../../docs/INSTALL_RU.md#если-панель-не-открывается) ·
[Package catalogues do not update (RU)](../../../docs/INSTALL_RU.md#если-каталоги-пакетов-не-обновляются).

## Files and further reading

| File | Contents |
| --- | --- |
| [README.md](../../../README.md) | Russian homepage |
| [README_EN.md](../../../README_EN.md) | The same guide in English |
| [docs/README.md](../../../docs/README.md) | Documentation index |
| [docs/INSTALL_RU.md](../../../docs/INSTALL_RU.md) | Installation, updates, removal and rollback |
| [docs/CURRENT_STATUS_RU.md](../../../docs/CURRENT_STATUS_RU.md) | Integration status and links to verified results |
| [docs/FILES_RU.md](../../../docs/FILES_RU.md) | Explanation of other files and folders |
| [scripts/bootstrap.sh](../../../scripts/bootstrap.sh) | Script that downloads a verified release |

## For the coordinator before replacing README

This draft uses committed source `65044c4de3e85b24566424005654c08c2fde62e8`,
`VERSION=0.19.3`; review covers source and consistency between the two languages only.

- Migration from an actual old 0.19.3 installation, restoration of the
  binary/state pair and the ordinary 0.20.0 install/update path are not yet accepted.
- Final acceptance on the router is needed for lists and exclusions, Start/Stop and
  selected client traffic, including a sustained VLESS check. Source/CI checks
  and a single successful node check do not replace those results. Update the
  final status from the [acceptance log (RU)](../VALIDATION_RU.md) after the final checks.
- After acceptance, place the Russian text in `README.md` and the English text
  in `README_EN.md`; remove the draft notices and this section, adjust relative
  links to the repository root and replace links between drafts with the normal README links.
  Confirm commands against the actual release. This commit changes no shared README,
  version number, installer or publication.
