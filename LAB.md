# RAZVILKA verification guide

For normal installation, use the [README](README.md). This page is for testing
changes and release files. Confirmed hardware results and remaining limitations
are recorded in [current status](docs/CURRENT_STATUS_RU.md).

## Development and release checks

On Linux with the Go and Node versions pinned in the CI workflow:

```sh
./scripts/check.sh
```

This runs Go tests, race checks, vet, interface checks, installer fixtures and
builds Linux ARM64, MIPS, MIPSel and development AMD64 binaries. MIPS targets use
soft-float. Cross-compilation is not a physical-router acceptance result.

## Isolated installer checks on Entware

Use a verified release archive, unpack it and enter its directory. The following
fixtures use temporary directories and explicit installation paths:

```sh
mkdir -p /opt/tmp
PATH=/opt/sbin:/opt/bin:$PATH TMPDIR=/opt/tmp sh scripts/test-bootstrap.sh
PATH=/opt/sbin:/opt/bin:$PATH TMPDIR=/opt/tmp sh scripts/test-uninstall-entware.sh
PATH=/opt/sbin:/opt/bin:$PATH TMPDIR=/opt/tmp sh scripts/test-entware-transaction.sh
```

The first two use mocked downloads, package operations and processes. The third
starts temporary copies of the real panel on a separate port; allow enough free
memory for a second instance. It covers fresh installation, upgrade, rollback,
port conflict, refusal after failed shutdown, private-state recovery and removal
after an upgrade. A deliberate failed-stop case waits for the shutdown timeout.
Temporary instances use separate settings and do not enable bypass routes.

## Testing routes

Route tests require a separate scope: a selected client, working profiles,
baseline network state, an explicit apply, real client traffic and a final stop.
Report the exact revision and binary checksums, each observed result, and cleanup.
Do not substitute a running process, TCP ping or an old success for a fresh
service and client-path check.

The current published hardware report covers ARM64. Physical MIPS/MIPSel,
multi-client, reboot/WAN, IPv6/UDP and endurance checks remain separate tasks.

[Historical v0.0.8 lab notes](docs/archive/LAB_v0.0.8.md) ·
[Full installation guide](docs/INSTALL_RU.md)
