# Snapshot provenance

This directory contains RAZVILKA's grouping of the upstream domain list, not an installation of nfqws2-keenetic.

- Upstream: https://github.com/nfqws/nfqws2-keenetic
- Snapshot: `c77226bd384e047a3d97e3ab6f0ad8b46fc3c967`
- File: `etc/nfqws2/lists/user.list`
- Recorded SHA-256 of upstream file: `974016ffc0b0cef05fbb05718f12b721104a72b3fa7261a814d596974dc339cc`
- Previously retrieved: 2026-09-15; this candidate does not claim a new online refresh.
- 278 unique domains, six presentation groups (180/23/34/10/1/30).
- Upstream MIT notice: LICENSE in this directory.

Group labels, probes, and the intended NFQWS2 route are RAZVILKA additions.
The Discord group additionally contains eight RAZVILKA-added domains that are
not part of the upstream file: `discordstatus.com`, `discordapp.io`,
`discord-attachments-uploads-prd.storage.googleapis.com` (file uploads),
`airhornbot.com`, `airhorn.solutions`, `bigbeans.solutions`,
`watchanimeattheoffice.com` and `hammerandchisel.ssl.zendesk.com`. They follow
the Discord TCP host list used by the zapret2/z2k installer; the upstream
counts above describe the upstream file only.
The common CDN/Google domains cover more than a single application. These are not assertions that all affected applications or features are verified.
No upstream `auto.list`, `exclude.list`, kernel module, init script or IP set is installed or overwritten by this snapshot.
`configs/service-catalog.json` must remain byte-identical to `catalog.json` here; tests enforce that relationship.
