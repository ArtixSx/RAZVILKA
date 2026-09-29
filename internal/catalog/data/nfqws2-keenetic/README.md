# Snapshot provenance

This directory contains RAZVILKA's grouping of the upstream domain list, not an installation of nfqws2-keenetic.

- Upstream: https://github.com/nfqws/nfqws2-keenetic
- Snapshot: `077f9af6068cd3380527085ca351b503a2dcf926` (tag v1.3.1, the version installed by the package)
- File: `etc/nfqws2/lists/user.list`
- Recorded SHA-256 of upstream file: `681d1278de09bbfef7d743de089c6e30bf7d52b82c91f03e91a0b595c5e76bb0`
- Retrieved: 2026-09-29. Copies of the upstream `user.list` and `exclude.list` of this tag are kept in `upstream/`; tests require the catalogue to contain exactly the upstream domains and none that the upstream exclude list removes.
- 273 unique domains, six presentation groups (180/23/29/10/1/30). Version 1.3.1 moved `roblox.com`, `robloxcdn.com`, `robloxapp.com`, `robloxgames.com` and `robloxlabs.com` from the host list to the exclude list; the Roblox group keeps the CDN domains.
- Upstream MIT notice: LICENSE in this directory.

Group labels, probes, and the intended NFQWS2 route are RAZVILKA additions.
The common group is probed at `www.cloudflarestatus.com`: the apex `cloudflarestatus.com`
is blocked by IP in Russia, so no local DPI bypass could ever pass that check.
The Discord group additionally contains eight RAZVILKA-added domains that are
not part of the upstream file: `discordstatus.com`, `discordapp.io`,
`discord-attachments-uploads-prd.storage.googleapis.com` (file uploads),
`airhornbot.com`, `airhorn.solutions`, `bigbeans.solutions`,
`watchanimeattheoffice.com` and `hammerandchisel.ssl.zendesk.com`. They follow
the Discord TCP host list used by the zapret2/z2k installer; the upstream
counts above describe the upstream file only.
The Riot Games group additionally contains `auth.riotgames.com` and
`authenticate.riotgames.com`, also RAZVILKA additions: every page of
`account.riotgames.com` redirects to its sign-in on those hosts, so with the
single upstream domain the web check could never be confirmed through NFQWS2.
The common CDN/Google domains cover more than a single application. These are not assertions that all affected applications or features are verified.
No upstream `auto.list`, `exclude.list`, kernel module, init script or IP set is installed or overwritten by this snapshot; the copies in `upstream/` are test references only.
`configs/service-catalog.json` must remain byte-identical to `catalog.json` here; tests enforce that relationship.
