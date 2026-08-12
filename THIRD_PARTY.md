# Third-party components and data sources

RAZVILKA v0.0.8-security-gate does not bundle the following engines/data into its manager binary. It detects, references or plans adapters for them. Their own licenses and trademarks remain applicable.

- nfqws2-keenetic / zapret2 — anti-DPI engine/integration.
- usque / usque-keenetic — Cloudflare WARP MASQUE implementation/integration.
- sing-box — proxy/routing core.
- Xray-core — optional proxy transport core.
- ByeDPI — candidate local SOCKS anti-DPI adapter.
- AmneziaWG — candidate DPI-resistant VPN adapter.
- MagiTrickle — routing/integration reference.
- Re:filter lists — external operational domain/IP lists (MIT repository).
- RunetFreedom russia-blocked-geosite / geoip — external routing datasets (GPL-3.0 repositories).
- v2fly/domain-list-community — external service classification dataset (MIT).
- Roskomnadzor unified registry — external official point-lookup reference.
- OpenAI network recommendations — vendor documentation used to maintain the OpenAI service manifest.
- Telegram CIDR resource — vendor-published network ranges.

Before a public packaged release, exact bundled-vs-referenced license obligations must be reviewed for every component included in distribution artifacts.


## UX references

- XKeen-UI (zxc-rv/XKeen-UI) was reviewed as a UX reference for selector and connection-monitoring concepts. No XKeen-UI source code is included in RAZVILKA.
- MetaCubeXD and Zashboard — dashboard/product UX references; no code bundled.
- Pi-hole Web and AdGuard Home — network activity/client UX references; no code bundled.
- HomeProxy / PassWall — router control-plane/config-validation references; no code bundled.
- AntiGoblin — Keenetic selective-routing UX/transaction reference; no code bundled.
- Hiddify App — profile/automatic-selection UX reference; no code bundled.
- 3x-ui — node/traffic/multi-hop operational UX reference; no code bundled.
- OpenClash and OpenWrt PassWall — router integration/dependency/compatibility references; no code bundled.
