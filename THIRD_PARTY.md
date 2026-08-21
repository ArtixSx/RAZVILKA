# Third-party components and data sources

RAZVILKA references the following engines and external datasets. Their own licenses and trademarks remain applicable.

- nfqws2-keenetic / zapret2 — anti-DPI engine/integration.
- [z2k](https://github.com/necronicle/z2k) — MIT-licensed Zapret2 integration reviewed for strategy organization, validation, diagnostics and external-runtime ownership concepts. RAZVILKA does not bundle z2k scripts, fake payloads or telemetry.
- usque / usque-keenetic — Cloudflare WARP MASQUE implementation/integration.
- [quic-go](https://github.com/quic-go/quic-go) and qpack — MIT-licensed Go QUIC/HTTP3 transport used only for real Strategy Lab HTTP/3 probes.
- Go `x/crypto`, `x/net`, `x/sys` and `x/text` modules — BSD-licensed transitive runtime dependencies of the HTTP/3 transport.
- sing-box — proxy/routing core.
- Xray-core — optional proxy transport core.
- ByeDPI — candidate local SOCKS anti-DPI adapter.
- AmneziaWG — candidate DPI-resistant VPN adapter.
- MagiTrickle — routing/integration reference.
- Re:filter lists — external operational domain/IP lists (MIT repository).
- RunetFreedom russia-blocked-geosite / geoip — external routing datasets (GPL-3.0 repositories).
- v2fly/domain-list-community — external service classification dataset (MIT).
- Loyalsoldier/geoip — external generated network datasets (CC BY-SA 4.0 and GPL-3.0; upstream also incorporates attributed GeoLite2 data).
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
