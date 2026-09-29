# Внешние идеи: что сохранить и как проверять

Здесь **задания исследования**, не рейтинг проверенных сейчас готовых решений. В новой редакции заново прочитаны только официальные страницы Project X routing, sing-box TUN, WireGuard и AmneziaWG. Остальные проекты — кандидаты из обсуждения для изучения конкретного upstream commit/license/схемы. Не делать из названия обещание работающей функции и не устанавливать чужой контроллер внутрь RAZVILKA.

| Источник | Что исследовать | Куда относится | Что не переносить вслепую |
|---|---|---|---|
| bol-van/zapret2, nfqws2-keenetic, z2k | Память успешных стратегий, NFQUEUE visibility, recipes/assets, update preservation | N01/N02/M01 | z2k как обязательный daemon, глобальный scope при пропаже policy |
| 0xkee/keenetic-entware-extras | NDM wake/reconcile, RU whitelist, cached status, route preview от MAC, WAN discovery | E02/R01/R02/UX01 | Второй geo-split/DNS owner, постоянные host routes без TTL/shared-IP анализа |
| awadak3davra/wayhop | Обратимый Apply, отказ по capabilities, import/lifecycle | X/W/A/G02 | Признание README подтверждённой реализацией |
| Dushnilin/tachyon | Bounded strategy search, watchdog/restart backoff, snapshots | N02/F02 | OpenWrt platform rules как готовые Keenetic rules |
| OpenWrt mwan3, keen-pbr | Несколько health targets, hysteresis, failover state, conntrack | F02/R01 | Глобальный conntrack flush и повторные probes без бюджетов |
| XKeen | Разделение движка и Keenetic policy, delivery/transport constraints | X02/E01 | Установка второго controller |
| HydraRoute / Ground-Zerro/Geo-Aggregator | Категории сетевых сервисов, definitions, mixed domains/CIDRs | C01/E02 | Подмена default catalogue allowlist; raw mixed list как только домены |
| Hydra Launcher | UX подключаемых источников | C01/UX01 | Игровые download sources не являются сетевыми service definitions |
| itdoginfo/podkop | Workflow выбора, split routing, DNS со своим core | C01/UX01/D02 | Автоматическое удаление/перепись чужих configs |
| Nikki/Momo/HomeProxy | Profile overlays, native check, supervisor и platform quirks | X01/B01 | Предположение, что config syntax latest совпал с installed version |
| OpenClash | Providers, fallback/url-test UX, large catalog navigation | C02/F01/UX01 | URLTest одного адреса как service proof всех приложений |
| dae | Раздельная TCP/UDP/IPv4/IPv6 decision model | F01/H01 | Обязательный eBPF для старого ядра Keenetic |
| SmartDNS/mosdns | Готовый DNS executor, cache, conditional upstreams | D01/D02 | Несогласованный второй DNS plane |
| Xray-core / Project X docs | Routing defaults, canonical profiles, Reality/XHTTP, real TUN support if present | X01/X02 | Неявный first-outbound DIRECT из импортированного JSON |
| WireGuard | Cryptokey routing, interfaces, keys, native tools | W01/W02 | AllowedIPs=0/0 как user consent, hooks из чужого conf |
| AmneziaWG / AWG Manager | Field compatibility, module/tools delivery, migration | A01/A02 | Универсальная версия по ярлыку; чужой server setup без permission |
| sing-box / Mihomo | Native validation, TUN/DNS/version differences, fallbacks | X02/B01 | auto_route/auto_redirect одновременно с независимым controller |
| USQUE upstream | Auth/bootstrap, H3/H2 modes, native TUN/L4, versioned packaging | T02 | Ошибка UDP как повод создать аккаунт; TCP port open как MASQUE proof |
| HevSocks5Tunnel | Measured SOCKS↔TUN, memory cost, UDP/IPv6 | B02 | Установка ради имени без выигрыша/полного recovery |
| v2fly/domain-list-community, Loyalsoldier, itdoginfo/allow-domains | exact/suffix/CIDR, geo/category lists, provenance | C01/E02 | Скрытые TLD, большие CDN ranges как точный сервис |
| Internet-Helper/AdGuard-Home wiki | DNS/hosts идеи и диагностика | D02/R01 | Глобальные hosts/перехват DNS без scope и возврата |
| warp-gen.cyb-portal.org | Форматы генератора/конвертера, MASQUE/WG, optional VLESS feeds | T01/T02/C02 | Неподтверждённый API, silent full-tunnel fallback, приватные ключи наружу |
| warp3.llimonix.pw, Valokda, ImMALWARE/bash-warp-generator, warp-gen.github.io | Enrollment/export separation, endpoint hints, local converters | T01 | Перерегистрация на export/QR/DNS, all-sites при неизвестном списке |
| Kort0881, Goida, tiagorrg, CP subscriptions | Adapter formats, dedup/cursor, source independence | C02 | Внешний checker с приватными URI, выключенный TLS, сотни потоков |
| Генераторы/relay в Telegram | Есть ли документированный безопасный API/activation mechanism | L02/T01 | UI scraping/click automation как надёжный production lifecycle |
| Форумы Keenetic/Netcraze, OpenWrt, MikroTik, NTC.party, 4PDA и авторские сайты | Воспроизводимые platform-specific симптомы, MTU/offload/DNS/UDP | R01/N01/A01 | Чужой неподтверждённый рецепт как универсальная настройка |

## Правило внесения новой идеи

Одна карточка: проблема пользователя → точный source URL/commit/date/license → что реально прочитано → существующий аналог в RAZVILKA → минимальная полезная часть → риски scope/secrets/resources → unit/native/HIL tests → решение adopt/reject/defer. Не копировать код без проверки лицензии; при переносе соблюдать её условия.

## CyberPortal: специальная оговорка

При текущем обращении сайт не дал доступного содержимого. Из прошлой беседы известны предполагаемые WARP/WG-converter/MASQUE/VLESS направления, но сегодня количество форматов/подписок, `/api/masque`, endpoint logic и клиентская обработка ключей не подтверждены. Проверить перед написанием adapter. Похожий публичный warp-gen fork не доказывает source deployed сайта. Внешний сервис не должен быть обязательным для сохранённого общего интернета.

## DNS-кандидаты из обсуждения

Quad9, Control D Unfiltered/Uncensored, Xbox DNS, Cloudflare, Google, UncensoredDNS, FlashStart и другие — кандидаты с разными privacy/filtering/gateway семантиками. При реализации заново проверить официальные endpoints, условия и транспорт. Не хранить историческое «не подошёл для USQUE» как вечный глобальный запрет. Обычный resolver, Smart DNS gateway и DNS proxy не взаимозаменяемы.

## На будущее, не блокирует engines

VLESS/WARP/MASQUE relay chains, собственная серверная оркестрация, профили Hysteria2/TUIC, OpenWrt/GL.iNet/Asuswrt-Merlin/generic Linux и возможный MikroTik, ссылка-виджет в штатной панели Keenetic, собственный публичный сайт. Нет обязательной покупки сервера, нового relay или cloud account ради базового режима. Все цепочки проверять на циклы и независимость bootstrap.
