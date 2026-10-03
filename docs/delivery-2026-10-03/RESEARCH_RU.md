# Дополнительное исследование, 03.10.2026

Исследование не привело к установке второго сетевого менеджера или копированию стороннего кода. Ниже — конкретные прочитанные источники и выводы; это не аудит каждого проекта целиком. Источники из прежних V2.2/D2k-документов остаются reference, а не заново пройденными испытаниями.

## Zapret2 — lua/zapret-auto.lua

Источник: https://github.com/bol-van/zapret2/blob/master/lua/zapret-auto.lua
Прочитаны строки150–388; Git blob `c6999e2da57f79c99623d3be380817e4c52f4b7e`.

`circular` переключает группы strategy=N после порога сбоев, использует per-host состояние; для RST/redirect требуется наблюдение ответного направления. `standard_success_detector` опирается на продвижение TCP sequence или UDP-счётчики: это сигнал для управления локальным счётчиком, **не доказательство работы приложения**.

Взять: bounded local strategy rotation в существующем NFQWS2 executor, проверять видимость/offload, compatible Lua/assets, не перезапускать весь проект ради следующего рецепта. Не брать: самовольное ослабление scope, packet-counter=>service PASS, TCP fallback вместо неподдержанного QUIC. В текущей поставке это задача NET/DPI, не включённый новый runtime.

## VPNpool — nodecheck.sh

Источник: https://github.com/roman-png/VPNpool/blob/main/package/vpnpool/files/usr/libexec/vpnpool/nodecheck.sh
Прочитаны строки1–155; Git blob `d74fc031ed60716203aa24c884baec750f3d9340`.

Различает TCP-prefilter и per-outbound сервисную проверку через Clash delay API, публикует измерения в общий dashboard. Проверяет последовательно, делает ограниченные повторы и hysteresis. В комментарии описан опыт автора с перегрузкой многочисленными процессами; мы его не воспроизводили.

Взять: UI и watchdog должны читать согласованные результаты, не заставлять пользователя отдельно пинговать после автопроверки; дешёвый prefilter не равен service-check. Уже реализован собственный общий read-model measurements. Не копировать shell-lock check-then-create, parsing JSON по подстроке, обязательное совпадение всех сервисов для каждого узла или принудительный DIRECT при пустом пуле: у RAZVILKA service-specific политика и отдельное согласие на отказ.

README: https://github.com/roman-png/VPNpool — источник заявлений о warm-up, источниках, подписях quota, а не доказательство всей функциональности. Не подменять stock Sing-box форком без отдельной совместимости и доверия.

## Podkop — chunked rules

Источник: https://github.com/itdoginfo/podkop/blob/c0a2736bb95884c19fedf638345ed6148c5fd6af/podkop/files/usr/lib/nft.sh
Источник: https://github.com/itdoginfo/podkop/blob/c0a2736bb95884c19fedf638345ed6148c5fd6af/podkop/files/usr/lib/rulesets.sh
Посмотрены фрагменты функций chunked import из code-search (не полный построчный аудит). Разделяет работу на партии, избегая одной огромной команды/структуры.

Взять: ограниченный импорт и применение списков, размер партии от реальной памяти/времени, common owner, readback поколения. Не копировать автоматическое изменение dnsmasq/sing-box и глобальное изменение всей сети поверх исключённых устройств. Реальная интеграция общего LAN/DNS в поставке не завершена.

## D2k Telegram и прежние источники

Прежнее дополнение D2k сохранено в CODEX_REVIEW/reference. Полезны отдельный MTProto начальный probe, бюджет очередей, scoped DNS, TTL/provenance learned families, exact flow/trial ID. Нельзя считать nonce resPQ полной auth Telegram, запущенный/connected relay — медиа/звонками; нельзя копировать глобальный IPv6 REJECT, global conntrack delete или чужой relay по умолчанию.

Приоритет остаётся законченным VLESS/Xray, WG, AWG, а не новым C-control-plane. Наблюдатели D2k/ByeDPI — кандидаты ограниченной диагностики. Отдельная матрица runtime/HIL важнее красивого README.
