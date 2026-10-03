# Что осталось: продолжение V2.2 после итерации исходников

Предыдущий V2.2-MA2 в prior/ сохранён целиком. Ни одна его полная задача не становится done по изолированному harness. Ни H00, ни V01/V02/V06 ещё не приняты полной интеграцией. Этот документ — execution delta, не план V3 и не смена продукта.

## Первая итерация Codex

**I01. Полная интеграция.** Принять actual HEAD/dirty/worktrees и более новую работу, не reset. Прочитать AGENTS/CLAUDE, запустить pristine baseline. Применить один объединённый payload в отдельном tree точной базы либо перенести по смыслу. Проверить все anchors/компиляцию и полные tests. При новых ошибках исправить код, не ослаблять guard/fixtures ради зелёной сборки. Входные архивы H00 второй раз не применять.

**I02. Сквозное отображение VLESS.** Проверить, что service checks ручного пути, автопилота и recovery публикуют одни timings; current API отдаёт их без дискового/network IO под общим lock. Карточки не требуют ручного ping, при restart показывают честное отсутствие текущих timings до новой проверки. RecordCheck failure/cancel/new epoch/new ProbeID/missinghistory не показывает старый успех. Полный UI regression и layout на мобильном браузере. Для долговременных измерений нужна versioned миграция с downgrade, а не новое поле в прежней строгой схеме.

**I03. Реальный VLESS/Xray.** Запустить локальный Xray/Sing-box peer: первый IP отказал, второй обслуживает; prefilter/prepare/runtime используют один IP и originalSNI. Проверить actual network selection и отсутствие скрытого DIRECT. Завершить per-node Xray checker/identity и endpoint-neutral profile, затем XHTTP по capabilities. Импорт ≠ native compatibility.

**I04. Ограниченная сеть.** Нынешняя дополнительная проба только диагностическая. Для автоматического применения без DIRECT oracle нужен независимый exact-path proof: ownedruntime/listener/policy + controlled negative test candidate-down/direct-up и multiWAN/NATequalIP. Отсутствие прямого выхода или совпадение IP не делает все ключи плохими. До этих тестов guard остаётся.

**I05. Автоподбор и источники.** Закончить first-safe-usable без ожидания заполнения резервов, но сохранить свежесть, cleanup, B Apply fail→rollback→C и бюджет раунда. Не переносить простое break после первого canary: оно может лишить раунд C после отказа B. Проверить fast-lane отдельно. Для igareck/других источников — группы издателей, fair exploration, cursor/churn/304/429/503, reparse неподдержанных профилей после обновления core. Публичные peer не тестировать массово без ограничений и разрешённого scope. Сохранённый публичный источник не разрешает общий трафик всего LAN автоматически.

**I06. WG/AWG.** Принять H00 canary, native cold-peer без keepalive, Sources-only план, live/candidate с одинаковыми внутренними Address, маршруты endpoints/TTL, MTU/UDP/IPv6. Затем несколько genericWG профилей, AWG CLI/kernel/server matrix/readback/redaction. Не объявлять обычный WG/AWG зависимыми от Cloudflare. Совместимость с WARP проверяется отдельно.

**I07. Обновления.** Принять typed batches/receipts, затем durable intent+assets+config+deps, предыдущая рабочая версия удержание до фактический новый runtime и клиента, независимый helper после reboot/отключение питания/downgrade. Проверить SafeMode/Stop/window/revision после preflight. Unknown прекращает следующие mutations. Совпадение schema1 ещё не делает pending семантически понятным старому приложению.

## Остальные обязательные части прежнего плана

Общий общий интернет, индивидуальные сервисы, ноль карточек, неизвестный сайт/IP, единые device/site/RU исключения и совместное управление DNS. NETWORK_POLICY_EXECUTOR_REQUIRED не снимать до реализационного readback и negative client proof. Поддержка IPv6/временные IPv6-адреса, собственный DoH, общий CDN, выбранная base/block/unavailable fallback policy. Не глобальный ip_forward/очистка всей conntrack.

NFQWS2 preferred/only/pinned раздельно, сохранность пользовательские стратегии, visibility/offload, bounded fuzzer, D2k-inspired наблюдение только hints. USQUE H3/H2/пины/environment, повторное использование регистрации WARP, Mihomo полноценный исполнитель только с native lifecycle, HEV optional с измерениями. DNSbootstrap без циклов. Чтение локального каталога не загружает источник, publishers/mirrors≠trust, защита от SSRF. Ограниченные CPU/RAM/FD/time/filewrites по всей цепочке.

Главная показывает общийпуть+автопилот+jobs+причины; install/remove/update прогресс, не повторные подтверждения каждойвнутреннейфазы. Отдельные внешние права/удаление/регистрация согласуются.

Финал: native стенд → ARM64 с двумя физическими клиентами → MIPS/MIPSel → 24/72ч без браузера. Точный выпуск, rollback/отключение питания/нехватка памяти/заполненный диск, TCP/UDP/IPv6/сценарии сервисов. Успех веб-проверки не Telegram media/Discord voice/YouTube video. Все предыдущие тесты V2.2 остаются not_run до фактического прогона.

## Работа агентов

В данной сессии subagents не запускались. В Codex использовать существующие ролиMA2 только при реальных инструментах. CORE measurement/ranking; PROXY nodecheck/Xray; DATA feeds; UI browser; WG adapters; OPS updater; независимый QA. Общие nodecheck.go/autonomy_worker.go/DTO и схема — один writer, точная версия контракта. Не запускать несколько fullbuild/native network mutations на одном роутере параллельно. Отчёт с exact integrated SHA и отдельными unit/integration/native/HIL/soak.
