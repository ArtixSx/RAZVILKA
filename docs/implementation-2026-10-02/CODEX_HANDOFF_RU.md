# Продолжение в Codex

Прочитай README_RU.md и docs/CODEX_HANDOFF_RU.md в приложенном RAZVILKA_IMPLEMENTATION_2026-10-02. Это реальные исходные изменения и тесты, а не только план. H00 уже включён; prior/H00 не накладывать повторно.

Сначала сверь actual HEAD/worktrees/instructions и сохрани более новую работу. База payload 817783493f0c2784ccc70aa73868cd64e9437634. Получи отдельный полный checkout через prepare_project.py либо перенеси changes.json по смыслу при другом HEAD. Не reset/clean/публикация/установка на роутер.

На неизменённом требуемом Go проверь baseline, затем объединённый код полным scripts/check.sh. Изолированные 67 Go-функций, 23 JS-кейса и синтетический сборщик не равны fullCI. Исправляй интеграцию, не удаляй safetyguards. Первым результатом должен быть рабочий merged step VLESSmetrics+endpointpin и полный отчёт; не ещё один roadmap.

Продолжи Xray→WG→AWG, ранние VLESSfixes и остальной V2.2. NoDIRECT проба пока только диагностическая: Available=false, автоматическое применение не разрешено без альтернативного proof и negativecontrols. Требование всего интернета с исключениями сохранено. Не выдавай прошлые HIL/измерения Claude за приёмку нового diff.

# Что осталось: продолжение V2.2 после итерации исходников

Предыдущий V2.2-MA2 в prior/ сохранён целиком. Ни одна его полная задача не становится done по изолированному harness. Ни H00, ни V01/V02/V06 ещё не приняты полной интеграцией. Этот документ — execution delta, не план V3 и не смена продукта.

## Первая итерация Codex

**I01. Полная интеграция.** Принять actual HEAD/dirty/worktrees и более новую работу, не reset. Прочитать AGENTS/CLAUDE, запустить pristine baseline. Применить один объединённый payload в отдельном tree точной базы либо перенести по смыслу. Проверить все anchors/компиляцию и полные tests. При новых ошибках исправить код, не ослаблять guard/fixtures ради зелёной сборки. Входные архивы H00 второй раз не применять.

**I02. Сквозное отображение VLESS.** Проверить, что service checks ручного пути, автопилота и recovery публикуют одни timings; current API отдаёт их без дискового/network IO под общим lock. Карточки не требуют ручного ping, при restart показывают честное отсутствие текущих timings до новой проверки. RecordCheck failure/cancel/new epoch/new ProbeID/missinghistory не показывает старый успех. Полный UI regression и layout на мобильном браузере. Для долговременных измерений нужна versioned миграция с downgrade, а не новое поле в прежней строгой схеме.

**I03. Реальный VLESS/Xray.** Запустить локальный Xray/Sing-box peer: первый IP отказал, второй обслуживает; prefilter/prepare/runtime используют один IP и originalSNI. Проверить actual network selection и отсутствие скрытого DIRECT. Завершить per-node Xray checker/identity и endpoint-neutral profile, затем XHTTP по capabilities. Импорт ≠ native compatibility.

**I04. Ограниченная сеть.** Нынешняя дополнительная проба только диагностическая. Для автоматического применения без DIRECT oracle нужен независимый exact-path proof: ownedruntime/listener/policy + controlled negative test candidate-down/direct-up и multiWAN/NATequalIP. Отсутствие прямого выхода или совпадение IP не делает все ключи плохими. До этих тестов guard остаётся.

**I05. Автоподбор и источники.** Закончить first-safe-usable без ожидания заполнения резервов, но сохранить свежесть, cleanup, B Apply fail→rollback→C и бюджет раунда. Не переносить простое break после первого canary: оно может лишить раунд C после отказа B. Проверить fast-lane отдельно. Для igareck/других источников — cohorts, fair exploration, cursor/churn/304/429/503, reparse неподдержанных профилей после обновления core. Публичные peer не тестировать массово без ограничений и разрешённого scope. Сохранённый public source не разрешает default всего LAN автоматически.

**I06. WG/AWG.** Принять H00 canary, nativecoldpeer без keepalive, Sources-only план, live/candidate с одинаковыми внутренними Address, маршруты endpoints/TTL, MTU/UDP/IPv6. Затем несколько genericWG профилей, AWG CLI/kernel/server matrix/readback/redaction. Не объявлять обычный WG/AWG зависимыми от Cloudflare. Совместимость с WARP проверяется отдельно.

**I07. Обновления.** Принять typed batches/receipts, затем durable intent+assets+config+deps, previous-working удержание до actual newruntime и клиента, independenthelper после reboot/powerloss/downgrade. Проверить SafeMode/Stop/window/revision после preflight. Unknown прекращает следующие mutations. Совпадение schema1 ещё не делает pending семантически понятным старому приложению.

## Остальные обязательные части прежнего плана

Общий defaultInternet, serviceoverrides, нолькарточек, неизвестныйсайт/IP, единые device/site/RU исключения и jointDNS. NETWORK_POLICY_EXECUTOR_REQUIRED не снимать до реализационного readback и negative client proof. Поддержка IPv6/privacyIP, privateDoH, sharedCDN, выбранная base/block/unavailable fallback policy. Не глобальный ip_forward/flushconntrack.

NFQWS2 preferred/only/pinned раздельно, сохранность userstrategies, visibility/offload, bounded fuzzer, D2k-inspired наблюдение только hints. USQUE H3/H2/пины/environment, WARP reuse identity, Mihomo полноценныйexecutor только с native lifecycle, HEV optional с измерениями. DNSbootstrap без циклов. Localcatalog GETнеfetch, publishers/mirrors≠trust, noSSRF. Ограниченные CPU/RAM/FD/time/filewrites по всей цепочке.

Главная показывает общийпуть+автопилот+jobs+причины; install/remove/update прогресс, не повторные подтверждения каждойвнутреннейфазы. Отдельные внешние права/удаление/регистрация согласуются.

Финал: native стенд → ARM64 с двумя физическимиклиентами → MIPS/MIPSel → 24/72ч безбраузера. Currentexactrelease, rollback/powerloss/lowmemory/fullDisk, TCP/UDP/IPv6/сценарии сервисов. Успехweb не Telegrammedia/Discordvoice/YouTubevideo. Всепредыдущие тестыV2.2 остаются not_run до фактического прогона.

## Работа агентов

В данной сессии subagents не запускались. В Codex использовать существующие ролиMA2 только при реальных инструментах. CORE measurement/ranking; PROXY nodecheck/Xray; DATA feeds; UI browser; WG adapters; OPS updater; независимый QA. Общие nodecheck.go/autonomy_worker.go/DTO и схема — один writer, exactcontract. Не запускать несколько fullbuild/native network mutations на одном роутере параллельно. Отчёт с exact integrated SHA и отдельными unit/integration/native/HIL/soak.
