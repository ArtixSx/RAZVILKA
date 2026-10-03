# Остаток и распределение между ассистентами

> Исходное задание из поставки 03.10.2026. Отметки `not_run / remaining` ниже описывают состояние при передаче архива. Текущий статус этапов ведётся в [TASKS.json](TASKS.json), распределение авторов — в [COORDINATION_RU.md](COORDINATION_RU.md), независимые результаты и ограничения — в [VALIDATION_RU.md](VALIDATION_RU.md). Исходные требования сохранены для сверки.

Это продолжение V2.2, не новое ТЗ. Старые требования сохраняются. Поставлен **полный исходный проект**, поэтому первая задача — его собрать и проверить, а не снова скачивать/накладывать старые патчи.

## Шесть логических ролей

| Роль | Владение | Ограничение |
|---|---|---|
| INTEGRATOR (координатор) | Общие контракты, scheduler, application wiring, очередь PR | Только он принимает изменения общих файлов worker/store; не объявляет чужие тесты пройденными |
| UI | web assets, UI tests, понятные flows, performance | Не меняет серверные полномочия ради клика; клиентский getter не делает mutate |
| VLESS | profile/compiler/checker/ranking/feed pipeline | Не портит source/node reputation из-за локальных ошибок; не ослабляет TLS/path proof |
| NET | WG/AWG/NFQWS2, network/DNS executor | Один владелец сети, exact scope/cleanup, no foreign takeover |
| OPS | packages/updates/snapshots/bootstrap, WARP/USQUE lifecycle | Не повторяет unknown side effects и не удаляет LKG преждевременно |
| QA | Независимые native/HTTP/fault/HIL проверки | Не использует одно поддельное API как доказательство настоящего runtime |

Роли — не заявление о реально запущенных здесь агентах. Координатор проверяет инструменты делегирования, выделяет worktree/ветку и файл-owner. Общий роутер/namespace/порты не изолируются git-worktree: live-окно только одно. При недоступном делегировании — последовательная работа по тем же ролям. В отчёте указывать настоящий task-id только если его создал инструмент.

Каждое задание: входной commit, цель, owned files, запреты, tests, Definition of Done, deadline/budget, отчёт diff+commands+rc+unverified. Не закрывать следующий PR только потому, что unit прошёл. Новый runtime может быть implemented без HIL, но не production-ready.

## Очередь

### D00 — Полная Go1.26.5 интеграция и CI

Владелец: **INTEGRATOR**. Зависимости: нет. Статус: **not_run / remaining**.

Сопоставить присланную базу/более новый HEAD. go mod verify; sh scripts/check.sh; проверить API structs/adapters без test doubles. Никакого downgrade production go.mod.

### D01 — Настоящий HTTP/login/CSP и ленивые чтения

Владелец: **UI**. Зависимости: D00. Статус: **not_run / remaining**.

Браузер с реальным приложением: auth/CSRF/logout, скрытые вкладки, быстрые переходы, повторные клики, 401/409/500, dirty forms. Измерить число запросов, render-cost, CPU на ARM64.

### D02 — Per-node Xray и канонический VLESS

Владелец: **VLESS**. Зависимости: D00. Статус: **not_run / remaining**.

Сохранить обязательные поля и доказательства; настоящий RAW/TCP Reality, compiler capabilities; XHTTP отдельным проверяемым подэтапом, не lossy conversion.

### D03 — Xray end-to-end

Владелец: **VLESS**. Зависимости: D02. Статус: **not_run / remaining**.

Native server/client локально, затем selected/control client, endpoint changes, kill proxy/sidecar, app/router restart, rollback. SOCKS probe не доказывает TUN.

### D04 — WG candidate isolation и холодный старт

Владелец: **NET**. Зависимости: D00. Статус: **not_run / remaining**.

Handshake с инициирующим трафиком; реальное попадание в временный интерфейс при одинаковых Address; Sources не удаляются; keepalive optional; TCP/UDP IPv4/IPv6.

### D05 — WG профили и резервы

Владелец: **NET**. Зависимости: D04. Статус: **not_run / remaining**.

Отдельный engine не WARP, strict conf, hooks rejected, несколько профилей, hostname TTL, endpoint route pin, Stop/WAN/reboot/rollback.

### D06 — AWG production

Владелец: **NET**. Зависимости: D05. Статус: **not_run / remaining**.

Проверенные module/CLI/kernel/ABI/backend и сервер, readback без секретов, сохранение foreign owners, wrong module safe reject, reboot authority отдельно.

### D07 — Общий default и service executor

Владелец: **INTEGRATOR**. Зависимости: D03, D05. Статус: **not_run / remaining**.

NetworkPolicy all-except + per-service overrides. Нет сервисов/неизвестный сайт/прямой IP всё равно использует default. Scope mismatch продолжает default, удаление override не DIRECT. Вводить по capabilities, не снимать guard заранее.

### D08 — Согласованный LAN/DNS/RU exclusions

Владелец: **NET**. Зависимости: D07. Статус: **not_run / remaining**.

Исключённые устройства вне всех owned обходов и service DNS. Guest opt-in. Bootstrap DAG, IPv6/UDP policy, CNAME/TTL, shared CDN, existing connections scoped, не flush всего LAN.

### D09 — Адаптивный NFQWS2

Владелец: **NET**. Зависимости: D00. Статус: **not_run / remaining**.

Явно отделить preferred/only/manual. Локальный bounded подбор на compatible Lua/assets с visibility; packet success не media/voice. Разрешённый VLESS fallback; пользовательские стратегии сохраняются.

### D10 — Холодный first-usable и справедливый refill

Владелец: **VLESS**. Зависимости: D02. Статус: **not_run / remaining**.

Не ждать весь резерв для первого пригодного пути, но сохранить B apply-fail→verified rollback→C. igareck и другие approved feeds, cursor32/33, shared publisher mirrors, reserve diversity, no poisoning checker errors.

### D11 — Crash-safe обновления

Владелец: **OPS**. Зависимости: D00. Статус: **not_run / remaining**.

Полный persistent package/config journal и независимый recover. Хранить прежний LKG до live acceptance нового runtime. Unknown→stop, matching repair, SafeMode/Stop, downgrade старым бинарником pending receipts. Test power cut before/after every phase.

### D12 — Один рабочий путь во всех разделах

Владелец: **UI**. Зависимости: D01. Статус: **not_run / remaining**.

Установка/профиль/проверка/применение на карточке; per-engine подтверждения прогресса; массовые VLESSоперации; раскрываемая AI группа; меньше legacy дубликатов. Не ломать URL/ID/API; получить профиль открытой вкладки и настоящий замер weak router.

### D13 — WARP/USQUE и источники

Владелец: **OPS**. Зависимости: D00. Статус: **not_run / remaining**.

Регистрация != export/DNS/endpoint. Unknown enrollment не mint-again. H2/H3 отдельно, pins/environment/UDP capability, mirror TTL/provenance, read-only offline каталог. Mihomo/HEV experimental до native benefit.

### D14 — Аппаратная матрица и длительная работа

Владелец: **QA**. Зависимости: D03, D05, D06, D08, D09, D10, D11, D12, D13. Статус: **not_run / remaining**.

Два реальных клиента, Keenetic ARM64, MIPS/MIPSel отдельно от cross-build; при возможности OpenWrt отдельно. 24h/72h browser-closed; WAN, OOM/disk, process kill, real media/voice/game; no false PASS.

## Неизменяемые инварианты

Рабочий LKG не меняется ради меньшего ping. Проверка по одному сайту не доказывает весь интернет. Область устройства исключает и туннели, и NFQWS2, и service DNS. Ручные исключения выше автоматики. Обновление feed не расширяет доверие и не включает новые сервисы само. Default-public-node consent отдельно от одного сервиса. При отсутствии всех резервов — заранее согласованный fallback либо scoped block, не случайный DIRECT.

Никакого нового Autopilot2, отдельного DNS-scheduler, установки z2k/D2k/Podkop/VPNpool как второго owner, замены ядра неподписанным fork или выдуманного HIL. Открытие UI никогда не считается правом обновить ядро/перезагрузить устройство.
