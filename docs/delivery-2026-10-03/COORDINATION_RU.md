# Координация и чаты 6.1 sol — 03.10.2026

По указанию владельца программирование переносится в отдельные чаты `gpt-6.1-sol`. Координатор в чате «RAZVILKA Astra» выполняет обзоры, независимые проверки, тестирование и объединение. VM и роутер остаются под одним владельцем.

Общая интеграционная ветка — `review/delivery-2026-10-03`, папка `C:/Projects/RAZVILKA/delivery-review`. Исходная копия владельца `current` сохранена. Внешняя папка `C:/Projects/RAZVILKA` не является Git-репозиторием, поэтому каждому чату назначается собственный явно указанный worktree внутри `worktrees`.

| Направление | Ветка | Папка | Первый результат |
|---|---|---|---|
| CORE | `sol/core-20261003` | `worktrees/sol-core` | Matching recovery обновлений через приложение; затем общий исполнитель |
| VLESS | `sol/vless-20261003` | `worktrees/sol-vless` | Engine-aware Xray evidence, диспетчер и контракт подключения |
| NET | `sol/net-20261003` | `worktrees/sol-net` | Same-peer WG/LKG и native endpoint lifecycle; затем AWG/DNS/NFQWS2 |
| OPS | `sol/ops-20261003` | `worktrees/sol-ops` | Журнал self-update и воспроизводимые fault/native package проверки |
| UI | `sol/ui-20261003` | `worktrees/sol-ui` | Ошибки настоящего HTTP и понятные состояния интерфейса |

Полное владение файлами, порядок зависимостей, конкретные задачи и условия приёмки находятся в [SOL_HANDOFF_RU.md](SOL_HANDOFF_RU.md). Общий файл всегда имеет одного автора. CORE пишет общие app/config/worker контракты, координатор принимает эти изменения. Остальные исполнители не меняют их параллельно.

В первом заходе — одна завершённая проверяемая порция, коммит и `handoffs/<ROLE>_RU.md`: diff, команды, коды завершения, ограничения и запросы другим владельцам. Новые крупные этапы следуют после интеграционной проверки. Ни один рабочий чат не публикует релиз и не меняет live-роутер самостоятельно.

## Принятые предыдущие работы

D00 завершён: сохранены локальные изменения владельца, сверены 1134 файла поставки, выполнены полные Linux-прогоны Go 1.26.5. Старые H00/IM-патчи повторно не применялись.

Первую порцию подготовили `/root/delivery_ui`, `/root/delivery_vless`, `/root/delivery_ops`. Следующую — `/root/d02_xray`, `/root/d04_wireguard`, `/root/d11_recovery`. Эти задачи завершены и больше не пишут общие файлы. Их worktrees сохранены как исходники принятых коммитов и отчётов. Нативные проверки WG, Xray и kernel cleanup выполнены координатором, ограничения приведены в [VALIDATION_RU.md](VALIDATION_RU.md).

Новая копия ещё не установлена на роутер и не опубликована. Наличие прошедшего CI не закрывает matching live recovery, общий LAN executor, аппаратную матрицу и длительную работу.

## Вторая порция пяти чатов

Первые коммиты CORE `6451f48`, VLESS `04dd691`, NET `3ee9a0e`, OPS `731a087`, UI `f4356d2` объединены обычными merge до `99ac304`. История всех рабочих веток сохранена. Коммит CORE `0a3a25b` с явными абсолютными каталогами компонентов принят отдельно; Windows-проверки CLI прошли, UI получил его для настоящего HTTP стенда.

- CORE: закончить startup/CLI/API wiring self-update; затем engine-aware Xray/WG API и общий default executor. Ему назначены также routecatalog/routekind. Перед сетевой приёмкой убрать overwrite чужого default и игнорирование ошибки IPv6 из `applyRecordedPolicy`.
- OPS: доверенное supervision/quiescence компонентов, отдельное принятие установленного неактивного компонента и rollback acceptance; затем замена shell file lifecycle на согласованный self-update протокол.
- VLESS: scoped Xray TUN adapter и воспроизводимый selected/control сценарий; затем D10. Общая регистрация и app wiring — CORE.
- NET: исправление выявленного native D05 сбоя, затем AWG compatibility и DNS TTL. D04 live-after IPv4/IPv6 подтверждён координатором.
- UI: recovery и единый workflow D12; настоящий policy HTTP/браузерный тест после path fix, без synthetic transport.

Координатор выполняет Linux/race, native Xray/WG/kernel/package испытания и принимает небольшие коммиты. До подключения recovery/самообновления промежуточная сборка не устанавливается на рабочий роутер. Рабочие чаты не запускают общие live-окна.

## Уточнение владельца общего журнала сетевых правил

После согласования с CORE новый `internal/dataplane/policy_addition_receipt*.go` (реализация и новые unit/fault/native tests) передан VLESS. Контракт — [CORE_POLICY_ADDITION_CONTRACT_RU.md](handoffs/CORE_POLICY_ADDITION_CONTRACT_RU.md). CORE подтвердил, что этот модуль не начинал и параллельно его не пишет; существующие policy mutation/kernel helpers, manager/app/config и D07 остаются у CORE. Новые необходимые изменения этих файлов согласуются с владельцем.

VLESS реализует один общий протокол для proxy и WG, затем подключает proxy. NET использует тот же API для WG. Отдельные парсеры и переписывание legacy `route replace` в каждом адаптере не нужны: исправленный общий primitive `b3bc486` уже принят и проверен настоящим ядром. Такая передача освобождает CORE для self-update и app wiring, сохраняя одного автора каждого общего файла. Координатор проверяет реальные crash/foreign-owner сценарии отдельно от unit тестов.

## Дополнительные направления — 04.10

Чтобы D11 и WG/DNS не задерживали независимые D09/D13, созданы два чата `gpt-6.1-sol` от интеграции `fe7d0ab`:

| Чат | Ветка / папка | Задача |
|---|---|---|
| RAZVILKA CLOUD · 6.1 sol | `sol/cloud-20261004`, `worktrees/sol-cloud` | D13: WARP/USQUE и источники; id `01a10395-72aa-7f10-a98f-bbdb05418f05` |
| RAZVILKA NFQWS · 6.1 sol | `sol/nfqws-20261004`, `worktrees/sol-nfqws` | D09: bounded локальный подбор; id `01a10395-74c0-7cb2-a735-f9f3e4fbc52e` |

Перед передачей проверен WIP прежних владельцев: перечисленные в новой таблице SOL_HANDOFF файлы не изменялись. OPS и NET уведомлены о передаче; их активные изменения сохранены. CORE по-прежнему единственный автор app/worker/config. Новые чаты не запускают общие live-окна и не регистрируют публичные аккаунты.

По отдельному запросу пользователя исследователь перенесён из временной задачи `router_research` в пользовательский чат **RAZVILKA RESEARCH · 6.1 sol**, id `01a10399-da1b-7800-94fd-df9d5ce762c5`, ветка `sol/research-20261004`, папка `worktrees/sol-research`. Временная задача передала findings и остановлена; дублирующего поиска нет. Исследователь ищет применимые реализации в первичных проектах для роутеров и сетевых программ, проверяет лицензии и ограничения. Первые темы: согласованная LAN/DNS маршрутизация и Stop/восстановление при обновлении. Он не меняет production код; координатор передаёт выбранные решения владельцам соответствующих файлов.

## Параллельная реализация общего пути — 04.10

По согласованной с CORE границе создан **RAZVILKA DEFAULT · 6.1 sol**, id `01a103df-5be1-7233-ae14-f6af8fdd9edd`, `worktrees/sol-default`, branch `sol/default-executor-20261004`, base `e0e83db`. Его исключительная область — новые `internal/app/default_route_executor*.go` с тестами и `handoffs/DEFAULT_RU.md`. Существующие app/main/config/manager/plan/policy остаются у CORE. Исполнитель делает review/compiler/Execute через один Manager; CORE добавляет ingress в точные kernel selectors/receipts и atomic applied NetworkPolicy CAS/undo. Первая IP-only capability не закрывает требуемые domain-aware исключения/overrides; DNS→IP не становится доказательством flow identity.

NFQWS дополнительно получил только новые `internal/components/nfqws_supervision*.go` и собственные тесты для согласованного bridge существующего subreaper supervisor. Существующие OPS helpers принадлежат OPS. Persistent intent/receipt остаётся в текущем Strategy Lab, новые общие журналы не создаются. CLI dispatch и app worker подключает CORE; native/live acceptance — root.

Вспомогательная задача `/root/review_core` получила отдельный `qa-build-gate` worktree и три файла build/check/mock-test. Коммит `53bcc93` принят: ARM64 check на Linux amd64 создаёт оба необходимых test binaries без промежуточного MIPS/MIPSel; install/update/rollback/remove не пропускаются. Эта порция завершена; дальнейшие изменения этих файлов снова через координатора.
