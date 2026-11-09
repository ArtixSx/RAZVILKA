# Независимая сверка исследования и реализации 09.11.2026

Исходная база: `0e2db5ab2120b20e249e3da7a8e861b558506550`, отдельный
worktree `research-build-20261109`. Владелец этого документа — independent_review;
общие API, roadmap и интеграция принадлежат ведущему. Ни одна запись ниже
не подтверждает аппаратную приёмку. Новые результаты проверки дописываются
отдельно от исторических доказательств.

## Что уже есть и что действительно остаётся

| Направление | Подтверждённое состояние исходников | Реальная дельта и приёмка |
| --- | --- | --- |
| Capabilities/API/AUTO | `runtime_lifecycle_capabilities.go` отдаёт регистрацию операций отдельно от `available:null`; AUTO использует общий с worker `autonomyRouteBlockReason`. HEV preflight не называется native validation. | Не заменять tri-state установленным бинарником или boolean PASS. Регрессии `TestRuntimeLifecycle*`, `TestAutonomyCapabilitiesDistinguishImplementationFromAdmission` и общий HTTP inventory. Per-plan Mihomo readiness зависит от завершённого lifecycle. |
| VLESS | Dispatcher удерживает общую квоту до joined cleanup; `node_job_timing.go` измеряет очередь отдельно; полный Check включает validation и cleanup, срок evidence не продлевается cleanup. | Подтверждать новую экономию одинаковыми fixtures и отдельными стадиями, не возвращать задержку TCP как service evidence. Основной контролируемый baseline уже существует; заново измерить текущий SHA. |
| Domain scope/DNS | Legacy proxy/WG запрещают адресный перехват domain-only сервиса без flow authority. Точные исключения проверяются до probe и публикации истории. | Failed-setup cleanup и GEN2 ready → cancel → retire → retry не завершены в native. Старый прогон `f71db55f` остановился на GEN1 DNS, новую cleanup lane не упражнил. Это программная работа, не отсутствие роутера. |
| Managed NFQWS2 | Scoped probe, история/manual intent и generation/ownership admission реализованы. | Полный LAN Apply → included/excluded traffic → Stop/recovery пока FAIL. Отдельный reviewed batch `098abc69` не интегрирован; его micro PASS не закрывает workflow. |
| Mihomo | Реальные Apply/Check и некоторые fault cuts достигались; current HEAD сохраняет exact stopped-plan wire images и исходные Stop phases. | Следующий Stop ACK refusal остаётся; нужны полный повторный Stop, fresh Apply, same-boot race/ACK cuts и ранний restart. Пакет/health archive не дают live readiness. |
| Backup/restore | Совместимая snapshot3 binary/StrategyLab пара, CAS/журнал, encrypted roundtrip и fences уже реализованы; исторический focused pair PASS для `a2d1c3c7`. | Повторить после lifecycle изменений; аппаратный power-loss отдельно. Верхний исторический guard-only раздел CURRENT_STATUS нельзя выдавать за текущее полное состояние. |

Источники исходного состояния: [основной roadmap](ROADMAP.md),
[runtime matrix](RUNTIME_SUPPORT_RU.md),
[сохранённая контрольная точка](validation/2026-11-02/budget-checkpoint/README.md).
Контрольная точка явно различает native FAIL/SKIP и generic CI SUCCESS разных SHA.
В отдельном `76c67f32` оставлены 22 WIP paths; переносить их целиком без разбора
metadata/restart и prior-history нельзя.

## Обязательная независимая проверка изменений P0

1. Изменение readiness не заменяет service proof: открытый чужой порт, неверная
   аутентификация, неправильный HTTP status и direct leak остаются отказами.
2. Отмена и собственный timeout сохраняют причину, прекращают ожидание и
   присоединяют cleanup; следующий checker не обходит cleanup fence.
3. Не меняются ресурсный guard, проверки network profile, exact node/engine,
   generation, exclusions и TTL evidence. UDP-only транспорт не отсекается TCP.
4. Queue, prepare/start, readiness, actual HTTP/proxy, service и cleanup не
   складываются с перекрывающимися стадиями как независимые интервалы.
5. Контролируемое ускорение startup или библиотечного SHA не называется
   сокращением полного Apply → LAN-ready; холодные/повторные прогоны раздельны.

Адресные существующие проверки: `TestExactNodeTimingIncludesValidationAndCleanupWithoutRenewingEvidence`,
`TestDispatcherSharesQuotaAcrossEnginesThroughCleanup`, `TestNodeCheckCancellationDoesNotPromoteProofOrSkipCleanup`,
`TestExactNodeCleanupDeadlineRevokesSuccessAndFencesNextCheck`,
`TestNodeEgressPairRefusalCancelsAndJoinsTheOtherPath`,
`TestLegacyProxySharedDomainAddressRefusedBeforeCapture`,
`TestWGRefreshCannotWidenCommittedCaptureToDomains`, `TestAutonomyResource*`.

Это перечень проверки кода, а не заявление о новом прогоне. Windows loopback,
Linux native namespace и физический router/LAN остаются разными уровнями.

## Ревью первого изменения

Независимо подтверждён дефект `startSession`: прежний восьмисекундный предел
проверялся только между попытками, тогда как текущий SOCKS greeting использовал
внешний context. Поэтому ответ после предела мог считаться успешной готовностью.
Исправление ограничивает текущую попытку дочерним context и проверяет его после
успешного ответа. Родительский context, resource guard, dispatcher quota,
closing identity, cleanup fence и правила service evidence не меняются.

`runtime_start` и `runtime_ready` — диагностические стадии; `route_identity`
теперь измеряется отдельно от startup. API сохраняет закрытый whitelist без
сообщений и адресов. Панель явно помечает интервалы как «не сумма».
`cmd/nodeeval` добавляет только наблюдения: последовательное ожидание кандидата
не называется очередью App, summary включает конечный recovery. Ограниченный
отчёт пропускает неизвестные статусы, идентификаторы и отрицательные длительности.
Admission, свежесть, успех HTTPS и отказ после неудачного cleanup прежние.

В ходе ревью исправлены якорь времени loopback fixture и проверка двух
последовательных кандидатов. Блокирующих замечаний к production diff не найдено.
Это допуск к интеграционным тестам, не подтверждение всех сетевых сценариев.

Независимо выполнено на Windows, 09.11.2026:

```text
node scripts/test-node-job-timing-ui.mjs      PASS
node scripts/test-node-measurements-ui.mjs   PASS (26 cases)
node scripts/test-node-browser-ui.mjs        PASS
```

Проверки включают expiry, точный executor, отсутствие ложного proxy latency
после failure/direct leak и защиту read/auth/mutation epoch. Go/native результаты
публикует ведущий по фактически завершённым прогонам интегрированного дерева.

## Ревью парного Linux workflow

`research-probes.yml` запускает baseline `0e2db5ab` и candidate на одном disposable
runner с одним SHA-проверенным Xray 26.3.27, одинаковым неизменённым harness и
`RAZVILKA_NODE_PERF_ALGORITHM=current-reuse` для обеих ревизий. Это сравнение
двух настоящих версий Check. `historical-request-reference` в существующем
harness — отдельная модель дублирующей пробы; она здесь не запускается и не
должна подменять baseline текущего исправления.

Для законченного прогона ожидаются 52 Check sample и 39 queue sample на каждую
ревизию: четыре сценария Check и три сценария queue по 13 строк. В каждой группе
первый sample отделяется от 12 повторных. Для последних nearest-rank p50 — шестой,
p95 — двенадцатый элемент отсортированных значений. Live, dead-service, cancel и
dead-node не смешиваются. App HTTP readback не является browser paint или LAN.

Порядок baseline → candidate фиксированный, поэтому небольшие различия могут
отражать нагрузку и файловый кэш. Первый Check холодный относительно fixture,
но не доказывает холодный page cache ОС. Private readiness timeout исправляет
поздний ответ; обычный healthy Check не обязан ускориться. CPU SELF/CHILD, observed
RSS и стеночное время анализируются отдельно; пустой child RSS не означает ноль.
Это предварительное ревью workflow. Результат первого завершённого CI приведён
ниже; последующие commits требуют отдельных результатов.

## Ревью измерений Mihomo handler

Проверен дополнительный diff `component_mihomo_probe.go` и timing helper:
`handler_elapsed_ms` заканчивается перед JSON-сериализацией, preparation включает
только работу внутри handler, `adapter_check_ms` включает собственный dataplane
cleanup, postcheck и finalize измерены отдельно. Неисполненная стадия отсутствует,
наблюдавшаяся длительность менее миллисекунды равна нулю.

Исходный `finish()` по-прежнему закрывает source/control и освобождает исходный
допуск до ответа. Позиции defer, panic fence, retained owner и исходные ошибки не
меняются. При 409 передаются только фиксированные диагностические поля времени,
не частично положительный probe result. Ответы 400, operation failure и отдельного
recovery не приобретают новые полномочия или выдуманные длительности.

Блокирующих замечаний к diff нет. Существующий native HTTP тест дополнен timing
assertions и сохраняет проверки `held == nil` и terminal `removed` после ответа.
Модельный тест ошибки helper не является доказательством native cleanup; результат
его настоящего Linux исполнения должен публиковаться отдельно.

## Повторная проверка после первого native прогона

Paired-native run `42557481299`, job `128966328426` завершился SUCCESS для
candidate `71b6f969579833e3ba217b331dc3c1a24bb150f7`. Независимый анализ подтвердил
52 Check и 39 queue строк каждой ревизии, один алгоритм `current-reuse`,
совпадение Xray SHA, ожидаемые live/failure verdicts, cleanup и exact identities.
Исходные артефакты и машинный анализ сохранены вне дерева в
`C:/RAZVILKA-research-20261109/ci/42557481299`.

Live repeated p50/p95 `407.049/411.030 → 406.042/407.920` мс не подтверждает
существенного ускорения первой правки. В candidate сохранён dead-service выброс
487.176 мс с configuration 100 мс; в all-vless sample 1 есть один RSS read error.
Эти наблюдения не удалены из расчётов. Minute-scale delay на этом fixture не
воспроизведён. Новый runtime_ready p50 101 мс отделён от runtime_start 1 мс и
route_identity 0 мс, что обосновывает отдельное исследование начального polling.

Повторное ревью nodeeval обнаружило неверную атрибуцию диагностических stages:
чужой или устаревший result мог прикрепляться к NodeID текущего запроса при
`fresh:false`. Исправление разрешает эти stages только после существующей exact
identity/freshness проверки; собственные wall measurements wrapper сохраняются.
Cleanup refusal остаётся обязательным независимо от происхождения результата.
Независимый запуск семи mismatch cases — PASS (`go test ./cmd/nodeeval -run
'^TestUnmatchedResultCannotAttributeStagesToRequestedNode$' -count=1`, 1.147 с).

Проверено последующее предложение локальной cadence readiness:
номинальные попытки 0/10/30/70/100/200 мс вместо 0/100/200. Добавляются только
три ранние попытки, исходный восьмисекундный context, process checks, поздний
отказ и cleanup сохранены. Реальная стоимость дополнительного I/O не нулевая;
native сравнение нового candidate должно подтвердить итоговый выигрыш и CPU.
Результаты `71b6f969` не являются результатами этой последующей оптимизации.

## Ревью продолжения durable node-check

Исходный секундный интервал подтверждён в `durable_service_jobs.go`: после
успешного bounded шага очередь выставляла NotBefore и timer на одну секунду.
При этом selector, recovery priority и ограничение durableBurst уже отдельно
обеспечивали уступку управления. Новая правка делает успешное продолжение due
сразу, но не запускает следующий checker рекурсивно и не удерживает прежнюю lease.

Проверено: исходный worker возвращает только после joined cleanup/release;
checkpoint сохраняется до wake; `r.mu` снимается до вызова `nudgeReconciler`.
Wake-флаг остаётся false до успешного persist. Чужой CAS, ошибка writer admission,
отмена родителя и blocked scheduler не превращаются в сигнал продолжения.
Stop/recovery, aging, burst3, busy5с и WAN30с/60с backoff не изменены.

Независимо выполнен `go test ./internal/app -run '^TestDurableNodeContinuation'
-count=1`: PASS, 2.310 с на Windows. Проверены запись cursor, свободная исходная
lease, один bounded шаг на turn, отсутствие wake/перезаписи при конфликте,
Stop/recovery/burst, отмена, WAN/busy и повторная проверка после restart.
Это проверка scheduler с реальными Store/journal/operation gate и моделируемым
checker. Полный native batch нового candidate и Linux race оцениваются отдельно.

## Независимое ревью последующих lifecycle исправлений

Все изменения ниже проверены отдельно от их автора; они сохраняют публичный
admission. Положительный portable regression не считается native приёмкой.

| Изменение | Проверенный контракт | Доказательство и ограничение |
| --- | --- | --- |
| Mihomo rotation и stopped wire (`94821d71`, `12879f78`) | Тот же original health cursor/header; compiler expected Plan приводится к собственной опубликованной wire shape, incoming документы не нормализуются | Before FAIL / after PASS; 20 mutations и обе ACK. Native d5 проходит прежние отказы, достигает terminal-close |
| Closing scope (`2e613a61`) | Сохраняется ровно original owned Mihomo definition; reader9 header и raw journal checks остаются | Before FAIL / after PASS; vet PASS после устранения copied mutex в fixture. Native2924 первой попытки не выполнялся из-за HTTP504 |
| DNS original capture read (`efe6cf3f`) | Каждый original resource.Current полный; callback-free closing associations, public/custom пути прежние; нет кэша между effects | Reviewer потребовал убрать callback из closing; принято исправление. Строгая native publication пока FAIL |
| Два retirement views (`2f08886a`) | Каждый view совпадает со своим настоящим holder; обе closed observations и точные coordinates | Genuine factory выдаёт два разных view. Native d5 проходит это место, достигает listener restoration failure |
| Восстановленный listener (`2924cd74`) | После обоих ACK, двух restored-standby проверок и original joined child отзывается CAS только точный witness; до снятия fences | Real-child regression PASS; Linux occupied-port test проверен и crosscompiled, выполняется generic Linux gate. Clean/две partial ACK проверяются отдельным native сценарием |
| NFQWS post-Add (`02ca980d`) | Loan охватывает свежий readonly readback, сам Add снаружи; false/foreign/stale/error сохраняют Pending1/Added0/Unknown | До FAIL / после PASS, независимый run0.563с и vet PASS. Full LAN ускорение пока не подтверждено |

Полные сырые результаты, включая неудачные попытки, находятся в
[lifecycle журнале](measurements/2026-11-09/research/lifecycle/README.md).


## Последующее ревью finite reads — 09.11.2026

`cc918208`: NFQWS current/health/original queue и точный COMMON ExactPresence
получили ограниченный original tool read interval. Все проверки процессов,
источников, inventory и счётчиков сохранены; closing refusal отменяет bool/count.
Новый набор содержит13 отказных и fresh-count сценариев. Runtime effect,
Start/Add/Delete и запись receipt выполняются вне интервала. Независимое
code review PASS; normal/race и полный native workflow ещё должны проверить
результат. Retire неизвестного частичного Add по-прежнему отказывает.

`61afd346`: только исходный domain producer объединяет чтение байтов между
ExactPresence→Guard→ExactPresence→Guard после сохранения intent/fault и до Add.
Все четыре вызова, порядок и классификация ошибок сохранены. Private scope
связан с original owner/process/capture/baseline/plan/runner, отзывается до Add;
чужой, истёкший или производный context не выбирает fallback. Public/custom
путь прежний. Reviewer потребовал точную owner.captureResource association
и сохранение причины ранней отмены; исправления включены. Новые проверки
mutation/cancel/order и actual-child cancellation добавлены, но до CI не
считаются PASS. Native counters pre-add-original-read/complete/command-boundary
отделяют вход в реальный factory от модели чтения файлов.

Общий policy effect guard не ослаблялся. Успех модели или уменьшение числа SHA
не закрывает strict DNS12/4, NFQWS LAN15с и восстановление частичного применения.


Mihomo `441e97e4` повтор42607484456: оба Apply104.215/104.272с PASS,
первый Stop6.028с PASS; второй closing cut завершился ровно на общем
fixture lifetime300с (whole300.40с). Это независимые пользовательские циклы,
но источники и peers ошибочно жили под одним сроком одного цикла. Исправление
только стенда даёт каждому циклу300с, первым включая setup; общий original
source lifetime600с и hard harness660с только для двух циклов. Один цикл
сохраняет300/360с. Per-operation110с и production apply480с не изменены.
App, исходные владельцы и peers сохраняются между циклами. Независимое ревью
PASS; native результат требуется повторить, ускорение не заявляется. Ошибка
bfc material refusal и высокая цена SHA остаются отдельными наблюдениями.
