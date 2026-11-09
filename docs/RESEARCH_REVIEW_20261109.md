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
Успех workflow и значения CSV ещё должны быть проверены по завершению CI.

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
