# Исходный NFQ owner для COMMON, native queue и повторного Stop

Порция подключает законченный NFQ whole-graph/stock-listener observer к обычному
исходному managed NFQ выполнению. Номер managed queue берётся только из
`NFQWSActiveMaterial.BindExecution` и сохранённого private participant.
Штатные очереди допускаются как точные comparison rows лишь после полного
доказательства OUTPUT-only reachability на неизменённом actual inventory.
Числа очередей, имена vendor chains и decoded journals не дают исключений.

Зависимость: законченные NFQ `94b9c53e` (whole typed read image), `d2e5abb1`
(reviewed matcher ABI) и `e3e80fc8` (opaque fresh queue proof). Root уже перенёс
их как `36e04df6`, `c1481b2a` и `06979981`. Также требуется прежний original
direct-mode/untimed-activation/retained-Stop путь CORE, уже принятый Root.

## COMMON observation

Production `BindNetworkPolicyChecks` удерживает тот же concrete inventory,
который заморожен при trusted startup. Внутренний stock bridge требует SAME
Manager, registry generation, gate/binding/runtime, NI/provider, actual NFQ
adapter, tools/collector и исходный private execution context.

Для существующих owned NFQ rows берутся только строки того же raw image,
канонически совпадающие с исходными receipt-qualified observations. Optional
missing intent rows не добавляются в capture. Полный граф остаётся нетронутым.
Сравнение штатных rows освобождает только collision classification; все
обычные обязательные counts, порядок, syntax и project ownership остаются.
Standalone `CheckLANPolicyInventory` и bare predicates остаются strict.

Исходные consumers/owners проверяются до последнего полного capture. После
него исполняются только pure comparison и прежние file/root bookends.
Сравнивается весь opening/closing image, включая прочие таблицы.

## Preparation, native life и retirement

Первичная absence до выдачи SessionID использует actual concrete inventory и
actual original queue, без dummy compiled command. Unlaunched/rollback absence
сохраняет original compiled absent predicate с точными stock comparison rows.
Дополнительная whole-image equality защищает closing inventory.

Три native callsites — readiness transition, live owner read и retirement file
closure — используют private `admission.execution` от SAME ordinary participant.
Остальные native lifecycle/Wait/ECHILD/file CAS проверки не изменены. Admission
без такого original participant продолжает использовать strict typed observer.

Отдельная final absence использует precompiled strict graph без любых owned-row
исключений. Opening whole image дополнительно проходит полный COMMON predicate
с nil LAN, а queue proof требует равенства closing whole image. Поэтому
отсутствие managed listener не маскирует оставленные project effects.

## Повторный Stop

`Manager.CheckRetiredManagedNFQWSAbsence(ctx, cleanup, handle, observation, checks)`
требует свежую finite actual cleanup operation и тот же настоящий успешно
retired final handle. Private admission удерживает исходный execution pointer;
закрытый scope/оригинальный removed resource/retained owner должны совпасть.
Copy, DTO, другой Manager/resource/checks или восстановленный журнал не подходят.

Read-only context действует только внутри этого вызова и отзывается при выходе.
Он разрешает fresh queue/backend/consumer/RPDB observation, но не оживляет
forward scope, source, command admission или Start. COMMON `RetireCheck`
использует этот исходный NFQ participant вместо прежнего process-only observer,
который всегда оставался closed; остальные adapters и standalone NFQ inactive
observer не изменены. Для native invocation дополнительно требуется настоящий
Wait/retirement и actual removed COMMON receipt с file bookend.

## Проверки и пределы

Windows: `go test ./internal/dataplane ./internal/app -run
'^(TestNetworkPolicy|TestNFQWS)' -count=1` — PASS (57.268 s / 0.953 s).
Win vet и Linux arm64 vet обеих packages — PASS. Focus новых COMMON/terminal
tests — PASS (16.377 s). Tests используют actual protected COMMON writer и
оба execution writers; NI/kernel/process transport leaves явно моделируются.

Здесь не выполнялись native/router/ELF/Linux tests. Успешный ACTIVE, физический
LAN маршрут и timing budget должны быть проверены Root на точной объединённой
версии: ordinary Start → ACTIVE → fresh Stop → repeated Stop → next Start.
15-second activation/Stop bounds не расширены. Domains/synthetic/Xray runtime
не включены этой порцией.
