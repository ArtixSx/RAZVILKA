# D10 — actual worker first-usable checkpoint

04.10.2026. Worktree `C:/Projects/RAZVILKA/worktrees/sol-autopilot`, branch `sol/autopilot-20261004`, base `43b6447394d07af85d61ab6ce37d8cd1d52ad4ae`. Единственный автор переданных worker/refill/reserves/store/decision и новых D10 helpers/tests. Root отдельно разрешил узкие изменения `autonomy_reserves_test.go` и `autonomy_candidate_failure_test.go`. Existing ranking, node/config/main/providerfeed/profile/store API не изменены; production go.mod/VERSION сохранены.

## Контракт и код

`runAutonomyService` теперь вызывает существующий `Nodes.SearchFirstUsable` для холодного пути или уже разрешённой замены, до подготовки общего reserve. Последовательно: fresh exact Check → durable consumed cursor → guard → обычный reviewed transactional Apply первого usable. ReserveTarget больше не задерживает первый Apply. Healthy LKG/same-node repair/failure quorum и общий exclusive operation lease сохранены; меньший ping не даёт основание менять работающий узел.

Новый `Runtime.Search` хранится в существующем autonomy sidecar, без второго журнала: ordered IDs (до512), version fingerprint согласия/service/scope/engine/WAN, monotonic consumed cursor, exhausted, retry time и halted intent. Начальное ordering детерминировано по IDs, существующий prefix не перестраивается после новых checks; новая страница добавляется в конец. Новая страница имеет приоритет перед повторной проверкой старого prefix даже после истечения локального retry interval. Restart не сбрасывает search; decode проверяет bounds/IDs/duplicates/exhausted и Clone отделяет mutable slices. Schema остаётся1: старый strict reader с DisallowUnknownFields отвергает неизвестный search, существующий blocked ownership guard сохраняет защиту. Дополнительный runtime write не становится NodeStore proof. Существующий общий предел sidecar256KiB сохранён: переполнение отказывает сохранению и Apply.

Cursor/budget/intent saves возвращают ошибки, вместо best-effort статуса. Cursor продвигается только для consumed unsupported/definite failure/fresh usable или явно пропущенного current/ineligible entry. Нейтрален только отдельный `ErrExactNodeUnsupported`, без history. Joined unsupported+runtime, local/cleanup/cancel/busy/inconclusive/ERROR не разрешают продолжение; reputation классификация остаётся существующей консервативной nodequality. Проверка кандидата проходит existing guarded `checkAutonomyReserveForEngine` → `checkAndRecordNodeForEngine`, общий dispatcher/slots не дублируются.

Перед Apply durable halted intent предотвращает C после crash/untrusted failure на следующем round/restart. Продолжение B→C разрешается только через typed candidate Health cause + matching execution/plan + verified rollback всех adapters/config + прежние network/config/definition/scope/consent + durable failure/budget. C проходит новую exact check после rollback. Successful Apply очищает локальный halted при финальной публикации; crash до финальной публикации оставляет консервативную review latch. Новое явное service enrollment через existing API создаёт новый Runtime. Ошибки без trusted continuation не становятся CandidateFailure/blacklist.

Engine берётся из exact current/expected route. Current proof, reserve proof, checks, Apply guard и rollback matching используют engine явно. Xray не получает Sing-box историю; поскольку existing ranking принадлежит CORE, Xray reserve ordering детерминирован по IDs с healthy current первым. Existing XraySelectable, NETWORK_POLICY_EXECUTOR_REQUIRED и history admission guard сохранены: Xray Apply capability этой порцией не открывается.

Refill учитывает consumed unsupported только при matching traversal version и точном engine/service/WAN. Пока snapshot не exhausted, следующая page не запрашивается. После первых32 unsupported без истории разрешён bounded `RequestRefillRanked`; existing manager сохраняет allowlist/enablement/cooldown/Retry-After/publisher fairness/queue dedup/TTL/snapshot paging. Source utility теперь explicit-engine. Healthy passive reserve maintenance остаётся отдельной legacy веткой; её CandidateBatch/status publisher не переписаны этим cold/replacement checkpoint.

## Проверки и команды

Go `C:/Projects/RAZVILKA/tools/go/bin/go.exe`1.26.5; `GOMAXPROCS=2`, `GOFLAGS=-p=2`, `GOTOOLCHAIN=local`. Приведённые Windows real-store прогоны выполнены через auto-reviewed `require_escalated`: sandbox-профиль этого чата блокировал atomic file write. Production fs/os.Root guards не менялись.

- Control `go test ./internal/restorejournal -run '^TestFileTargetReadOnlyAndExactCAS$' -count=1` — RC0,0.660s вне sandbox.
- Final `go test ./internal/app ./internal/autonomy -run 'D10|Autonomy' -count=1` — RC0; app27.141s, autonomy0.297s. Все autonomy/D10 tests, включая existing sticky recovery/rollback/refill regressions, прошли.
- `go test ./internal/app ./internal/autonomy -run 'TestD10Traversal|TestRefill' -count=1` — RC0 внутри sandbox, app0.089s/autonomy0.323s.
- `go vet ./internal/app ./internal/autonomy` — RC0. `git diff --check` — RC0; перед commit diff/owned-file list проверены. `git diff -- go.mod VERSION` — пусто.
- Первые sandbox прогоны real-store tests — RC1: `node store commit uncertain` ещё на первом Import в existing fixture. Независимый baseline `go test ./internal/nodestore -run '^TestStableIdentityFreshnessAndNoSecretSnapshot$' -count=1` — тот же RC1 в sandbox. Это не объявлялось PASS; CORE отдельно подтвердил свой RC0 на таком baseline. Исправление среды подтверждено последующими настоящими прогонами вне sandbox.

Новые app tests: первый usable Apply раньше следующего Check; cold B typed Health failure → verified rollback → fresh C; untyped Apply refusal сохраняет halt после reopen; cursor I/O fault не Apply/не penalty; busy/runtime/cleanup/cancel/inconclusive/ERROR/unsupported+local/Stop/SafeMode не consume; durable unsupported cursor после reopen+append page без повторения prefix; actual autonomyRound32unsupported→actual RequestRefill queue→approved passive entry33→fresh Apply; traversal decode/clone/order/late-page safety; exact Xray checker/history admission + unchanged Apply capability refusal. Existing definite-remote fixtures теперь BLOCKED/403, ERROR regression сохранена. Three-reserve fixture готовит резервы в отдельном healthy round: initial first-usable теперь проверяет только primary.

## Непроверенное и приёмка Root

Новые worker32→33 tests удерживают network admission настоящей providerfeed queue и моделируют **завершённый approved passive import** следующей страницы. Они не вызывают напрямую SyncSaved и не выдают этот fixture за настоящий HTTP304. Stable304 validator/origin TTL/paging покрыты существующим `providerfeed/TestSnapshotPagedFirstUsableAppliesEntry33AfterRestart304` принятой библиотеки; новый сквозной actual-worker+HTTP304 тест ещё нужен Root/владельцу providerfeed с согласованным transport fixture.

Linux/race/full-gate/native proxy/LAN/router restart/retained old binary/live feed и HIL/soak здесь не запускались. Не изменялись VM/router/accounts/release. D10 production/HIL readiness не объявляется. Для приёмки Root: final checkpoint merge, Linux `go test ./internal/app ./internal/autonomy ./internal/nodestore ./internal/providerfeed -count=1`, адресный race и existing stable304 test; native/live окно только Root. До изменения Xray ranking/actual config Xray consumer — согласовать с владельцами, capability gates не снимать.

Commit SHA и точный diff передаются сообщением Root после commit этого отчёта и кода.

## Follow-up: non-divisible tail / ring cursor

CORE read-only review выявил P2 в `bb489b6`: библиотека использует ring cursor и bounded Examined=len(Ordered). При full ordering3, persisted Cursor2, budget2 после unsupported последнего она могла ещё проверить entry0 и уменьшить durable cursor с3 до1. Exhausted терялся, refill задерживался. Аналогично full ordering32/cursor31/budget2; прежние budgets1/2 и4/32 этого не показывали.

App теперь передаёт библиотеке только `Ordered[absoluteCursor:]`, локальный cursor0. PersistCursor переводит локальное смещение назад в абсолютное; локальный wrap0 обозначает конец suffix. Library Examined bound ограничивает оставшийся хвост и не допускает проверку consumed-prefix. NodeStore/library API, guards, journal schema и rollback continuation не менялись.

Новый `TestD10RestartTailDoesNotWrapIntoConsumedPrefix`: реальные app/store/journal, deterministic persisted tail для3 и32 узлов при budget2; reopen → только один последний unsupported Check → monotonic cursor3/32 + exhausted; повторный reopen не проверяет prefix; approved passive page append → только новый usable Check → Apply + cursor4/33. OS/checker fixtures контролируемые, внешний fetch/native/HIL не выполнялись.

Адресный `go test ./internal/app -run 'TestD10RestartTail|TestD10Cold|TestD10Cursor|TestAutonomyCandidate' -count=1` — RC0,10.821s (Windows Go1.26.5/тот же env, auto-reviewed execution вне sandbox). Связанный `go test ./internal/app -run 'TestD10(Unsupported|Worker32)|TestAutonomyReserves(CandidateBudget|Definite)' -count=1` — RC0,2.561s. Final `go vet ./internal/app ./internal/autonomy` и `git diff --check` — RC0. Follow-up SHA передаётся Root после commit. Эта порция исправляет App ring/suffix boundary; общий library ring contract сохранён.

## Follow-up: Linux private feed fixture

Root Linux race log `delivery-review/.review-local/integration66.log` выявил единственный app failure: `TestD10Worker32UnsupportedQueuesRefillThenAppliesEntry33` на открытии providerfeed, до paging/assertions. Fixture передавал напрямую `t.TempDir()`, а Linux guard требует существующий absolute private0700 directory. Тест теперь создаёт child `feeds` через `os.Mkdir(..., 0o700)` и передаёт его реальному Manager. Production feed/NodeStore/ownedfs guards и код не изменены.

Адресный Windows `go test ./internal/app -run '^TestD10Worker32UnsupportedQueuesRefillThenAppliesEntry33$' -count=1` — RC0,0.913s; diff check — RC0; тот же Go1.26.5/env/auto-reviewed execution. Новый адресный Linux/race результат этой fixture-правки должен подтвердить Root; здесь Linux/native не запускались.
