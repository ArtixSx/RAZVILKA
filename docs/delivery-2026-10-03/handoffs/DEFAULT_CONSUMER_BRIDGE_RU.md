# DEFAULT: общий inventory и consumers-only retirement bridge

Finished source slice на принятой базе `616abe9`, ветка `sol/default-consumer-bridge-20261007`. Меняются только shared DEFAULT participant и его модельные проверки. Main/app/config, NFQ collector/Spec/queue, CORE proxy producer и NET physical observer не редактируются. Реальные router/VM/native операции принадлежат ROOT и здесь не выполнялись.

## Callable startup binding

`checks, err := manager.BindNetworkPolicyChecks(gate, inventory)` вызывается один раз в trusted startup **после регистрации всех фактических участников**, включая именно этот typed `*NetworkPolicyAdapter`. Используется SAME existing Manager, полный registry generation, существующий private Manager root и concrete `*BackendInventory` от SAME `*netidentity.Provider`. IPTables/IP6Tables aliases должны точно совпадать с gate runtime. Constructor не читает request DTO, не приобретает Manager operation gate, не пишет journal и не производит kernel/process effects. Публичного fake reader или API для передачи готового consumer allowance нет.

CORE construction order:

1. Сохранить `var checks *dataplane.NetworkPolicyChecks` в lifetime owner.
2. Создать typed gate через `NewNetworkPolicyAdapter` с исходными physical ScopeCheck, ApplyGuard и CleanupGuard. Для InventoryCheck/ConsumerCheck/RetireCheck передать **closures**, которые обращаются к переменной checks при каждом вызове. Method value от ещё nil receiver захватит nil навсегда; такой вызов отказывает.
3. Зарегистрировать gate и всех остальных owners на SAME Manager. DNS `InactivityKernelCheck` аналогично вызывает `checks.ScopedDNSInactiveCheck` через closure.
4. Связать checks указанным выше методом. Ошибка означает unavailable production binding, без success stub или lazy binding из первого HTTP request.
5. Сохранить Manager, checks, actual tools lease, original physical review и CORE effect/control guards в одном existing startup owner. `checks.Close()` отзывает чтения и закрывает retained descriptor; вызвать после bounded cleanup всех consumers. Close не останавливает процесс и не удаляет rules.

Методы:

- `InventoryCheck(ctx, fullIdentity, allowedLAN) error`: два полных fresh collector images, exact compiled LAN rows и независимо подтверждённые concrete consumers. Nil LAN требует отсутствия всех reserved rows.
- `ConsumerCheck(ctx, lan) error`: та же проверка, дополнительно нужен хотя бы один независимо подтверждённый live consumer.
- `RetireCheck(ctx, lan) error`: direct fresh `RuntimeInactivityObserver.VerifyRuntimeInactive` **каждого** другого actual registered owner, включая unused. Исключается только точный зарегистрированный LAN participant. Missing/nil/unknown observer отказывает.
- `ScopedDNSInactiveCheck(ctx, fullIdentity) error`: concrete full collector и DNS namespace predicate по всем rows. Действующая LAN gate допустима, поэтому DNS observation внутри retirement не вызывает false inactive verdict или рекурсию.
- `CheckLANPolicyInventory(snapshot, identity, allowedLAN) error`: отдельный pure gate-only predicate. Consumer rows здесь никогда не разрешаются. Это detached observation, не эффектный grant.

Bridge не вызывает `Manager.VerifyRuntimeInactive`, не повторно приобретает Manager operation и не ослабляет `CheckExecutionRecovery`. Pending journal текущего Apply/rollback/Stop не выдаёт foreign recovery verdict внутри consumers-only проверки. Call site по-прежнему держит исходный Manager operation gate и CORE cleanup guard.

## Что считается independently receipted consumer

Первый production observer поддерживает **actual registered scoped Xray** с existing forwarding creation lease. Выполняются исходные owner validators: frozen managed route authority и full LAN generation/default role, current node manifest/config/material/endpoints/profile, freshly compiled exact literal rules/exclusions, actual firewall body/order/creation ownership, same scoped TUN interface lease/index, process/sidecar launch/config/socket identity, RPDB/FIB evidence и exact common addition receipt. Service health, positive mark, chain name, copied config hash или supplied expected rows не заменяют эти проверки.

Original plan доступен gate callbacks через private operation context, который shared participant создаёт для своих существующих стадий. Холодное чтение использует только protected anchored `latest-committed-plan.json`, matching exact gate owner PlanID/Digest/LAN; candidate/latest intent не принимается. Plan digest является reference для existing owner binding; сам по себе он не подтверждает runtime или consumer ownership.

Сначала проверяются candidate binding + staged policy + complete common receipt. После promotion используется actual active retained binding/generation с SAME receipt ID. Common canonical checksum/compiled commands/boot/root/step validators сохраняются. Read-only reader открывает **существующий** permanent lock, проверяет private regular file, marker, SameFile и nonblocking lock. Missing/busy/corrupt lock или receipt отказывает; reader не создаёт lock, не сохраняет receipt, не ремонтирует metadata и не проводит migration. Anchored private proxy/common directories остаются открытыми до окончания обоих collector captures. Их inodes, private permissions, common checksum и owner observations должны совпадать.

WG/AWG, scoped DNS active redirect и NFQ active capture **не получают row allowance** от этой фазы. Для них нужны отдельные завершённые independently receipted owner proofs. В частности, NFQ active ownership/transfer A–E не реализован здесь и не выдаётся из schema/hash/typed identity.

## All-row refusal

Inspect производится по обоим семействам и всем зарегистрированным classic tables, включая custom/security, плюс полный native NFT predicate исходного collector. Exact gate body допускает known partial apply/cleanup subsequence в compiler order. Дубликаты, reordered body, foreign mask/table/family, orphan declarations и лишние jump/goto отказывают. Exact consumer body требуется целиком; вариант с только matching positive mark не разрешается.

Reserved chain families RZG/RZP/RZC/RZD/RZQ/RZT и mark/CONNMARK/HMARK/TPROXY/NFQUEUE forms рассматриваются как candidates для strict compiled comparison. Комментарий остаётся одним inert operand. All-row scanner не использует десять фиксированных table reads или unknown NFT errno fallback.

Consumer owner observations A и B окружают первое complete capture; затем выполняется final complete capture. Сравниваются **все** rows/coverage/NFT generation/scope, включая unrelated/custom rows. После final capture external consumer callbacks не выполняются. Manager root, actual registered instances/IDs/root paths, registry generation, exact gate binding/runtime/tools, typed identity и held proxy/receipt roots проверяются повторно. Никакой атомарности двух снимков или защиты от недетектируемого ABA этим не заявляется. Actual protected tool lease, NET continuous physical review и original CORE guards остаются обязательными.

## Проверки и пределы acceptance

Модели покрывают actual shared gate Apply/promote/Stop, live и unknown unused owner до первого delete, held operation с pending journal без Manager recursion, поздние registry/root/identity/binding/tool/cancel/close/image изменения, every-table/family/foreign-mark forms, full и partial exact gate, genuine modeled scoped proxy + candidate/retained common receipt, missing lock без recreation, absent receipt/process/generation, extra/lost/custom-table row и отсутствие mutation при отказе.

Combined Windows temporary journal models `TestNetworkPolicyInventory|Checks|Manager|ExecutionJournal|NFQWSScoped|Managed|LANPolicy|BackendInventory` PASS36.441s. Windows и Linux amd64/arm64 dataplane/app vet RC0; Linux amd64/arm64 dataplane test cross-compile RC0. Temporary binaries удалены. Точный commit pin передаётся ROOT отдельно.

Эти model/cross-build результаты не являются native/platform или ordinary Enable PASS. Actual CORE proxy Stage generation producer и canonical route roundtrip fix должны быть приняты ROOT отдельно; модель здесь явно подготавливает typed producer intent и не ослабляет verifier. Default transport proof issuer, physical/kernel effect admission, NFQ active lifecycle и обычная app registration остаются отдельными finished owner phases.
