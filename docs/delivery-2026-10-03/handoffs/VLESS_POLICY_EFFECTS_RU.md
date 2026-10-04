# Mixed policy effects receipt — VLESS → CORE/LAN

Общий backend поддерживает immutable mixed generation поверх существующего `policy-additions-v1.json`, private owned root, permanent `.policy-additions-v1.lock`, boot identity и алгоритма promotion. Это schema 2; schema 1 policy additions сохраняют прежние bytes/checksum и поведение. Оба reader отвергают другой режим. Существующий root нельзя дополнить эффектами или переинтерпретировать; новый Apply требует новый root.

## Доверенный API

`PolicyEffectPlan{Generation, Effects}` передаётся заново в **каждый** Apply/Remove/Inspect/Promote из trusted immutable Manager payload. Generation — lowercase hex64. `PolicyEffect{Tool, Add, Delete, Needs}` хранит enum `PolicyEffectIP`, `PolicyEffectIPTables` либо `PolicyEffectIP6Tables`, точные argv и отсортированные уникальные индексы более ранних prerequisites. Backend глубоко копирует ожидаемый plan, проверяет bounds/DAG и хеширует generation вместе с ordered tool/argv/dependencies. Сохранённые argv только сравниваются с ним; runner получает команды из private копии ожидаемого plan. Paths executable берутся из trusted startup `PolicyEffectTools{IP, IPTables, IP6Tables}`.

- `ApplyPolicyEffectsWithReceipt(ctx, runtime, plan, root)` создаёт новый ledger и последовательно применяет effects.
- `RemovePolicyEffectsWithReceipt(ctx, runtime, plan, root)` очищает только durable ACKed effects в обратном порядке.
- `InspectPolicyEffectsReceipt(ctx, plan, root)` возвращает существующий `PolicyAdditionStatus`; Complete означает durable ACKs, а не kernel readback или health.
- `PromotePolicyEffectsReceipt(ctx, plan, source, destination)` переносит одно cleanup право через существующие durable transfer boundaries.
- `PolicyEffectPlanDigest(plan)` возвращает metadata hash без разрешения на мутацию.

Максимум 4096 effects, до 128 args на команду, до 1024 bytes на arg, суммарно до 128 Ki args и 64 Ki dependency indexes. Предварительный byte/work budget проверяется до копирования; полный plan JSON ограничен 1 MiB, receipt — прежними 2 MiB. Oversize/invalid input отвергается целиком до первой мутации; усечения нет. Этот API — локальный контракт доверенных владельцев, его нельзя использовать как HTTP command permission.

## Обязательные runtime hooks

`PolicyEffectRuntime` содержит `Runner`, trusted `Tools` и read-only callbacks, привязанные к тому же immutable plan:

- `Preflight(ctx) error`: проверяет обе семьи и все collisions/foreign references до первого эффекта.
- `ExactPresence(ctx, index) (int, error)`: полное bounded readback конкретного ожидаемого эффекта; только count 0/1, duplicates/unknown syntax/foreign ambiguity дают error. До Add требуется 0. Matching preexisting tuple не становится собственным.
- `BeforeDelete(ctx, index) error`: проверяет live foreign references и kernel dependencies вне ledger DAG. Собственный chain нельзя удалить при чужой ссылке; anchor/default нельзя убрать под чужим selector/goto.
- `Guard(ctx, index) error`: проверяет текущую admission до эффекта и непосредственно перед RPC. Runner дополнительно должен потреблять CORE admission у actual process start; backend не держит Stop/control lock через весь Apply.

LAN compiler/inspector остаются у LAN owner. Его `InspectEffect(...)(count,foreign,error)` адаптируется так, чтобы `foreign=true` становился error. Обратный порядок требует, чтобы удаления body оставляли ожидаемый prefix, attachment исчезал раньше body/chain и RPDB prerequisites сохранялись до dependent gates.

## Сохранение исключений и unknown

У каждого эффекта прежние состояния `planned → intent → added → cleanup-intent → removed`; intent и cleanup-intent durable до RPC. После общего preflight intent записывается до первого per-effect readback: late preexisting exact attachment также оставляет unknown, а не planned child под live jump. RPC failure, lost acknowledgement и write failure после RPC не дают ownership по readback и никогда не replay. Unknown **любого** mixed эффекта запрещает весь generic cleanup, включая независимый known subset. Это намеренно консервативно: неизвестный attached jump удерживает отрицательные gates, chain body, anchor и прочие prerequisites.

Known teardown идёт строго назад и останавливается на первом failed guard/foreign check/readback/RPC. `Needs` дополнительно запрещает удаление prerequisite при ещё active или unknown dependent. Attachment должен зависеть от всего необходимого body, negative guards и RPDB prerequisites, а не только от chain creation. Generation/hash/digest совпадение не заменяет эту семантику.

До первого kernel readback при cleanup backend одним durable save временно переводит все исходные ACKed effects в cleanup-intent. Если save не удался, kernel inspection не начинается. Затем читается весь expected plan по сохранённым исходным состояниям: planned/removed effects должны отсутствовать, исходные ACKed — присутствовать ровно один раз. Любая absence, duplicate, read error, cancellation или failed guard оставляет fence и запрещает RPC. Только полностью согласованный scan и closing guard разрешают одним save вернуть исходные ACKed states в added и начать обычный обратный cleanup. Это сохранение прежних grants после scan без мутаций, а не усыновление readback. Crash во время scan или обнаруженное исчезновение ACKed effect удерживают всё поколение; fresh retry не усыновит появившуюся позже exact copy. All-planned/removed ledger не получает delete grants. Это более консервативный mixed contract, чем schema 1 known-subset cleanup; автоматического восстановления такой drift здесь нет.

Normal cleanup добавляет два metadata saves на полный scan. Failed restoration save после успешного rename может оставить readable added ledger, но restoration допускается только после scan без наблюдавшейся absence; caller всё равно сохраняет внешний transaction/recovery fence при ошибке записи.

Add после durable intent повторяет exact presence. Per-effect cleanup записывает cleanup-intent до `BeforeDelete` и exact presence: observed absence может завершить этот effect без RPC, но failed settlement save оставляет intent вместо старого ACK. Для present effect closing Guard идёт после read-only checks непосредственно перед RPC. Если за время записи ledger появилась чужая ссылка или duplicate, RPC не запускается и generation остаётся unknown. Проверка не является kernel-wide transaction: позднюю конкурентную мутацию должен корректно обработать primitive/inspector, а ошибку ACK нельзя превращать в успешное владение.

Promotion использует тот же алгоритм schema 1: source promotion-intent, active destination copy с тем же random ID и своим root hash, source promoted. Retry завершённого transfer принимается только пока matching destination fully-added и active. Consumed/further-promoted destination, foreign copy, missing/corrupt receipt, old boot и interrupted transfer дают fence без kernel RPC.

## Интеграционная граница

CORE владеет immutable `Plan.LAN`, journal participant и Manager order. LAN владеет compiler, mark/priority collision readback, runtime inspector, DNS/domain policy и native classifier acceptance. Данный backend не вводит второй Manager journal и не доказывает отсутствие конфликтов на firmware. LAN bits/priority из compiler требуют его фактического preflight. Actual forwarded flows, old-flow drain, app/router acceptance и DEFAULT consumers остаются отдельными проверками.

Caller обязан удерживать unknown transaction/recovery fence при любой ошибке durable write, даже если старый readable ledger ещё выглядит added. Нельзя ремонтировать файл или повторно принимать exact copy как owned после такого отказа. Admission для cleanup отдельная от нового Apply; Stop не превращает readback в новую мутационную authority.

## Проверки

Go 1.26.5, Windows: финальный `TestPolicy(Addition|Effects)Receipt*` PASS 15.133s, vet RC0. Матрица включает 30 mixed fault boundaries, batch scan fence/restore/crash/write failure, per-step absence settlement failure, late preexisting exact attachment, foreign reference/duplicate после durable intent, planned/removed reinsertion, ACK absence и fresh-copy fence, cancellation, closing admission guard, schema/boot/root/plan/DAG mismatch, aggregate limits, immutable copy, consumed promotion retry и прежние canonical schema 1 bytes/checksum. Независимый узкий прогон новых scan/per-step/initial absence regressions PASS 1.792s; финальный Linux amd64 compile-only и vet RC0. После финального protocol delta Root integration group прежнего receipt, proxy generation, rollback retry, scoped Xray, LAN HTTPS и Router HTTPS producer PASS 14.328s.

Новая opt-in Linux fixture `TestNativePolicyEffectReceiptCrashBoundaries` здесь **не запускалась**. Она требует `RAZVILKA_POLICY_RECEIPT_NETNS=1`, root, separate self netns относительно PID 1, только lo, пустые mangle обеих семей и только builtin RPDB до первого dummy. 30 children с `os.Exit(73)` проверяют intent/add/added и cleanup-intent/delete/removed на create, IPv6 negative guard, attachment, anchor и IPv6 goto. Fresh reader при unknown не выполняет runtime RPC и сохраняет весь kernel snapshot; known ACK cleanup сохраняет v4/v6 near-match rules. После coordinator Source41 RC1 обнаружена ошибка тестового oracle: вставленный порядок `-i/-s` сравнивался с kernel `-S`, который может их переставить. Теперь exact synthetic foreign tuple проверяется read-only `-C` до и после cleanup, а canonical readback сравнивается с собственным фактическим before baseline с count=1; unknown full snapshot и zero RPC assertions сохранены. Диагностика содержит только public synthetic argv и before/actual parent. Linux compile/vet исправленной fixture RC0. Координатор сообщил native Source43 `d3d7823`: все30 crash boundaries PASS, v4/v6 foreign near-match сохранены, unknown zero RPC/full snapshot stable. Это reported actual native результат координатора, не локальный запуск VLESS и не full D07/app acceptance. Teardown — только точные test-owned tuples с общим deadline, без flush/replace. Запускать отдельно от иных mutation fixtures; full acceptance — у координатора.
