# Общий policy addition receipt — VLESS → CORE/NET

04.10.2026. По явному назначению координатора VLESS реализовал новый общий модуль `policy_addition_receipt.go` на согласованном `b3bc486`. Существующие policy mutation/kernel, manager и app не изменены. Proxy wiring и D10 будут отдельными коммитами.

## API и authority

`applyPolicyWithReceipt(ctx, runner, ip, state, receiptRoot)` и `removePolicyWithReceipt(...)` используют один CORE primitive/parser: `applyRecordedPolicy`, `kernelRulesForPolicy`, `kernelRuleArgs`, `recordedDefaultRoute`, `readPolicyRules`, `parseKernelPolicyRule`. Нет rewrite legacy argv и второго parser. `receiptRoot` передаёт trusted adapter code: существующий абсолютный private owned directory; не DTO/HTTP path. Фиксированные имена `policy-additions-v1.json` и `.policy-additions-v1.lock`; постоянный nonblocking kernel lock, без stale unlink.

Один root — одно неизменяемое поколение. Повторный apply не replay и не перезаписывает даже полностью removed receipt. Journal привязан к schema 1, random generation ID, полному canonical PolicyState SHA256, boot ID, trusted root hash и заново сконструированным add/delete argv. Strict canonical JSON, checksum, private regular bounded file, file fsync и Linux anchored directory fsync. Нет произвольной команды из JSON.

Каждый tuple имеет planned → durable intent → successful netlink → durable added. Любой intent без added остаётся unknown; matching readback и EEXIST не дают ownership. Cleanup идёт только по durable added, пишет cleanup-intent **до** del и removed после независимого absence readback. Lost cleanup acknowledgement не replay. Unknown rule сохраняет defaults, в том числе во время in-call compensation CORE, чтобы unresolved selector не открыл DIRECT fallback. Corruption, unavailable journal, boot/state/root mismatch, busy lock и unknown останавливают автоматическую компенсацию. Старый boot не принимается как успех старой команды.

`inspectPolicyAdditionReceipt(ctx, state, root)` возвращает только metadata (`ID`, Complete/Removed/Unknown/Promoted и counts), без kernel mutation и без новой authority. Это не health receipt.

## Promotion contract

`promotePolicyAdditionReceipt(ctx, state, source, destination)` **переносит** единственное cleanup право, не копирует два владельца. Оба каталога уже созданы trusted adapter code и проверены как private owned roots. Destination должен быть новым; source должен быть fully added. Сначала source durable promotion-intent с hash destination (source cleanup fenced), затем destination с тем же ID и своим root hash, затем source durable promoted. Settled transfer с matching destination ID идемпотентен. Interrupted transfer не replay и не возвращает право source; нужен отдельный trusted reconciliation. Raw copying receipt в иной каталог отвергается.

Adapter Commit обязан выполнить promotion и сохранить durable private reference на получателя **до** удаления transaction directory. В snapshot хранить prior generation reference; сами retained roots не удалять до verified settlement. Rollback после Commit должен удалить candidate через promoted destination, а не source. Refresh/recovery/restoration используют **новый** generation root; old receipt не оживляется и не перезаписывается. В policy.json не добавлен arbitrary path. NET получает тот же API для WG. Legacy committed ownership остаётся отдельно; новый staged missing receipt не допускает legacy fallback.

## Проверки

Windows Go 1.26.5: `TestPolicyAdditionReceipt*` PASS, включая три повтора основной группы. Lifecycle/no replay, nonblocking contender, EEXIST late identical IPv6 tuple и known IPv4 subset, unknown rule/default fence, cleanup-intent/lost deletion acknowledgement, strict corruption/argv/boot/state/root/lock mismatch, cancellation after intent, failure acknowledgement write, complete/interrupted promotion. Linux amd64 compile и vet PASS.

Новый opt-in `TestNativePolicyAdditionReceiptCrashBoundaries` **не запускался здесь**. Координатору: root в отдельном empty netns, `RAZVILKA_POLICY_RECEIPT_NETNS=1`, test binary `-test.run=^TestNativePolicyAdditionReceiptCrashBoundaries$ -test.count=1`. Preflight требует только lo и отличие self netns от PID 1. Test создаёт свой dummy и проверяет реальные kernel defaults/rules; 12 subprocess scenarios: intent/add/added и cleanup-intent/delete/removed на первом default и последнем selector. Child `os.Exit(73)` без defers; свежий reader не удаляет unknown tuple и очищает acknowledged subset. Fixture teardown использует только сконструированные tuple этого доказанно пустого namespace; не production reconciliation. Не запускать вместе с другим mutation fixture в одном namespace.

Race/full/native gates — координатор; real app/router restart/HIL и production LAN health contract этим коммитом не закрыты. XraySelectable/NETWORK_POLICY_EXECUTOR_REQUIRED не изменены.
