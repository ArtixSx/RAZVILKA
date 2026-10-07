# CORE: retained control epoch и original cleanup lifetime

Parent: CORE `c62cc5526fda405d886789439a9d73bae421f65e`
(Root accepted equivalent `60c54ae`; Root Linux134 normal/race gate/App HTTP/
DefaultRouteExecutor PASS сообщил координатор; это не native effect admission).

## Конкретные interfaces

`Gate.ReviewControlEpoch(ownedCtx, existingRoot) (*ControlEpochReview, error)`
открывает только existing protected control root и permanent lock FD. Missing
authority не создаётся. SAME gate original exclusive capability обязателен.
Self-pointer защищает от zero/copy handles. Retained root/lock inode, marker,
current UID/mode, installation/sequence и Stop проверяются до/после каждого read.
Root/lock replacement (включая same-byte lock replacement) не выдаёт разрешение.

`Reference() ControlEpochReference` содержит только InstallationID/Sequence для
сравнения. `Current(freshSameGateOwnedCtx)` читает оригинальный retained owner;
fresh operation может сверить durable consent epoch. Detached reference, raw
context, foreign Gate и закрытый review не восстанавливают owner.

`WithStart(ownedCtx, begin)` удерживает существующий protected control lock ТОЛЬКО
через настоящий bounded Cmd.Start. Exact command/tools/Store/immutable review/
known process owner обязан предварительно связать конкретный caller. Control
primitive их не выдаёт. Callback не вызывает этот review и не выполняет Wait,
readiness, fsync либо cleanup. Ошибка callback сохраняется; closing failure не
становится successful ACK. Close закрывает FDs после short use, не release Gate.

Existing lockControl переведён на private lockControlFile с прежней семантикой
всех существующих self-update callers. Новый retained owner читает marker через
ТОТ ЖЕ locked FD: Windows mandatory byte lock запрещает read другого handle.
Новый ledger, Stop protocol, self-update permission или reset не добавлены.

`Gate.ReviewExclusiveCleanup(originalOwnedCtx) (*ExclusiveCleanupReview, error)`
выдаётся до cancellation/effects. `WithCurrent(freshFiniteCleanupCtx,use)`
проверяет только SAME ещё удерживаемую original admission lifetime и joins use
до original release. Cancellation/fence не освобождают lease. Новый forward
context/Enter/Start/provider grant не выдаётся; old forward deadline не продлён.
Zero/copy/raw/released handles и unbounded/cancelled cleanup context отказывают.
Actual owner отдельно подтверждает exact Stop/soleWait/ECHILD/receipt/cleanup
command. После Apply release активному owner нужен НОВЫЙ actual operation и
его собственный known cleanup proof; старый token не возобновляется.

CLOUD полный READY/PERMIT/STARTED ACK удерживает original review через Gate use,
а control WithStart применяется только к helper Cmd.Start. Actual child Start
остаётся у CLOUD helper + live private permit + same protected epoch. NFQ fresh
committed/cleanup guards связываются с concrete opaque handles и exact Store/
Plan; этот primitive не заменяет такие guards.

## Проверки

Windows Go1.26.5/GOMAXPROCS2/GOFLAGS-p2: full operationgate PASS 0.919s.
Новые tests: actual control read/Start/Stop lock linearization, missing no-create,
raw/foreign/zero/copy/closed refusal, detached ref edit, callback error, actual
same-byte lock replacement, marker drift; cleanup после cancel/fence без forward
authority и refusal после release. Root replacement test на Windows skipped:
OS запрещает rename удерживаемого root; Linux fixture cross-built для Root.

Related App self-update Stop/stopped/exclusive tests и Windows vet RC0.
Linux AMD64/ARM64 vet operationgate/App/main + operationgate test cross-build RC0.
Native effect syscall/race этой порции выполняет Root; обычный production Apply
без concrete consent, exact owner proofs и main wiring готовым не объявляется.
