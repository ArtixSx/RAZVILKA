# CORE: original exclusive operation context

Основа: accepted Root `9566d687a01fa2ec69e4eb29750fd601c7adb119`.
Порция касается operationgate и существующего App admission/default executor.
Новый ledger, scheduler, процессный owner и provider grant не вводятся.

## Контракт

- `Gate.ExclusiveContext(ctx) (context.Context, func(), error)` одновременно
  получает настоящее exclusive admission и выдаёт приватный original capability.
- `Gate.WithExclusiveContext(ownedCtx, use func() error) error` проверяет SAME
  gate, исходную отмену/срок, current fence и удерживает оригинальное admission
  через синхронный callback. Проверки до и после; ошибка callback сохраняется.
- Metadata `Snapshot`, labels, Holder, обычный `Exclusive` release, raw/foreign
  context и JSON/reference не создают capability. Старый context после release
  не оживает при следующем admission. `WithoutCancel` не продлевает исходный срок.
- Release одноразовый; начинает closing, запрещает новые uses и ждёт завершения
  уже допущенных callbacks. Cancellation/fence сами не освобождают admission.
  Release нельзя вызывать внутри удерживаемого callback. Owner сначала join,
  затем release. Panic callback освобождает use, но не поглощается.
- Gate mutex не удерживается через callback; metadata и вложенные Current checks
  допустимы. Closing запрещает позднюю вложенную проверку без взаимной блокировки.

Exclusive HTTP middleware теперь выдаёт этот настоящий context при первоначальном
входе (включая busy retry), а не из уже имеющегося generic exclusive release.
`App.privateExclusiveOperation` повторно использует активное exclusive admission
ТОГО ЖЕ запроса через существующее scoped retain. Shared GET не повышается до
exclusive, завершённый scope не заимствуется повторно. DefaultRouteExecutor
Review/Execute получают этот context; его guard проверяется внутри same-gate use.
HTTP Review→Execute сохраняет внешнее admission и не делает reentrant Enter.

Это только общий original-operation primitive. OPS command admission обязан
отдельно сверить exact command/held tools/immutable review/Store; короткий durable
control lock удерживается только вокруг настоящего Cmd.Start. CLOUD private
READY/PERMIT/STARTED ACK может удерживать original review use, но не этот control
lock через ожидание. Provider consent, физическая LAN, transport/TUN proof и
known-owner cleanup не выдаются этим capability. Истёкший forward context не
позволяет новый Start; cleanup остаётся у конкретного владельца и завершает join
до original release. Default production Apply этим коммитом не объявлен готовым.

## Проверки

Windows Go1.26.5, GOTOOLCHAIN=local, GOMAXPROCS=2, GOFLAGS=-p=2:

- operationgate full tests PASS 0.772s;
- App admission/private import/private restore/default suite с явным локальным
  `RAZVILKA_DEFAULT_WINDOWS_JOURNAL_TESTS=1` PASS 10.755s;
- новые actual middleware/default-executor fixtures: SAME original capability
  у Observe, successful single-manager commit, отсутствие повторного входа,
  outer-request retention, late/foreign/shared/released refusal;
- cancellation, original deadline даже через WithoutCancel, fence, joined release,
  late nested use, callback panic и concurrent idempotent release проверены;
- Windows vet operationgate/App/main RC0;
- Linux AMD64/ARM64 vet этих packages и operationgate test cross-build RC0;
- gofmt и diff check RC0.

Linux native/race и реальные command effects здесь не запускались; ими владеет
Root. Windows fixtures не являются production command-admission authority.
