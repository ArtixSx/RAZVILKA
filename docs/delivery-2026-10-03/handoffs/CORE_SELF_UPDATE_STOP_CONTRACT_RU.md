# CORE → OPS: durable Stop outside the frozen application files

04.10.2026 checkpoint: module реализован в `internal/operationgate/self_update_stop*.go`; Windows unit tests и vet проходят. Linux native tests добавлены, здесь только кросс-компиляция; координатор выполняет native acceptance. HTTP/OPS consumers ещё подключаются, end-to-end Stop PASS не заявлен. Ниже прежнее проектное описание уточняется фактически существующим API: schema1; поля Owner, InstallationID, Sequence, TransactionID, ConfigRevision, State, Stopped, Digest. Ready имеет epoch1, Stop повышает epoch; явный `InitializeSelfUpdateControl(ctx, root)` разрешён только trusted Prepare и не сбрасывает Stop. `WithSelfUpdateEffectAdmission` уже реализован с общим коротким kernel lock. Отсутствующий marker в существующем root не восстанавливается для запуска/Initialize/Stop; неполный ledger требует review. `ErrSelfUpdateStopChanged` отличает identity/epoch/revision mismatch от повреждения journal. Windows проверяет process interruption, не Linux power-loss durability.

04.10.2026. Конкретный контракт для передачи координатором OPS. Это следующий сопряжённый module/consumer, **не уже выполненный Stop PASS**. CORE владеет `internal/operationgate/self_update_stop.go`, app HTTP/admission и exact runtime cleanup orchestration. OPS потребляет readonly guard в actual supervised helper/startup/Authority/Run/Live/Finish; не пишет параллельный Stop ledger. Existing operationgate Guard/Fence используется для admission; его память сама по себе не durable Stop.

## Общий нейтральный API CORE

```go
// Fixed root is provided by trusted startup, never from HTTP.
type SelfUpdateStop struct {
    Schema int
    TransactionID string
    ConfigRevision uint64
    Sequence uint64
    State string // requested, cleanup-unknown, observed-stopped
}

func RequestSelfUpdateStop(ctx context.Context, root, transactionID string,
    expectedRevision uint64) (SelfUpdateStop, error)
func ReadSelfUpdateStop(ctx context.Context, root string) (SelfUpdateStop, bool, error)
func CheckSelfUpdateStop(ctx context.Context, root, transactionID string) error
func RecordSelfUpdateStopped(ctx context.Context, root, transactionID string,
    sequence uint64, observe Guard) (SelfUpdateStop, error)
```

Errors `ErrSelfUpdateStopped` (any active stop request, including observed-stopped) и `ErrSelfUpdateStopJournal` (unavailable/corrupt/mismatch) должны быть различимы. `Check` fail-closed при **любом active Stop**, даже ином job ID: старое поручение не переносится на новый helper через смену ID. Никакого implicit clear/reset на Startup/Prepare/Finish/reboot. Read не создаёт каталог/lock/file. Request повтор exact ID/revision — идемпотентный receipt; different ID/revision — mismatch без overwrite. Sequence binds дальнейшую cleanup observation к этой конкретной revocation. Core rechecks current file/helper ID и live Store CAS перед Request; library обеспечивает durable exact matching и не доверяет произвольному DTO.

Production root `/opt/var/lib/razvilka/self-update-stop`, вне `self-update-files` images и вне config/private restore. Fixed `current-v1.json` + retained per-ID immutable revocation request; permanent nonblocking kernel-lock marker с проверкой marker/inode. Strict canonical checksummed schema/ID/revision/sequence/state, bounded reads, no symlink/root traversal, 0700/0600, file fsync + directory fsync. После initial request разрешены только monotonic observation records этого sequence; intent/history не удаляются/не переписываются другим поколением. Windows model tests не подтверждают Linux durability.

## HTTP Stop и authority

Ограниченная recovery-панель подключает штатный `/api/v1/service-control/runtime` Stop с auth/Origin/CSRF, confirm `STOP_OWNED_ROUTES`, exact expected_revision. В режиме retained application replacement этот endpoint сохраняет Stop ledger **без config write**, не запускает обычный CommitServiceRuntime. Это отдельная revocation admission: не ждёт/не заимствует installer Exclusive lease, не обходит private/network ownership fence для cleanup. После успешного fsync ответ 202: `stop_requested=true`, `authority_revoked=true`, `stopped_confirmed=false`, `cleanup_pending=true`. На ошибке durable write не заявляет revocation или cleanup success. GET matching recovery показывает receipt и отдельный cleanup status.

OPS обязан вызывать `CheckSelfUpdateStop` перед каждым replacement/launch/start/runtime recovery разрешением и после наблюдений. Matching Startup даже actual supervised helper identity не обходит durable Stop. Во время длинной команды trusted supervisor наблюдает ledger и отменяет свой ctx; он join/проверяет **своё** exact supervised дерево, не ищет/убивает произвольный PID/PGID/name. CORE отзывает bounded applied-node/startup worker и ждёт его cleanup. Terminal file receipt/Finish не очищает Stop и не разрешает автозапуск. Если Stop произошёл между file Accept и helper Finish, provider оставляет helper в requires-review; не объявляет running/live accepted.

Файловый Restore в stopped direction может быть отдельно разрешён как bounded recovery old/new images после trusted quiescence. Он не запускает panel/runtime и не снимает Stop. `Authority` для effects поэтому получает различимый тип действия: **read/observe**, **replace-to-rollback**, **stop-owned**, **start/live**. OPS может предложить нейтральное дополнительное method signature `AuthorityAction(ctx,id,revision,action)`; CORE добавит его в интерфейс. Общий безусловный `Authority` с ErrStopped остаётся для start/live/new install; нельзя обходить Stop простым matching repair ID. Unknown commands не replay даже для Stop.

## Обязательное уточнение: Stop и начало эффекта имеют одну точку admission

04.10.2026, после research `48b3ab0`. Описанный выше readonly `CheckSelfUpdateStop` **не достаточен для разрешения spawn/effect**: между чтением и syscall может быть принят Stop. Этот раздел уточняет прежний API, а не разрешает OPS обходить guard до появления CORE module. Текущий uncommitted OPS `SelfUpdateStopCheck(context.Context, string) (bool, error)` подходит для readonly наблюдения/cancellation; для start consumer нужен отдельный linearized admission callback.

CORE остаётся единственным владельцем независимой authority в `internal/operationgate`. Финальная запись требует installation identity + монотонный control epoch, а не только job-local boolean. Proposed `SelfUpdateStop.Sequence` служит этим epoch и не откатывается вместе с old/new config. Общий root остаётся вне frozen files/private restore. OPS **не создаёт** альтернативный `self-update/ID/stop.intent.json` как источник authority. Fresh bootstrap требует trusted installation ownership; missing/corrupt record после установленного bootstrap не означает разрешение старта. Resume позже повышает epoch и не оживляет tickets прежнего helper.

Дополнение к neutral boundary, пока проектное, не уже существующая функция:

```go
// begin only admits the bounded start syscall of this exact effect.
// It does not run/wait opkg, fsync a payload, acquire a Store or call this API.
func WithSelfUpdateEffectAdmission(ctx context.Context, root, transactionID string,
    expectedSequence uint64, effectID string, begin func() error) error
```

`RequestSelfUpdateStop` и epoch validation + `begin` используют **один** короткий межпроцессный control lock, независимый от installer Exclusive/writer lock. Trusted effect identity/durable intent заранее фиксируется owner journal и связывается с review epoch; effectID не приходит из HTTP. Если Stop первым принял lock и сохранил revocation, begin не вызывается. Если begin допущен первым, Stop повышает epoch, отменяет уже допущенное owned дерево и требует join/cleanup. Длинная команда не удерживает control lock; actual worker продолжает читать authority, включая перед собственными child starts. Admission ticket без синхронизации с реальным `Cmd.Start` не закрывает гонку. Readonly callback или дополнительное чтение после Start также не закрывает её.

File effect, live acceptance и helper settlement имеют тот же review epoch. Payload USB writes проходят отдельную admitted/cancelable operation; durable file outcome не превращается в start/live authority после revocation. Публикация live результата обязана учитывать актуальный epoch; receipt, принятый до Stop, после повышения epoch показывает остановку, а не resurrected running. CORE/OPS согласуют action-sensitive authority `AuthorityAction(ctx,id,revision,action)` из OPS WIP: read/observe, replace-to-rollback и stop-owned сохраняют независимые exact matching/quiescence fences; start/live/new install требуют актуальную unstopped authority. Нет generic matching-ID bypass и нет unknown command replay.

Нужные barriers для native review: Stop непосредственно перед/после bounded spawn admission, во время long command и каждого file rename, между file acceptance/helper Finish; ACK → crash/reboot/restore. После Stop ни один позднее допущенный child/start не появляется; ранее допущенные проверяются cancellation/join и не считаются остановленными по пустому scan. Failed fsync/unknown schema не возвращает successful revocation. Old/rollback binary также обязан понимать authority schema; один guarded init не заменяет его HTTP/worker guard. Existing gate/scheduler/owned supervisor остаются, второй scheduler не создаётся. До реализации module + actual consumer production `-self-update-schema` остаётся **0**, `7b8db16` остаётся foundation для review, а Stop не объявляется готовым.

## Exact owned cleanup и подтверждение

После revocation CORE запускает отдельную bounded cleanup только после подтверждённого освобождения прежнего installer/runtime lease и trusted helper quiescence. План/receipt/launch identity читаются readonly, mutable private Stores не восстанавливаются/мигрируются. Используются штатные concrete adapter ownership checks и общий VLESS addition receipt primitive. Foreign tuple/process/interface и unknown addition/removal не удаляются. Ошибка/unknown оставляет `cleanup-unknown` и retained fence, HTTP никогда не выдаёт stopped-success по одному пустому process scan. `RecordSelfUpdateStopped` требует trusted независимое наблюдение **до и после** durable observation записи: exact owned runtime absent, helper/startup worker quiescent, все receipts согласованы. Выбор bool/PID/path из HTTP не является proof.

Restart читает этот ledger до нормальных bootstrap effects и запрещает helper/runtime auto-start. Explicit Resume — отдельный последующий CORE/D07 reviewed protocol, только после settled file/helper transaction, observed cleanup, fresh CAS/owned plan/network proof. Ни обычный restart, ни matching Accept, ни новая job ID не равны Resume. До реализации Resume ledger сохраняется; восстановление приложения без запуска возможно только по bounded rollback authority выше.

## Проверки для принятия OPS/CORE

1. Stop while installing/start command/node recovery owns Exclusive: revocation durable202 без ожидания/перезаписи config, worker authority revoked, exact join; no third application image.
2. Restart на requested/cleanup-unknown/observed-stopped: никакого startup/installer/runtime resume; inspection остаётся доступным.
3. Stop before/after candidate live и между terminal file/helper writes: отсутствие ложного live/stopped PASS; не повторяется команда.
4. Concurrent Stop/CAS/job mismatch/Stop write fault, corrupt/symlink/mode/checksum/lease marker: fail-closed, intent не теряется.
5. Actual owned cleanup versus identical foreign defaults/PID reuse/unknown addition: foreign сохранён; cleanup unknown не выдан за success.
6. Library root-only Linux fault matrix (intent/fsync/rename/observation), native subreaper cancellation + reap, actual application HTTP stopped authority. CORE Windows fixtures не являются native acceptance.

Пожалуйста, OPS подтвердить consumption APIs и action-sensitive rollback authority/order до capability1. Координатору разрешено переслать этот текст как concrete contract. CORE текущую foundation portion коммитит с capability0, затем реализует общий Stop ledger в согласованной маленькой порции; app dispatch D02/03 и D07 остаются следующим critical path, план не закрывается на recovery foundation.
