# NFQWS: actual parent/helper Start bridge

Дата: 2026-10-04. Зависимость: ROOT-reviewed DEFAULT scalar binding
`2a2b8a8ed5424031233eb5647c6762ba483eaf6a` и typed metadata `bbdd0da`.
Normal merge `db122ed` без конфликтов; чужие owner files вручную не менялись.
Ни binding DTO, ни metadata, ни этот private callback bridge не публикуют
production launch capability. DEFAULT пишет issuer/барьер, CORE владеет
production constructor и Stop; actual combined wiring ещё не принято.

## Finished private ABI

`nfqws2ManagedStartBinding` — alias принятого `NFQWSExecutionBinding`:
ExecutionID, PlanID, PlanDigest, ResourceID, ResourceGeneration, EffectsDigest,
SessionID, CommandSHA256. Identity хранится optional `execution_binding`
в существующем `ownership.json`, **вне command hash**. Это предотвращает
цикл command hash -> compiled scoped spec/effects -> resource digest.
Она строго связывает command.ID/hash, но сама не является разрешением.

`runManagedNFQWSProcessWithAdmission(ctx, command, helperPrefix, admission)`
использует private callbacks существующего live common Execution:

- `BeforeStart(ctx, binding)`: exact owner readback и durable process-pending
  **до** producer intent, parent helper Start или child qnum bind.
- `WithStart(ctx, binding, begin)`: synchronous одноразовый start/close barrier
  Manager; удерживается до actual child Start и durable STARTED ACK либо
  bounded unknown outcome. Close обязан дождаться begin; callbacks нельзя
  отправлять в detached goroutine или удерживать как reusable issuer.
- `Prepared(ctx, binding)`: после ACK и release start barrier подтверждает
  actual Process/Queue/LAN `VerifyPrepared`, затем durable capture-ready.

Callbacks копируются, binding frozen. Перед/после они потребляют только
finished retained issuer; callback presence не доказывает authority.
Без вызова begin и после WithStart return повторный Start отказывает.
Root/path/session не приходят из произвольного CLI/JSON.

## Actual cross-process boundary

Parent создаёт private socketpair AF_UNIX / SOCK_SEQPACKET / CLOEXEC,
передаёт только helper endpoint fixed fd3 через ExtraFiles. Helper требует
этот endpoint для scoped intent **до открытия writer lease**: socket type,
Unix peer, peer credential exact parent PID/euid и fresh parent birth.
Helper dup endpoint CLOEXEC; NFQWS child его не получает. No listener,
socket pathname, discovery, persistent grant file или new CLI argument.

Одноразовый обмен: READY (durable armed exact helper) -> PERMIT (exact
binding/helper) -> STARTED (actual child Cmd.Start, true /proc birth/argv/
executable, durable running receipt). Каждая frame <=4096 bytes, typed
strict JSON с duplicate/unknown fields refusal; truncation, ancillary data,
EOF, timeout, unexpected/replayed phase и mismatch — unknown/refusal.
Parent exchange deadline min(session deadline, now+3s); session <=15s.

Manager start barrier охватывает parent Start и весь обмен. **3c lock**
охватывает только соответствующий actual Cmd.Start: parent освобождает
его до READY/ACK ожидания, helper освобождает до Started publish/ACK.
Hash/readers, journal writes, socket I/O и Prepared идут вне 3c lock.
Таким образом parent не держит control lock, необходимый child Start.

Scoped binding в persisted intent без live channel не позволяет Start.
Обычный private process-only producer и ранее принятый ec/native harness
сохраняются; они не используются как production scoped issuer.
STARTED ACK не означает queue-ready, terminal ACK или service health.
Нужны отдельный Prepared и existing exact ECHILD + parent terminal ACK.

## Failure / lifetime

Lost ACK после PERMIT не превращается в not-started/unused и не допускает
повтор. Parent сигнализирует exact helper и ожидает existing kernel receipt;
независимая terminal ACK допустима после отмены/Prepared refusal. Журнал
Execution остаётся pending до owner inactive/removal proof и common settle.
Scope closure serializes cooperative Start через Manager barrier. **Parent
death после PERMIT не является атомарным kernel no-fork proof**: текущая
parent identity проверяется перед child admission, existing supervisor
детектирует parent loss и убирает/reaps детей. Pending record после crash
сохраняется; missing parent/ACK/receipt не разрешает restart adoption.

Новые узкие private функции `nfqwsScopedBeforeStartCurrent` и
`nfqwsScopedPreparedCurrent` используют detached read-only binding с
Manager.Current. Copy не выходит в Apply/Runner writer path. Actual binding
сохраняет отдельный capture-ready ApplyGuard. Cleanup guard и
VerifyInactive/SettleRemoved остаются самостоятельными.

## Проверки / ROOT launcher

Локально: focused Windows managed/start/scoped regressions RC0; strict
frame decoder, foreign helper/resource/child, lost ACK, cancelled/revoked
permit, single-use/replay, outside-command binding hash, Current proof
vs capture writer. Windows vet; Linux amd64/arm64 test compilation и
shell syntax. Native/race/router/kernel actions локально не выполнялись.

Existing ROOT-only `scripts/test-nfqws-managed-process-native.sh` теперь
добавляет `TestNFQWSManagedProcessLaunchBridgeNative` к accepted lifecycle
и genuine no-intercept suite. Actual five cases: exact Start/ACK/terminal;
pending denied before intent; scope closed before Start; Prepared refusal
with independent ECHILD/terminal ACK; scoped persisted intent without fd3
refuses without changing intent. Retained begin callback тоже отказывает.
Это **private channel/process proof**, не production Manager/LAN/queue proof.

Следующий finished checkpoint DEFAULT должен привязать callbacks к opaque
live resource и original review/WAN/root identity, exact process-pending
phase и own one-shot start/close barrier. Затем paired constructor и ROOT
actual common Execution + genuine scoped packet oracle; production capability
остаётся закрытым до этой связки.
