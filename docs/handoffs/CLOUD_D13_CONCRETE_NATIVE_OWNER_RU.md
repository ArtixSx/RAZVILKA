# D13: concrete retained USQUE owner

Этот slice добавляет только новые CLOUD-файлы поверх принятого Root `da187f889b160f4ec7b218776613bdd434246bf2` (включает front door и concrete CORE primitives). Main/sharedApp/shared dataplane и существующие CORE/kernel primitives не изменены. CLOUD не запускал USQUE, существующий аккаунт, native helper, registration или сетевые действия.

## Реальный executable entry

`nativeowner.NewIssuer(originalFactory, HelperAsset{Path,SHA256})` реализует `nativeaccept.Issuer`; `nativeowner.RunCoordinator(ctx, request, helper, originalFactory)` запускает существующий настоящий `nativeaccept.Run`, `ProbeOwnedUSQUE` и независимый `ObserveOwnedUSQUE`. Это concrete process owner, а не alwaysnil seam. Отдельный `cmd/usque-owned-supervisor` собирается для Linux и запускается owner через reviewed inherited executable descriptor. Самостоятельный запуск helper без private seqpacket endpoint/held descriptors не выдаёт permission.

CORE получает минимальный original lease API из `nativeowner/contract.go`: фактический Scope (Acquisition, held netns Device/Inode, actual coordinator process birth, helper SHA/path, original operation deadline), Current, WithStart, WithEffectStart, Control, WithCleanup, Release, FenceUnsettled. Scope/Launch/Control hash доступен через `ReviewBindingDigest`; JSON struct не содержит maps или caller-selected digest. Hash/DTO никогда не становится grant. CORE владеет original exclusive operation capability, exact immutable review/Store/protected epoch и их wiring в main/sharedApp. API согласован с CORE; его original ExclusiveContext и protected epoch/cleanup primitives идут отдельными finished pins. CORE не реализует USQUE launcher.

`NewCOREFactory(originalOwnedCtx, actualGate, COREBinding)` использует конкретные принятые Gate.WithExclusiveContext, ReviewControlEpoch и ReviewExclusiveCleanup. Она проверяет trusted immutable review, existing protected control и actual same-gate context, удерживает borrowed original lifetime до known cleanup, оборачивает helper syscall через epoch.WithStart и Stop/verify/cleanup через cleanup.WithCurrent. Не создаёт Gate admission или control state. Plain/foreign/released/expired forward context отказываются; durable Stop отзывает forward; cleanup после cancellation сохраняет только исходный lease.

`RunCORECoordinator(originalOwnedCtx, actualGate, COREBinding)` — полный callable production entry с этой actual factory. Caller CORE/main получает original ExclusiveContext и trusted immutable Review из своего исходного execution; binding содержит exact Request/helper/control root/transaction ID. Review не может быть unconditional permission callback. CORE по-прежнему владеет original admission и main/sharedApp wiring. Старый standalone CLI до wiring сохраняет alwaysnil отказ, но coordinator path имеет concrete issuer и concrete CORE adapter. Нет ambient Gate, provider grant, ledger, scan fallback или adopted OSProcessController.

## Ownership и запуск

Linux owner открывает actual `/proc/self/ns/net`, читает actual parent birth через существующие components kernel readers, удерживает helper/program/config descriptors с SHA/incarnation и shared file review. Parent/child сохраняют исходный netns; setns/unshare, route/DNS/firewall changes отсутствуют. Валидация использует общий strict audited USQUE input ABI и exact native architecture hash. Stage/config принадлежат существующему front door; исходный аккаунт не меняется.

Один вызов Start расходуется до IO/callbacks. Saved/late/duplicate/reentrant begin, swallowed error/panic и попытка replay отклоняются. Start context ограничивается первоначальным Scope deadline. CORE WithStart удерживает исходную private operation/review/close capability через READY → PERMIT → actual child STARTED ACK; protected control lock не удерживается через readiness.

Parent helper `Cmd.Start` использует CORE WithEffectStart. Helper потребляет PERMIT ровно один раз и вызывает existing protected effect admission у фактического USQUE `Cmd.Start`. Передаются реальные inherited helper/config/binary/directory/netns/control-root/permanent-lock descriptors; root/lock marker/incarnation проверяются, cloned same-epoch files не принимаются. Медленные hash/review reads выполняются до короткого control admission; в actual start boundary остаются descriptor continuity и syscall. USQUE argv/env заморожены, executable запускается из held FD; IPC/control descriptors не наследуются USQUE.

После actual STARTED parent отдельно читает точный child birth/parent/group/argv/exe/netns. Только тогда вызывается настоящий `routeidentity.RecordStart` и создаются существующие `engine.pid` / `engine.pid.identity.json`; saved/adopted receipts не используются. Local readiness читает реальные паспорт/listener/underlay facts. Настоящий producer выполняет WARP trace через owned path; protocol остаётся source-bound inference, negotiated=false. Legacy scan, registration, fallback отсутствуют.

## Settlement

Только dedicated setsid helper включает existing subreaper primitive. Opening `Wait4(-1, WALL)` должен дать ECHILD. Этот же sole wait owner reaps direct child и adopted descendants; ограниченный proc scan используется только для сигналов собственным unreaped children, никогда для положительного quiescence. Terminal требует actual DirectReaped + ECHILD с тем же command/helper/child birth. Parent проверяет terminal, отправляет exact ACK и дожидается своего единственного actual helper `Cmd.Wait` с successful exit. Потеря helper/channel/ACK/join сохраняет unknown outcome и original fence.

Stop/join/verify/release используют тот же retained owner и concrete ExclusiveCleanupReview.WithCurrent с отдельным bounded cleanup context <=5s после request cancellation; forward authority этим не обновляется. Только после отдельного VerifySettled front door удаляет свой secret. Owner дополнительно требует фактическое отсутствие stage engine.json, удаляет только собственные exact-incarnation PID/passport metadata и закрывает held secret/program/control descriptors до CORE Release. Logs остаются приватными. Нет recursive cleanup, нового ledger, новых registrations или новых network effects.

Cancellation немедленно прерывает parent socket wait через deadline того же retained channel. Callback cancellation joined до reset deadline для cleanup; он не может испортить следующую bounded STOP/ACK phase. Новая permission при этом не выдаётся.

Borrowed original lifetime удерживает actual execution object вместе с private channel/asset descriptors при unknown результате. Возвращённый или отброшенный result DTO не даёт GC освободить этот owner до подтверждённого Release.

## QA / Root

Pure owner models проверяют actual-lease dependency, immutable launch, replay/retained begin/error/panic/reentrancy, closing authority mutation, bounded close vs Start, original cancellation + separate cleanup, exact terminal ECHILD/child binding и strict framed JSON. Linux-only filesystem models проверяют held asset replacement/rewrite, cloned original control root/lock и no-helper cleanup gate; они не запускают процессы/сеть и не сохраняют synthetic owned passport.

```sh
unset RAZVILKA_NATIVE_CLOUD_TRANSPORT RAZVILKA_NATIVE_CLOUD_OWNED_DIAL RAZVILKA_NATIVE_CLOUD_RETENTION
go test ./internal/usquediag/nativeowner ./internal/usquediag/nativeaccept ./cmd/usque-owned-native ./internal/usquediag \
  -run '^(TestOwner|TestRun|TestArguments|TestAssets|TestCommand|TestOwned(Native|Producer|Capture|SelectedEndpoint|Environment))' -count=1 -timeout=120s
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o usque-owned-supervisor ./cmd/usque-owned-supervisor
```

Root принимает source и затем отдельно выполняет existing-account H2 и QUIC через `RunCORECoordinator` с actual original ExclusiveContext/immutable review и digest конкретного helper build. До этого actual native kernel/helper/producer/settlement outcomes не заявляются и D13 не закрывается. Root Linux131 race front door и Linux138 race CORE gate не являются native PASS нового helper.
