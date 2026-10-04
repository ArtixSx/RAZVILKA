# CLOUD — fresh USQUE active/committed health

04.10.2026. Base: accepted integration `f1f731a5f1ba5ace1c3e9e66c2449ce6baf21a13`, содержащая `643ed62` и CLOUD `8ad2533`. Изменены только новые `proxy_usque_live_health.go`, собственные tests и этот handoff. Existing proxy/main/Manager/app files не менялись.

## Caller contract для VLESS / CORE

```go
receipt, err := adapter.probeOwnedUSQUELive(ctx, plan.RoutePlanFor("usque"), selectedTransport)
```

Private method принимает `RoutePlan`, `usqueTransport`, возвращает `usquediag.CanaryEvidence`. Его вызывает только explicit action/worker с действующей review operation authority, после owner `verifyHealthRuntime` / проверки forwarding и policy receipt. Это не GET callback, runtime factory, admission grant или scheduler.

- Для `Health(root)` caller передаёт exact staged transport, с которым был запущен actual runtime. Для `Reconcile` — exact committed selection. Отсутствующий/неверный selection означает отказ; fallback через `preferredUsqueTransport` не заменяет selection.
- `plan.NetworkProfileID` обязателен и должен быть valid WAN profile ID, равным actual `FreshProfile`, также для ordinary explicit USQUE service routes. Пустой/старый profile или nil callback отказывает. CORE обеспечивает эту привязку в actual reviewed plan/context.
- Caller сохраняет **весь возвращённый typed receipt** в существующем owner evidence path. Если receipt сохраняется для Commit, Commit должен переносить эту новую live запись, не перезаписывать её прежней Canary записью. Нового ledger / journal эта порция не добавляет.
- После restart / Activate / замены process binding требуется новый вызов. Наличие Canary receipt, TTL прежней записи или Running boolean не заменяет fresh producer.
- GET использует только существующий local observer для оценки текущего binding/TTL. Он не вызывает этот метод или `ProbeOwnedUSQUE`.

## Реализованная граница

Actual spec выводится из `engineProcessWithTransport`: ID `usque-engine`, current runtime root / `engine.json`, обычный SOCKS port, exact canonical argv / selected QUIC либо HTTP/2 endpoint. Canary alias не используется. Mandatory review guard и существующая address-refresh authority проверяются до current profile / runtime observation и снова вокруг единственного producer вызова. Stop/revocation/cancellation или WAN change не возвращают receipt.

Bounded private `ownedfs` config read и actual read-only `ObserveOwnedUSQUE` связывают snapshot с session/argv/environment hashes. Observer и producer проверяют actual launcher receipt / executable / process birth / listener / endpoint / network epoch. До и после producer требуется тот же полный runtime identity; returned proof обязан совпасть с ним. `CheckedAt` должен попасть внутрь **данного** producer вызова; unexpired historical receipt тоже отклоняется. Оригинальные `CheckedAt`, `ValidUntil`, transport, endpoint и whole Owned payload возвращаются без обновления/переписывания. Mutable route/catalog slices и returned grade slices отделены от callers/producer.

Service/override использует complete frozen catalog predicate и immutable logical service ID через принятый shared predicate compiler. DEFAULT требует sealed `FrozenLAN` и запрашивает только explicit owned WARP readiness, с нулём catalog services. Отсутствующий predicate/seal, foreign route, malformed selected endpoint/argv и unsupported scope отказывают. Общий window не более 30s; producer network timeout не более 20s. Вызов не делает Start/Stop, transport fallback, generic/legacy повторный probe, регистрацию account, запись файлов/маршрутов или изменение policy.

Same `ProbeOwnedUSQUE` сохраняет своё existing producer Origin / ProofBasis (`managed-usque-canary` / source-bound owned-path inference). Эти поля здесь не переименовываются: это свежая production producer запись для **actual active** runtime, а не продвижение historical Canary. Это не direct negotiated ALPN/QUIC attestation, LAN selected/control/egress, TUN forwarding, DNS или UDP proof. Challenge/UDP/broader grades отклоняются.

## Проверка

Go 1.26.5, GOTOOLCHAIN=local, GOMAXPROCS=2, GOFLAGS=-p=2, GOPROXY=off. Все три CLOUD native opt-in flags пусты.

- New `TestUSQUELiveHealth*`: PASS, 0.236s. Local files + private observer/producer doubles; реальные процессы, procfs, DNS, sockets и native USQUE не запускаются.
- Полный portable `go test -count=1 ./internal/dataplane` для исходного checkpoint `91ed14e`: RC 0, 150.508s, без skip.
- Fixtures: QUIC/HTTP2 exact active spec + whole receipt equality; unchanged existing evidence/config tree; mandatory/missing/revoked/canceled authority; Stop/WAN change; process birth/executable/config/argv/listener/profile replacement; missing endpoint/predicate/default seal; full status/content-type/JSON/body/truncation semantics; caller mutation; historical-within-TTL / expired / future / extended TTL; foreign/runtime/service / invented UDP/challenge; explicit default WARP-only.
- Windows `go vet ./internal/dataplane`: RC 0.
- Linux amd64 и arm64 `go build ./internal/dataplane`: оба RC 0, binaries здесь не исполнялись.

## Delta после независимого review `91ed14e`

VLESS выявил P2: callbacks могли revoke review authority, но вернуть matching profile / Running=true после последней проверки guard. Новые late FreshProfile/Running regressions воспроизвели ошибочный успешный receipt в исходном checkpoint. Authority теперь повторно проверяет mandatory guard после FreshProfile, перед Running, и после Running; helper также проверяет context до/после guard. Ранняя revocation не запускает следующее process/runtime observation; late revocation/cancellation после второго runtime observation возвращает пустой receipt. Даже matching/nil callback results не сохраняют authority.

Финальный целевой selector live health / owned bridge / Canary / predicate tests ×3: RC 0, 0.979s, включая early callback revocation и late FreshProfile/Running revoke/cancel-nil. Windows vet и Linux amd64/arm64 builds повторены для delta; native/live/caller acceptance не утверждается. Shared semantic deduplication разных LAN cells принадлежит VLESS, existing bridge здесь не менялся.

Actual caller insertion, current evidence retention/GET observer, CORE ordinary plan/admission binding и Root live acceptance остаются **UNVERIFIED**. Library/helper pass не закрывает D13. VLESS сохраняет ownership existing proxy lifecycle/caller files; CORE — main/Manager/app insertion.

## Read-only final identity leaf после VLESS kernel readback

Для исправления concrete closing-process P2 из `b5dbf56` добавлены private `verifyOwnedUSQUELiveIdentity(ctx, frozenSpec, socksAddress, originalOwnedProof) error` и `verifyOwnedUSQUELiveIdentityWith(..., identityObserver)`. Новый отдельный `usqueLiveHealthIO.identity` — только fixture seam; nil вызывает настоящий `usquediag.ObserveOwnedUSQUE`, обычный action observer не используется как fallback. Shared usquediag/VLESS lifecycle files не изменены.

Leaf выполняется **после** последнего caller kernel/admission/WAN callback и **до** callback-free anchored source/selection/TTL checks и записи. Он не вызывает review guard, FreshProfile, Running, producer или kernel runner. Environment callback замкнут на literal `originalOwnedProof.Identity.EnvironmentID`, ранее проверенный caller; он не выдаёт WAN/readiness authority. Caller по-прежнему обязан проверить current review/WAN/полную policy authority перед leaf. Единственные leaf observations — bounded local owned root/procfs/pin/executable/birth/args/config/listener/endpoint; весь полученный `OwnedRuntimeIdentity` должен совпасть с исходным. Иная birth, Stop, config/exe/args/socket/source/environment drift сохраняют отказ. Максимальное окно 5s с сохранением меньшего parent deadline; cancellation и original full proof/TTL проверяются до/после observation. Receipt/timestamps/files не меняются.

Portable `TestUSQUELive(Identity|Health)*`: RC0, 0.279s. Проверены оба транспорта, неизменность whole proof/TTL/files, отдельный identity seam без action callbacks, original identity replacement по всем полям, Stop/error, cancellation, malformed/expired/future/extended input до observer. Nil-default fixture без PID/passport отказывает через actual observer до process inspection; executable/process не создаётся. Windows dataplane vet и Linux amd64/arm64 CGO0 package builds — RC0; binaries не исполнялись. Consumer placement и закрытие обоих VLESS P2 требуют отдельного finished caller review/ROOT acceptance.
