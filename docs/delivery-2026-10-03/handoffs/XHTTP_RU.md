# D02 XHTTP — compiler/checker checkpoint

Дата: 04.10.2026. Worktree: `C:/Projects/RAZVILKA/worktrees/sol-xhttp`, ветка `sol/xhttp-20261004`.
Вход: `1f197d9f580648663557ec95d5b692a2fccb06a0`.
Код: **`b9372bc0cc06fa6d54fe99d02c37424f9ecf9f5c`**.

Статус первого compiler checkpoint: реализован и проверен unit/static подэтап точного XHTTP VLESS. **Native XHTTP не запускался этим чатом; transport не production validated. D02/D03 не закрыты.** Последующие native55 CA fix и NodeStore import/read compatibility checkpoint описаны ниже; scoped adapter и ROOT native/admission acceptance остаются открыты. VERSION/go.mod/go.sum, app/main, Manager/Plan, прочие node/proxy, VM/роутер/рабочая сеть и GitHub этим чатом не изменены. Новых scheduler/store/journal нет.

## Результат и API

- `VLESSProfile` получил отдельный `XHTTP` с проверенными `host/path/mode/extra`; compiler выдаёт **`network=xhttp` + `xhttpSettings`**, не RAW/TCP. Сохраняются SNI, endpoint, UUID, security, ALPN, fingerprint и все принятые extra. Вложенные карты копируются, исходник не может менять готовый профиль. RAW/TCP TLS/REALITY и Vision сохраняют прежний контракт.
- Новые `ParseCanonicalProfile(raw)` / `ParseCanonicalURI(raw)` возвращают приватный envelope только с `outbounds`, без DIRECT/selector/routing/listeners. `BundlePreview.EngineID=canonical` обозначает импортный envelope, **не runtime engine**. `Preview.EngineID=xray` у XHTTP записи — capability, не proof. Совместимые прежние материалы имеют ту же canonical identity после удаления tag.
- `ParseProfile`/`ParseURI` по-прежнему строят реальные Sing-box drafts и явно отвергают XHTTP. В смешанной подписке неподдерживаемая запись учитывается в Rejected; частичный импорт сохраняет прежний explicit-accept contract. `ParseXrayProfile` разбирает canonical envelope и компилирует один выбранный узел. Он принимает URI `type=xhttp/splithttp`, canonical node JSON и строго ограниченный Xray JSON outbound (`protocol=vless`, один vnext/user).
- Native Xray JSON `xhttpSettings` с параметрами на верхнем уровне нормализуется в `extra` с тем же эффективным поведением. При наличии `extra` одновременные top-level параметры отвергаются: upstream игнорирует их. `host/path/mode` внутри extra, неизвестные/case-alias поля, duplicate JSON/query keys и null вместо обязательных типов не теряются, а отвергаются. Clash/Mihomo XHTTP остаётся explicit unsupported: отдельного точного YAML schema importer здесь нет.
- `SingBoxSupportsOutbound(map)` — transport gate для уже проверенного canonical outbound; не полноценная валидация профиля. `ValidateXrayXHTTPSettings(map)` — экспортированный transport-only gate для scoped validator владельца VLESS. Security/flow и общий scope должны проверяться дополнительно.
- Existing exact checker/dispatcher и одна общая квота используются без второго executor. Sing-box отвергает XHTTP до DNS/квоты. Xray compiler rejection тоже предшествует DNS/квоте. Новый runtime gate читает `xray version` с пределом 3 s, требует **точно 26.3.27**, без version cache; другой version → ErrExactNodeUnsupported, ошибка producer → ErrExactNodeRuntime, нулевой NodeCheckResult/ProbeID, без reputation record. Повторная проверка version происходит перед записью pinned config. RAW/TCP version gate не менялся.
- Pure `compilePinnedXrayNodeConfig` выделен из прежней materialization: закрепляет успешный IP, сохраняет исходное TLS/HTTP имя и XHTTP host/path/extra. Identity/receipt/cleanup/net epoch/парный HTTPS egress/service name+literal IP остаются прежними.
- Xray service/IP proof теперь требует явный `Engine=xray` наряду с тремя точными route IDs. Чужой/пустой engine не авторизует XHTTP. Сохраняется исторический implicit empty engine только для Sing-box; явно чужой engine отвергается и там. Unit fixtures обновлены, production proof producer уже задаёт engine.
- Feed parsing использует canonical APIs и сохраняет XHTTP identity/path/extra в bounded materials. Unsupported XHTTP combinations не становятся кандидатами. **Запись XHTTP через live feed/NodeStore ещё fenced отсутствующим NodeStore контрактом ниже; полного import success этого чата не заявлено.**

## Ограниченный pinned schema

Поддерживаются TLS и REALITY, без flow, modes `auto/packet-up/stream-up/stream-one`; absent/empty mode сохраняет upstream default. HTTP/2 и packet-up через HTTP/1.1 допустимы. Stream-up/stream-one с единственным ALPN http/1.1 отвергаются. Все просьбы H3, REALITY с явным ALPN, XHTTP+Vision, packetaddr, multiplex/chaining и unmapped TLS constraints/pins отвергаются. Fingerprints ограничены проверенными preset именами: chrome/firefox/safari/ios/android/edge/360/qq/random/randomized. REALITY key — raw URL-base64 32 bytes, short ID — hex до 8 bytes.

Принятые extra: headers; xPaddingBytes/ObfsMode/Key/Header/Placement/Method; uplinkHTTPMethod; **sessionPlacement/sessionKey**; seqPlacement/seqKey; uplinkDataPlacement/Key/ChunkSize; noGRPCHeader/noSSEHeader; scMaxEachPostBytes/scMinPostsIntervalMs/scMaxBufferedPosts/scStreamUpServerSecs; serverMaxHeaderBytes; xmux (maxConcurrency/maxConnections/cMaxReuseTimes/hMaxRequestTimes/hMaxReusableSecs/hKeepAlivePeriod). Values/ranges/types/enums и конфликт xmux проверяются. Числовые ranges nonnegative int32, упорядочены; положительные размеры либо upstream zero default. hKeepAlivePeriod допускает sentinel -1. Headers запрещают Host, duplicate case variants, framing/connection fields и control characters; header values приватны и маскируются в display label.

**downloadSettings полностью отвергается**: это второй endpoint/transport/security за пределами одного current pin/manifest. Новые main поля sessionIDPlacement/sessionIDKey/sessionIDTable/sessionIDLength тоже unsupported для pinned 26.3.27. Ограничения не обходятся XHTTP→TCP.

Первичные источники, прочитанные через web:

- [Xray 26.3.27 SplitHTTPConfig/StreamConfig](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/transport_internet.go).
- [Pinned dialer: HTTP version, modes, Host priority, download endpoint](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/splithttp/dialer.go). В этой версии auto с TLS выбирает packet-up; auto с REALITY без downloadSettings — stream-one. Не перенесены defaults из moving main.
- [Pinned range schema](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/common.go), [TLS fingerprint producer](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/tls/tls.go).
- [Official XHTTP documentation](https://xtls.github.io/en/config/transports/xhttp.html), [upstream discussion](https://github.com/XTLS/Xray-core/discussions/4113).
- [Sing-box 1.14.2 transport decoder](https://github.com/SagerNet/sing-box/blob/v1.14.2/option/v2ray_transport.go) и [official transport documentation](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/): XHTTP не является принимаемым типом stock decoder.

## Обязательный handoff VLESS / CORE / OPS

Это исходный контракт b9372bc. NodeStore части пунктов 1, 2, 4 выполнены checkpoint 516f014 ниже; scoped adapter, CORE/OPS admission и ROOT acceptance остаются владельцам.

1. **NodeStore import/reopen:** после принятия compiler checkpoint заменить `providerprofile.ParseProfile` на `ParseCanonicalProfile` в `nodestore/store.go` (Import) и `nodestore/document.go` (persisted material revalidation). Extract продолжает удалять tag; один приватный Store/schema/journal остаётся прежним. Проверить импорт URI/JSON/feed, стабильную identity, reopen/backup/restore с XHTTP и сохранение всех extra. Этот чат эти owned VLESS файлы не редактировал.
2. **Sing-box materialization:** `nodestore/routes.go` обязан до выдачи `MaterializeSingBox` явно отвергать `!providerprofile.SingBoxSupportsOutbound(outbound)` с ErrRouteProof. Невозможность получить новый Sing-box checker PASS сама по себе не заменяет compiler/materializer gate для сохранённого/поданного вручную evidence.
3. **Scoped adapter:** root поручил связать новый compiler с `strictvalidateScopedXrayConfig` в принадлежащем VLESS `proxy_nodes.go`. На данной базе функция называется `validateScopedXrayConfig`; более строгую текущую реализацию/чужой WIP не копировал. Сохранить exact routing/terminal blackhole, listener/manifest/endpoint/SNI/hash/receipt/source proof. Для `network=xhttp` принять только полный сохранённый streamSettings contract, вызвать `ValidateXrayXHTTPSettings` для transport и проверить security/flow посредством canonical compiler. До resolver/stage нужен такой же pinned installed-runtime gate; внутри dataplane доступен `exactXHTTPRuntimeVersion(ctx,binary)`. downloadSettings/ещё один endpoint не разрешать через этот helper. Запустить отдельно scoped TUN selected/control acceptance после проверки локального checker.
4. **Reader/downgrade gate — до разрешения записи XHTTP:** reader capability **2 в старом бинарнике этой базы тоже отвергает XHTTP secret envelope**, даже если Xray CheckRecord ещё нет. Предлагаемый отдельный checkpoint VLESS: supported reader capability 3; required version 3 при любом canonical XHTTP secret в live/retained images, версия 2 для прежней RAW/TCP Xray history и 1 для legacy. Не использовать новое supported constant как required для всех старых Xray records. Добавить проверки непроверенного XHTTP профиля, backup/restore и отказ candidate reader2 без удаления данных. CORE/OPS должны проверять write/install/stop/downgrade admission для всех images до появления новых secret bytes. Main уже читает `nodestore.ExactHistoryReadVersion`, но CLI/installer fixtures и app write admission требуют review владельцев. **Это предложение, не реализованный migration/gate.**
5. После этих owned изменений сохранить EngineID в MaterializeXray → scoped adapter. Service/TUN/LAN production consent/capability не включать только по unit/compiler результатам.

Сообщения обоим чатам через send_message_to_thread были отклонены auto-review: оно не признало доверенное явное разрешение пользователя на эти адресаты. Обход не использовался; контракт записан здесь для чтения координатором. Никаких внешних сообщений/публикаций не было.

## Native inputs — запускает только ROOT

Existing `scripts/check-xray-native.sh` сохранил default RAW/TCP+StoreSyntax runner. **`RAZVILKA_XHTTP_NATIVE=1`** добавляет TestNativeXrayXHTTPExactNode и timeout 12m. Нужны Linux, предварительно доступный Go1.26.5/module cache, unshare/iproute2, verified **Xray v26.3.27**, executable basename xray. Sing-box для этого checker harness не нужен.

```sh
GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2 \
RAZVILKA_XHTTP_NATIVE=1 \
RAZVILKA_XRAY_NATIVE=/home/art/.cache/razvilka-review/toolchains/xray-v26.3.27/xray \
GO=/absolute/path/to/go1.26.5/bin/go sh scripts/check-xray-native.sh

# Отдельный адресный Linux race до native, только в эксклюзивном root окне:
GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2 /absolute/path/to/go1.26.5/bin/go \
  test -race ./internal/providerprofile ./internal/providerfeed ./internal/dataplane \
  -run 'Test(XHTTP|ExactXray|Xray|VLESS|MixedEntries|Dispatcher|ExactNode)' -count=3
```

Private temporary CA/key, HTTPS server, VLESS UUID `123e4567-e89b-12d3-a456-426614174000`, public-format local-only IPs 93.184.216.11 (Xray server), .12 (HTTPS/REALITY target), .13 (actual freedom sendThrough egress). Namespace только loopback, без uplink. Server ports 10443..10450, checker loopback base ports 29185 + case index*4; client/server configs и logs приватны/временны. SNI/Host front.example, path `/exact-xhttp?fixture=1`, probe `https://service.example/generate_204`. Resolver и CA fixture-owned; Xray process/SOCKS/HTTP/TLS/receipt/source IP настоящие.

Матрица: TLS и REALITY × auto/packet-up/stream-up/stream-one; packet-up проверяет extra padding/header/session+seq query/xmux и flags. TLS packet-up и REALITY stream-one дополнительно проходят real wrong path/TLS name/mode/RAW transport → protocol/egress rejection, correct material recovery, server stop/restart, wrong UUID, actual client kill/Recover. Положительный baseline и повтор правильного материала отделяют негативный результат от сломанного стенда. No fake process/SOCKS/proof. Доказательство ограничено local HTTPS service name/IP и distinct actual egress; **не Интернет/TUN/LAN/app restart/router/rollback/HIL**.

## Файлы

- `internal/providerprofile/{xhttp.go,xhttp_import.go,xhttp_test.go}` новые; `profile.go`, `entries.go`, `uri.go`, `validation.go`, `xray.go`, `vless_exact_test.go` расширены.
- `internal/providerfeed/parse.go`, новый `xhttp_parse_test.go`.
- `internal/dataplane/nodecheck{,_dispatcher,_test,_xray,_xray_test,_xray_native_linux_test}.go`, новые `nodecheck_xhttp.go` / `nodecheck_xhttp_test.go`.
- `scripts/check-xray-native.sh`; этот handoff отдельным documentation commit.

## Фактические проверки

Windows/amd64, `C:/Projects/RAZVILKA/tools/go/bin/go.exe`, Go1.26.5, GOTOOLCHAIN=local, GOMAXPROCS=2, GOFLAGS=-p=2. Dependencies/VERSION неизменны.

| Команда | RC / доказанная граница |
|---|---|
| `go test ./internal/providerprofile ./internal/providerfeed ./internal/nodestore ./internal/dataplane -count=1` | **0**, финальный полный Windows повтор после runtime gate; dataplane 105.828s |
| `go test ./internal/providerprofile ./internal/providerfeed ./internal/dataplane -run 'Test(XHTTP\|ExactXray\|Xray\|VLESS\|MixedEntries\|Dispatcher\|ExactNode)' -count=3` | **0**, финальный адресный повтор |
| `go vet ./internal/providerprofile ./internal/providerfeed ./internal/dataplane` | **0**, Windows |
| `go build ./...` | **0**, Windows production build |
| `GOOS=linux GOARCH=amd64 go test -c -o <private temporary file> ./internal/dataplane` | **0**, включая native XHTTP harness, только compilation; binary удалён |
| `GOOS=linux GOARCH=amd64 go vet ./internal/providerprofile ./internal/providerfeed ./internal/dataplane` | **0**, static only |
| `C:/Program Files/Git/bin/sh.exe -n scripts/check-xray-native.sh` | **0**, syntax only |
| `git diff --check` / staged diff check | **0** |

Первый sandbox прогон завершился RC1: Windows owned atomic rename Access denied; dataplane дошёл до standard 10-minute test timeout. Контроль **неизменённого** TestFileTargetReadOnlyAndExactCAS в restorejournal тоже падал внутри sandbox и прошёл RC0 при auto-approved обычном запуске вне него. MSYS syntax process аналогично имел NtCreateDirectoryObject access denial; разрешённый повтор -n прошёл RC0. Это ограничения sandbox, production ownership/permissions/cleanup не ослаблялись. В исправленных промежуточных прогонах также найдены/устранены XHTTP YAML nil mapping, missing engine unit fixtures и неверная keys-json fixture shape. Все финальные команды в таблице прошли после исправлений.

Runtime version producers/checker probes в новых Windows unit tests — явные fixtures. Linux runtime/race, XHTTP native server/client, full integration gate, scoped TUN и аппаратная проверка **не выполнялись**. ROOT должен сохранить реальные logs/RC и проверить semantic oracle, не повышая compilation/SKIP до native PASS.

## Native55: CA isolation checkpoint (после принятия ROOT 86c29d1)

ROOT передал read-only evidence `delivery-review/.review-local/xhttp-native55.log`: **RC1**. RAW TLS/REALITY и StoreConfigSyntax прошли; все 8 XHTTP случаев прошли protocol/paired egress (actual `.13`), затем получили service request-failed, HTTPStatus 0; TLS listener записал `remote error: tls: bad certificate`. Native PASS XHTTP отсутствует.

Исправление harness: **`c2436eb8532a9a4ef898381089a94262e0d8c951`**, только `internal/dataplane/nodecheck_xray_native_linux_test.go`. Каждый top-level RAW/XHTTP matrix reexec-ится в отдельном Go test child **в той же isolated network namespace**. Причина: каждый matrix генерирует отдельную CA, но локальный Go1.26.5 `crypto/x509/root.go` вызывает `once.Do(initSystemRoots)`; последующий SSL_CERT_FILE не обновляет cache для штатного service TLS probe. Egress getter уже имел explicit fixture roots, поэтому egress проходил. Child получает env marker с exact test name, единственный test.run, count1 и bounded parent deadline; все прежние server/client, real service, egress/source/receipt/cleanup/mismatch/lifecycle criteria сохранены. Production code, TLS verification и confidence oracle не изменены. Причина затем подтверждена ROOT native57 ниже.

Проверки здесь: Linux amd64 dataplane test compilation **RC0**, Linux dataplane vet **RC0**, diff check **RC0**. **Actual native/race этим чатом не запускались. ROOT принял fix и повторил тот же `RAZVILKA_XHTTP_NATIVE=1 ... sh scripts/check-xray-native.sh`: native57 RC0.** Исправление принято отдельно от NodeStore checkpoint.

### Reader3 integration: CORE/OPS contract

Согласованный scope ROOT передал XHTTP владельцу NodeStore `store.go`, `document.go`, history compatibility и `routes.go` плюс узкие tests. Работа начата от обычного fast-forward accepted base **86c29d116f6e7978a95217423208fa9b0f11ca10**; native55 diagnosis имела приоритет. NodeStore changes зафиксированы отдельным checkpoint **516f01450e4faf3bcfe4ee355b55ca91fd2ec18e**: canonical import/reopen, Sing-box transport gate и supported reader3 / required3 только XHTTP secrets, RAW Xray history2, legacy1. Native CA fix можно принять отдельно, до reader3 consumers.

CORE/OPS до принятия reader3 должны устранить hard-coded reader2 в своих owned consumers: `internal/updatecheck/node_history_admission.go` (CheckReadable, CheckWrite bounds, checked binary version bounds, probe accepts only strings1/2), `internal/updatecheck/node_history.go` (typed reader верхняя граница сейчас ошибочно связана с **SelfUpdateReadVersion=2** — node read capability отделить, **не менять self-update schema2**), `internal/updatecheck/file_adapter.go` (`-node-history-read-version` expects2), `cmd/razvilka/node_check_engines_test.go` (CLI expects2) и соответствующие fixtures. Main печатает typed `nodestore.ExactHistoryReadVersion` и app передаёт constant в Xray write guard: после bump это3, старый OPS guard иначе fail-closed отвергнет все Xray writes. Это не NodeStore-owned изменения; здесь они не редактировались. Дополнительно admission должен покрывать XHTTP secret write **до первого check**, включая обычный import/feed/restore, и проверять live + every retained backup/journal/controller image before stop/install/downgrade. Candidate reader2 обязан отвергаться без удаления данных. ROOT координирует это с CORE/OPS; отправку сообщений после auto-review rejection не повторял.

## NodeStore XHTTP checkpoints 516f014 + b0d27a9 — завершённый подэтап

**Код: `516f01450e4faf3bcfe4ee355b55ca91fd2ec18e`**. `Store.Import` и persisted `validate` используют `ParseCanonicalProfile`, extract/identity/private schema4/lease/CAS/restore journal/health history остаются прежними. XHTTP имеет canonical identity, не Sing-box executable draft. `MaterializeSingBox` возвращает ErrRouteProof и нулевой RouteMaterial для XHTTP даже при вручную сохранённом current Sing-box PASS; отказ не записывает history. `MaterializeXray` сохраняет exact streamSettings host/path/mode/extra/TLS/REALITY, endpoint set, node tag, destination domains/IPs и default/terminal blackhole только при matching Xray proof.

**Дополнительный code checkpoint: `b0d27a9e01dc5970555a825f1a68b4cb8a0c1e0e`**, только `routes.go` и его XHTTP regression. По finding VLESS и поручению ROOT `collectPrivateEndpointHosts` больше не обходит вложенные keys `server/address/endpoint`: единственный DNS/exclusion endpoint — validated top-level canonical `outbound.server`. Accepted XHTTP private headers `Address`, `SERVER`, `Endpoint` сохраняются в compiled config и никогда не становятся EndpointHosts; SNI/HTTP host тоже не приобретают endpoint authority. Проверено полным materializer test с matching Xray proof и private header tokens. `SourceUtility` уже читает только top-level canonical server; не менялся. VLESS scoped consumer отдельно выводит actual remote endpoint из `settings.vnext[0].address`; его файлы не редактировались.

`ExactHistoryReadVersion=3` обозначает supported reader, не required для любых Xray записей. Required inspection сначала проверяет **все validated private secrets** (включая unchecked/disabled/expired XHTTP), и возвращает frozen XHTTP capability3; иначе frozen RAW Xray history capability2; иначе1. Required inspection read-only, не возвращает IDs/credentials, не зависит от latest health, origin expiry или наличия PASS. `RequiredPrivateHistoryReadVersion` применяет тот же typed validator к backup/retained image: live XHTTP deletion не убирает требование3 у retained backup; restore снова восстанавливает live3. Schema number4, binary VERSION и RAW/TCP exact contract не повышались/не ослаблялись.

Файлы checkpoint: `internal/nodestore/{store.go,document.go,routes.go,history_compatibility.go,history_compatibility_test.go}`, новые `exact_history_xhttp_test.go` / `xhttp_store_test.go`, узкая end-to-end feed regression в existing `internal/providerfeed/xhttp_parse_test.go`. D10 логика/group/store mutation алгоритмы не менялись. VLESS `proxy_nodes.go` не редактировался.

Новые регрессии: TLS+REALITY URI/canonical feed envelope/native Xray JSON dedup одной identity; все принятые extra byte-exact при reopen/export/private journal restore/reopen; public DTO privacy; mode matrix auto/packet-up/stream-up/stream-one; untested/no matching engine proof и expired proof отвергаются; невозможный Sing-box PASS не обходит transport capability; unsupported import сохраняет existing bytes, mixed import требует explicit accept; persisted unsupported secondary endpoint при согласованной HMAC identity отвергается без repair/deletion; live+retained unchecked/failed/disabled/expired secret требует3, RAW history и old retained RAW backup остаются2, legacy/empty1; actual feed Sync импортирует только quarantined/untrusted/not_checked material с read3 fence.

Финальные проверки после всех code changes, Go1.26.5, GOTOOLCHAIN=local, GOMAXPROCS=2, GOFLAGS=-p=2:

| Команда | RC |
|---|---|
| Windows `go test ./internal/nodestore ./internal/providerprofile ./internal/providerfeed -count=1` | **0**; финально после endpoint fix 7.157s / 0.598s / 6.298s |
| Windows `go test ./internal/nodestore ./internal/providerfeed -run 'Test(XHTTP\|RequiredHistoryReadVersion\|XrayEvidence\|EngineFailure\|EngineRoute\|XrayProof)' -count=3` | **0**; финально после endpoint fix 4.531s / 0.764s |
| Windows `go vet ./internal/nodestore ./internal/providerprofile ./internal/providerfeed` | **0** |
| Windows `go build ./...` | **0** |
| Linux amd64 `go vet ./internal/nodestore ./internal/providerprofile ./internal/providerfeed` | **0**, static only |
| Linux amd64 `go test -c -o <own temporary output> ./internal/nodestore` | **0**, compilation only |
| Linux amd64 `go test -c -o <own temporary output> ./internal/dataplane` / `go vet ./internal/dataplane` | **0**, final native CA harness compiled/checked |
| `git diff --check` / staged check | **0** |

Windows filesystem-writing tests запускались auto-approved вне sandbox из-за ранее доказанного запрета atomic rename; production permissions не ослаблялись. Собственные temporary Linux binaries удалены после проверки абсолютного target внутри assigned worktree. Linux runtime/race, scoped TUN/LAN/HIL, CORE/OPS candidate2 actual admission/downgrade tests **этим чатом** не выполнялись. Перед разрешением production writes нужен совместный CORE/OPS checkpoint выше; данный NodeStore API результат сам по себе не заявляет completed admission gate или D02/D03 acceptance.

## ROOT native57 — полученное actual evidence

ROOT сообщил **RC0**, source **`ea69cb91375c1fa7db4de933f7a377b512f83c56`** (включает c2436eb). Read-only просмотрен `C:/Projects/RAZVILKA/delivery-review/.review-local/xhttp-native57.log`: оба RAW/TCP security cases PASS, все **8 XHTTP TLS/REALITY × auto/packet-up/stream-up/stream-one PASS**, StoreConfigSyntax PASS. XHTTP matrix 49.63s; реальный fixture наблюдал **direct36/proxy46/service30**. TLS packet-up и REALITY stream-one также подтвердили actual wrong path/TLS name/mode/RAW transport rejection, правильный material recovery, stopped/restarted server, wrong UUID и killed/recovered owned client. TLS verification не отключалась; fake server/process/SOCKS/proof не добавлялись.

Это подтверждает локальный exact XHTTP checker/harness и CA cache diagnosis; **не является TUN/LAN/Internet/router/HIL/restart/rollback production evidence**. Native57 не включает новые NodeStore reader3/endpoint checkpoints: их Linux native integration/admission повтор ROOT выполняет после объединения owned VLESS/CORE/OPS потребителей. Чат XHTTP самостоятельно native/VM/network не запускал и root evidence не изменял.
