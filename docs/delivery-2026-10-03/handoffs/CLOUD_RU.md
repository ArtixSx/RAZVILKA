# CLOUD — D13, библиотечный checkpoint 04.10.2026

Worktree: `C:/Projects/RAZVILKA/worktrees/sol-cloud`, ветка `sol/cloud-20261004`.
Base: `fe7d0ab9baaec1151c92593f308e080274903a93`.
Этот отчёт включён в коммит checkpoint; его SHA возвращается координатору в итоговом ответе.

## Аудит

1. Native enrollment уже использует единый `nativeenrollment` image, lease и pending до POST. Сохранённые response/key позволяют восстановить тот же аккаунт; pending без response блокирует новый POST после restart, в том числе `fresh=true`. Новый provider или журнал не понадобился.
2. Legacy `wgcf register` имел до трёх попыток после timeout/reset/EOF, без durable remote-outcome receipt. При fresh мог сначала убрать прежний account. Этот путь нельзя считать безопасным при unknown.
3. `CheckConnectivity` называл успешный обычный TCP socket `masque_http2.ready=true`. Протокол HTTP/2 и тем более HTTP/3/UDP таким тестом не устанавливаются.
4. USQUE doctor выдавал PASS сохранённым `warp=on` и service names без TTL, привязки к endpoint, файлам или WAN/DNS/boot epoch. При HTTP2_ENABLE=1 маршрут мог проверяться до QUIC endpoint вместо H2 endpoint. Ответ `ip` без interface тоже становился PASS.
5. Source cache уже атомарно сохраняет normalized content + receipt, проверяет hash/pin/config/TTL, сохраняет предыдущую копию после ошибки и запрещает stale enrichment новых планов. Но persisted final mirror origin не проверялся по allowlist; List отдавал вложенные metadata pointers менеджера. Отдельного read-only offline view не было.

## Изменённые файлы и результат

- `internal/warp/warp.go`: legacy wgcf теперь только `generate` из существующего account. Новая регистрация — через существующий native checkpoint. Без native generator fresh/missing account возвращает `ErrNativeGeneratorRequired` до удаления account или запуска команды. Удалены legacy retry loop и классификатор, ошибочно разрешавший повтор неизвестного POST. stdout/stderr генератора отбрасываются, version readback допускает только числовую версию известного формата.
- `internal/warp/health.go`: free-form activation errors больше не пишутся и не возвращаются. Новый фиксированный код `candidate-activation-failed`; старые сохранённые строки редактируются в readback без скрытой записи файла.
- `internal/warp/warp_test.go`, `d13_regression_test.go`: regression запрета legacy mint после restart/сохранения account, TCP != H2/H3/UDP, redaction нового/старого health state и настоящего subprocess output. Удалён тест старого retry classifier, обновлено ожидание публичной ошибки activation.
- `internal/usquediag/capabilities.go`: библиотечный binding и evaluator диагностики H2/H3/UDP. Максимальный срок receipt — 5 минут; future/expired/long TTL, другой endpoint/transport/files/network epoch дают unknown. H2 подтверждает только H2; native QUIC подтверждает H3/UDP и оставляет H2 unknown. Receipt не даёт права Apply/enrollment.
- `internal/usquediag/usquediag.go`: doctor использует evaluator; legacy canary остаётся историей, PASS больше не получает. Для проверки маршрута берётся endpoint выбранного транспорта, без подстановки endpoint другого транспорта. Пустой interface в ответе ip даёт warning. Публичный session readback допускает только canonical public literal IP соответствующей семьи; transport/binding/endpoint/expiry receipt фильтруются.
- `internal/usquediag/capabilities_test.go`, `d13_regression_test.go`: сроки, exact endpoint/transport, изменение environment во время чтения, смена binary, отсутствие секретов, отдельные capabilities и выбор H2 endpoint.
- `internal/sources/cache.go`: final origin проверяется при refresh и restart по исходному host или явно разрешённому mirror. Signed redirect query/path по-прежнему не сохраняются.
- `internal/sources/sources.go`: detached nested metadata в List; новый `OfflineCatalog() []State`, без fetch/write/upgrade. `offline=true`, `ready=false`; свежая сохранённая копия помечается offline-cache/LKG, stale/quarantine/legacy сохраняют свои ярлыки.
- `internal/sources/cache_test.go`, `d13_regression_test.go`: approved mirror survives restart, неподтверждённый origin не становится usable и не заменяет LKG; offline view не меняет receipt/manager, не обращается к HTTP и не превращает stale в fresh.
- Этот `handoffs/CLOUD_RU.md`.

`internal/cloudflareprovider/**` не изменялся; его полный адресный unit-набор проверен как зависимость. App/config/dataplane/UI/scripts, VERSION, go.mod и go.sum не изменены.

## Проверка — фактические RC

Все команды выполнены в указанном worktree с Go 1.26.5:

```powershell
$env:GOTOOLCHAIN='local'
$env:GOMAXPROCS='2'
$env:GOFLAGS='-p=2'
& C:/Projects/RAZVILKA/tools/go/bin/go.exe test -count=1 ./internal/warp ./internal/usquediag ./internal/sources ./internal/cloudflareprovider
& C:/Projects/RAZVILKA/tools/go/bin/go.exe vet ./internal/warp ./internal/usquediag ./internal/sources ./internal/cloudflareprovider
git diff --check
```

Все три — **RC 0**. Финальный четырёхпакетный test: warp 4.489s, usquediag 0.655s, sources 0.808s, cloudflareprovider 8.212s. После добавления двух test-only регрессий: `test -count=1 ./internal/usquediag ./internal/sources` — RC 0 (0.601s/0.785s), соответствующий vet и diff check — RC 0.

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
& C:/Projects/RAZVILKA/tools/go/bin/go.exe build ./internal/warp ./internal/usquediag ./internal/sources ./internal/cloudflareprovider
$env:GOARCH='arm64'
& C:/Projects/RAZVILKA/tools/go/bin/go.exe build ./internal/warp ./internal/usquediag ./internal/sources ./internal/cloudflareprovider
```

Обе сборки библиотек — **RC 0**. Это не исполнение Linux/native/ARM64 тестов и не сборка/приёмка всей панели.

Native enrollment существующие regression tests исполнялись вместе с warp: pending без response после restart не повторяет POST, response+key восстанавливают исходный enrollment, interrupted staging повторно использует тот же аккаунт, native restore сохраняет pending. Это checkpoint/fault unit fixtures с API double, не настоящая регистрация и не физическое отключение питания.

## Минимальный контракт CORE / VLESS / NET

### WARP

Публичные `Generate`, `GenerateAutomatic`, Status и private backup остаются на существующем пути; второй provider не нужен. Новая ошибка `warp.ErrNativeGeneratorRequired` означает, что неподтверждённый legacy enrollment отправлять запрещено. В обычном `warp.New` built-in generator уже включён. Переиспользование прежнего wgcf account без fresh работает через его export; migration/lease не заменены.

`ConnectivityCheck` сохраняет прежние поля и добавляет `masque_tcp`, `masque_http3`, `udp_capability`, `checked_at`. `masque_http2.ready` теперь false: CheckConnectivity не выполняет HTTP/2 native canary. `registration.ready` — HTTPS доступность API, а не факт создания account; общий `ok` — доступность хотя бы одного диагностического endpoint, не готовность туннеля. CORE не должен использовать `masque_tcp` как разрешение ротации, UDP Apply или успешную H2 проверку. Действующий recovery использует `registration.ready`; его смысл не изменён.

### USQUE

Новые API:

```go
// Конфигурация callback только при создании Manager; функция безопасна при
// параллельных запросах, берёт текущий epoch из доверенного состояния CORE.
Manager.EvidenceEnvironment func(context.Context) (string, error)
CanaryBinding(configSHA, sessionSHA, binarySHA, environmentID string) string
EvaluateCanaryCapabilities(receipt CanaryEvidence, endpoints Endpoints, binding string, now time.Time) TransportCapabilities
const MaxCanaryAge = 5 * time.Minute
```

`environmentID` — lowercase SHA-256 доверенной текущей identity, учитывающей boot, WAN, DNS и revision/route epoch. Callback memory/local-only, не начинает сетевую проверку. Missing/error/смена identity между началом и проверкой receipt оставляет unknown. Не брать epoch/binding из UI или самого receipt, не изменять Manager field параллельно с Check.

Действующий producer `internal/dataplane/proxy.go` принадлежит VLESS и в этой порции **не изменён**. Поля existing reader для exact installed-session canary:

- `checked_at` и `valid_until` в RFC3339, `checked_at <= now < valid_until <= checked_at + MaxCanaryAge`;
- `transport`: ровно `HTTP/2` или `QUIC`, фактически проверенный native transport;
- `endpoint`: exact pinned canonical AddrPort с портом 443; H2 только из endpoint_h2_v4/v6, QUIC только из endpoint_v4/v6;
- `binding_id = CanaryBinding(SHA256 текущих usque.conf, session.conf, exact executable bytes, текущий environmentID)` — это installed legacy пара, не временный managed engine.json;
- прежние warp/service facts только из native canary, без raw output/keys/token/device ID.

Экспортируемые capabilities содержат `http2/http3/udp` = `unknown|confirmed`, `fresh`, фиксированный `reason_code`. Они диагностические, не заменяют dataplane ownership/pin/CAS/revalidation/service proof. Producer обязан связать receipt с теми же bytes и epoch, реально использованными кандидатом; receipt от иной временной конфигурации нельзя переподписать под текущую. Managed producer использует transformed engine.json/CLI и требует согласованного typed runtime binding + current reader callback; одного добавления полей выше недостаточно. Точные existing identity/env поля и отсутствующие binary/peer/negotiated proof описаны в [USQUE producer contract](CLOUD_USQUE_PRODUCER_CONTRACT_RU.md). До этого wiring **вся legacy evidence unknown**. Exact kernel pin tuple, изменение WAN/DNS перед Apply и изоляция actual runtime остаются CORE/NET/VLESS и требуют отдельной приёмки.

### Источники / offline

`Sources.OfflineCatalog()` — новый memory-only read API; не вызывать Refresh/RefreshEnabled при входе, GET или fallback на offline. View показывает сохранённые Entries/SHA/provenance/expiry/settings; не даёт разрешения новой route mutation. `Sources.List()` тоже memory-only и теперь отдаёт detached metadata. Existing AutomaticUseReady/EntriesForService по-прежнему проверяют actual receipt и TTL; активную применённую политику эти функции не удаляют.

## Контракт UI

Показать TCP/443 отдельно от неизвестных HTTP/2, HTTP/3, UDP. `registration.ready` подписывать доступностью API; registered account брать из Status. `canary_evidence` без fresh capability — история с датой, не зелёный текущий статус. `offline=true`/offline-cache/stale/legacy/quarantined не представлять fresh; Entries и applied scope можно сохранять в read-only каталоге. Публичный activation error теперь фиксированный код, подробный process output возвращать нельзя.

## Ограничения и следующая приёмка

D13 **не закрыт**. Нет настоящей регистрации, HTTP/2/HTTP/3/WireGuard native canary, VM/router mutation, HIL, full Linux/race gate или физического crash/power-cut. Library tests не выдают production readiness. Новый callback и receipt fields ещё не подключены через CORE/VLESS; UI ещё не читает новые поля. Существующие POST diagnostics и source refresh authorization не менялись; login/GET не получили сетевых прав.

Координатору: принять diff/commit, запустить адресные пакеты на Linux, согласовать receipt writer + current environment callback и UI поля. После wiring проверить настоящий native H2 success при недоступном UDP, QUIC success, смену endpoint/WAN/DNS/boot, stale receipt, повтор unknown enrollment и сохранение активного LKG. Живую регистрацию проводить только в отдельном явно разрешённом owner-managed окне; эта порция её не требует и live harness не запускает.

NETWORK_POLICY_EXECUTOR_REQUIRED сохранён; auth/CSRF/TLS/Stop/CAS/ownership/recovery fence/LKG не отключены. Mihomo/HEV не получили production статус. Общие TASKS/VALIDATION и ownership docs остаются у координатора.

Уточнение OPS о mutable self-update restore: [retention contract для CORE/OPS](CLOUD_RETENTION_CONTRACT_RU.md) обновлён после review. Сохраняется действующий root/reader без новой namespace/capability; перечислены точные manifest exclusions и реализован узкий guard preexisting local facts в NativeRestore. Copy-only import rollback остаётся совместимым.

## Следующая библиотечная порция после c44ffee

Base: `c44ffeec4289534d6cb197e7a821aaa920bc8355`. Изменены только принадлежащие CLOUD библиотеки, собственный `test-cloud-*` script и handoffs:

- `internal/warp/native_enrollment.go`, `native_restore_guard_test.go`: live NativeRestore фиксирует initial document под прежним mutex/lease. CAS не может удалить/заменить initial enrollment facts, но позволяет exact rollback новых copy-only imported bytes. Raw Target/Save больше не экспортированы; прежний method contract для privaterestore сохранён. Offline startup journal protocol не меняется.
- `internal/usquediag/transport_probe.go`, `transport_probe_test.go`, `transport_native_test.go`: отдельный trusted opt-in native H2/H3 probe с literal endpoint, TLS verification, challenge, environment/expiry и resource cleanup. Не имеет enrollment capability и не выдаёт WARP proof.
- `scripts/test-cloud-transport.sh`: собственный opt-in localhost harness, без регистрации/VM/router mutation. [API, команды, ограничения и фактические проверки](CLOUD_TRANSPORT_HARNESS_RU.md).
- `CLOUD_RETENTION_CONTRACT_RU.md`: вместо несогласованного нового root перечислены exact exclusions на **действующем** root, включая canonical lease, health accounting, legacy account и native/feeds private-restore generations. Broad запрет copy-only rollback заменён baseline guard.

Адресный `test -count=1` warp/usquediag/privaterestore, выбранные app private/native backup restore regressions и vet — RC 0. Linux amd64/arm64 libraries и native fixture binaries cross-compile — RC 0. Default harness test — SKIP; launcher без opt-in — ожидаемый RC 2; shell syntax/diff checks — RC 0. Native opt-in, installer manifests/full Linux/race/HIL, настоящий WARP/USQUE не запускались. CORE/OPS/app/nativeenrollment/privaterestore, schema/layout/CLI paths, VERSION/go.mod/go.sum не изменены. Следующий шаг координатора — localhost native harness и OPS mutable-retention integration review, отдельно от реального WARP.

## Retention checkpoint после принятого 4d15788

Base: `4d157889d80185e9cb56091b7dfb624333d2b072`. Координатор сообщил independent Windows и Linux source28/cloud-native-02 localhost H2/H3 actual RC0, все семь subcases и race warp/usquediag/privaterestore PASS для прежней порции. Это не actual WARP/MASQUE и не retention acceptance.

Новая порция — только own fixture/runner и handoffs:

- `internal/warp/native_retention_test.go` + `scripts/test-cloud-retention.sh`: три opt-in сценария на production enrollment checkpoints, subprocess crash, реальном selfupdatejournal file lifecycle, production snapshot/prune functions и полном fixed shell rollback reader. Timeout accounting, original response/key, exact retained tree+lease inode, mutable LKG и absence старых snapshot root images проверяются без сети/daemon/router.
- [Retention contract](CLOUD_RETENTION_CONTRACT_RU.md): exact OPS exclusions на существующем root, включая конкретное basename-hash имя canonical lease. Generic mutable API отсутствует в проверенных refs; whole-root test доказывает существующий unsupported-key reader/file allowlist, не новый overlap protocol.
- [Retention harness](CLOUD_RETENTION_HARNESS_RU.md): root команды и честные границы. Fixtures schema/recovery CLI инертны; independent pending self-update receipt не выдаётся за live acceptance или полноценный CORE startup recovery.
- [USQUE producer contract](CLOUD_USQUE_PRODUCER_CONTRACT_RU.md): existing ProcessSpec/routeidentity/WAN поля, exact installed-session vs temporary candidate semantics, missing actual executable digest/connected peer/negotiated MASQUE proof. Никакого producer/CORE wiring этим чатом не добавлено.

Windows Go1.26.5 unit warp/usquediag/privaterestore RC0, vet own packages RC0, Linux amd64/arm64 retention test binary cross-compile RC0. Runner syntax RC0, выключенный runner actual RC2, default exact test SKIP. Новый native retention actual run **unverified** — координатор открывает это окно после review. Новый root/capability/migration не вводились; production OPS/CORE/VLESS/NET code, VERSION/go.mod/go.sum не менялись.

## Retention admission и функциональный USQUE checkpoint

Координатор сообщил принятие `f860c3df100d672b173904a726aeb3a198e3176d` в integration `d010e13` / source31: actual Linux `TestNativeLocalCloudRetentionHarness`, три первоначальных subcases — RC0, `.review-local/native-integration-12.log`. Это filesystem/process/shell/API-double harness, без регистрации или настоящего Cloud tunnel. Этот результат относится к исходной fixture до последующего OPS admission изменения.

Отдельный commit `4fd37fbabea76909a5313faa92a9ba7b7d2fd250` адаптировал только собственную retention fixture и её handoff к OPS `-check-node-history-state`: exact пять args, trusted roots и typed `{"ok":true}`. Добавлены несовместимый/unsupported gate случаи полного rollback shell до Stop. Windows unit warp и vet — RC0; native opt-in не запускался, при отсутствии новой production OPS функции соответствующий subcase SKIP. Combined OPS/CORE rerun этого commit остаётся за координатором.

Новая production часть находится полностью в CLOUD-owned `internal/usquediag`:

- `owned_runtime.go`, `owned_runtime_observe.go`: explicit `ProbeOwnedUSQUE` уже запущенного owned SOCKS runtime, три перечитывания Authority, before/after identity и отдельный local-only `ObserveOwnedUSQUE`. Runtime привязан к launcher receipt, exact argv/session, actual `/proc/PID/exe` SHA/inode, текущему FreshProfile epoch и owned FD/socket. Case aliases, duplicate top-level JSON keys и неоднозначный underlay отвергаются. Поддерживается exact official Linux USQUE4.2.1 для amd64/arm64/mips/mipsle; release `vcs.modified=true` явно ограничивает source provenance.
- `owned_probe_network.go`: настоящий verified-TLS WARP trace через exact owned loopback SOCKS, до восьми approved service probes и optional независимый UDP ASSOCIATE nonce echo. Nonchallenge service означает reachability; challenge требует точного свежего nonce. Нет registration/retry/fallback/redirect/proxy. Сеть ограничена default8/max20s, всё действие30s.
- `owned_runtime_test.go`, `owned_probe_network_test.go`: portable fake-proc/network/parser fixtures проверяют admission revocation, identity/config/args/env/exe/FD drift, inode ownership, endian, strict JSON, transport/UDP разделение, stale/current mismatch, TTL expiry во время readback и cancellation. Production observer, sockets и реальные процессы этими fixtures не вызываются.
- `usquediag.go`: typed `owned_runtime` в existing canary receipt, `owned_runtime_evidence` / `owned_runtime_fresh` в doctor и local-only `EvidenceRuntime` callback. Clock перечитывается после capture. Freshness связывает trusted producer-owned сохранённые факты с live runtime; digest не является подписью proof fields и не выдаёт import/UI/receipt apply authority.

`ProofBasis=official-release-owned-path-inference`, `ProtocolPath=HTTP/2|QUIC`, `Negotiated=false`. H2 established TCP peer наблюдается; QUIC unconnected socket peer остаётся explicit config inference. Actual WARP/service/UDP результаты разделены с native ALPN/RemoteAddr и TUN capability. Legacy H2/H3/UDP `transport_capabilities` от нового receipt не становятся confirmed. После Stop/restart/WAN/session/executable/socket drift current-green пропадает; другой activated process требует собственного action.

[Buildable API, exact release hashes и owner bridge](CLOUD_USQUE_BRIDGE_RU.md) задаёт точную предлагаемую границу: VLESS-owned новый `internal/dataplane/usque_owned_bridge.go`, вызов после Start/waitForSOCKSProcess до Stop и сохранение typed receipt целиком. CORE предоставляет current Authority и отдельный local readback callback. VLESS/CORE wiring **ещё не применено**; existing proxy/app/routeidentity и общие scripts этим commit не меняются. Control-plane GET не вызывает producer.

Фактические проверки этой порции, Go1.26.5, `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`:

- `test -count=1 ./internal/warp ./internal/usquediag ./internal/sources ./internal/cloudflareprovider` — RC0; warp4.641s, usquediag0.335s, sources0.835s, cloudflareprovider7.944s. После последних reader/fixture исправлений полный `test -count=1 ./internal/usquediag` — RC0,0.550s.
- `vet` четырёх own packages и финальный повтор usquediag — RC0.
- Linux amd64/arm64 `build` четырёх own libraries и `test -c ./internal/usquediag` — RC0. Test binaries сохранены локально в ignored `.review-local/cloud-owned-usque-linux-{amd64,arm64}.test`; не исполнялись.
- `test -run '^$' ./internal/app ./internal/dataplane` — RC0, compilation only, без исполнения тестов. `git diff --check` — RC0.

Actual USQUE/MASQUE, Linux/race fixture execution и root candidate tests этой порции **unverified**. D13 остаётся открытым до owner integration и bounded root проверки exact executable: H2 при UDP blackhole, QUIC path, отдельный UDP echo, Stop/restart/session/WAN drift. Новая регистрация, установка бинарников, VM/router/live mutation не выполнялись; VERSION/go.mod/go.sum не менялись.

## Independent P2 DNS boundary fix после 2b23a613

Root review обнаружил, что hostname SOCKS ATYP3 отдавал DNS upstream USQUE netstack: синтаксически approved HTTPS host мог разрешиться в private/mixed A/AAAA. Исправление только CLOUD-owned network boundary: `owned_probe_dns.go` и `owned_probe_network.go` выполняют fresh A+AAAA DoH по тому же exact owned SOCKS на literal `1.1.1.1:443`, с verified TLS hostname `cloudflare-dns.com`. Local/system resolver, proxy, ATYP3 destination и direct fallback не используются. Весь returned set проверяется до одного literal CONNECT; исходный service URL/hostname остаётся для TLS. API producer/receipt/backend не дублируются и не меняются.

DNS обеих семей имеет общий window3s внутри прежнего network deadline; wire4096 bytes, total64 RRs, cumulative32 A/AAAA, CNAME chain8. ID/question/header/framing/body lengths/CNAME связь проверяются; private/mapped адрес в answer/authority/additional или mixed family отвергает весь set. NODATA одной семьи допускается, aggregate nonempty обязателен. Нет cache/retry/адресного fallback; последующий Dial снова наблюдает и проверяет fresh set, текущий CONNECT уже закреплён за literal.

`owned_probe_dns_test.go` и адресные network tests — pure fixtures без DNS/socket/native/proc: private-only/mixed/all sections, correlation/framing/limits, NODATA/CNAME, fresh A→AAAA/shared timeout/cancel, exact DoH URL/TLS/media/body cleanup, один literal CONNECT при rebinding и отсутствие fallback. Финальный `GOPROXY=off`, Go1.26.5, GOMAXPROCS2/GOFLAGS=-p=2/GOTOOLCHAIN=local: `test -count=1 ./internal/usquediag` RC0,0.392s; `vet ./internal/usquediag` RC0; `test -run '^$' ./internal/app ./internal/dataplane` RC0 (compile only); Linux amd64/arm64 `test -c ./internal/usquediag` RC0 (не исполнялись); diff check RC0. Production DNS/DoH/native из CLOUD не запускались; actual router/root tests остаются UNVERIFIED. VERSION/go.mod/go.sum без изменений.

## Actual USQUE acceptance handoff

DNS fix зафиксирован отдельно: `a0b8cec28d5340bde6bceddafeff6d881ec381e4`. [Live checklist для root](CLOUD_USQUE_LIVE_CHECKLIST_RU.md) содержит gate owner commits/guard/actual binary/session, H2 under scoped UDP blackhole с exact H2/QUIC pins, real QUIC WARP+service bytes, independent SOCKS UDP echo, DNS/TLS/Stop/restart/WAN/session/exe/TTL/receipt negatives и cleanup ledger. Все actual-run строки UNVERIFIED; compiled/injected/local TLS results их не заменяют.

Read-only primary-source audit нашёл pinned compatible MASQUE server; его local interoperability сама по себе не даёт mandatory real WARP trace on/plus. Потому chosen deliverable — root live checklist, а не synthetic fixture с fake Warp. VLESS/CORE получили dependency request и готовые API/SHA. CORE подтвердил reuse current `dataplane.WithReviewGuard` worker seal; missing guard должен отказать active capture, GET вызывает только local Observe из private current ProcessSpec. Finished VLESS bridge/root acceptance ещё pending; backend/receipt/process ownership не дублируется. Это запрос по dependency, не подтверждение уже подключённого action.

## Retention compatibility после OPS 8f96be6

Отдельная порция от DNS fix `a0b8cec` и live checklist `675b718`. `native_retention_test.go` больше не ожидает raw rollback success при pending file journal. Timeout/response-crash требуют точный production managed refusal до init status/Stop/private recovery/deactivate, сохранение всего дерева `bin/etc/var/lib/razvilka` и прежнего file receipt ID/restored+pending. Отдельные presence-only subcases сохраняют file current, helper current и control root; retained artifacts не удаляются. Enrollment recovery того же attempt и API count=1 остаются отдельной CLOUD проверкой, не CORE startup admission.

Условный schema2 reader marker лишь пропускает ранний test CLI preflight к настоящему OPS presence gate; production capability/provider seals не создаёт. Low-level `Prepare/Install/Restore` с инертными callbacks — model lifecycle, не `InstallAdmitted/RestoreAdmitted`. Без integrated `require_legacy_file_protocol_free` managed cases явно SKIP. [Текущий harness](CLOUD_RETENTION_HARNESS_RU.md) и [retention contract](CLOUD_RETENTION_CONTRACT_RU.md) заменяют прежнее требование raw restoration на отказ с неизменным текущим mutable state; matching provider recovery после CORE wiring остаётся root интеграцией.

Проверки Go1.26.5, `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`, `GOPROXY=off`: `test -count=1 ./internal/warp` RC0,4.572s; `vet ./internal/warp` RC0; Linux amd64/arm64 `test -c ./internal/warp` RC0, binaries не исполнялись. POSIX syntax runner и diff check RC0. Exact harness с выключенным opt-in — SKIP. Независимый static review against OPS8f guard не нашёл blockers. Root сообщил native RC0 для самого OPS8f; actual обновлённый CLOUD harness на combined source **UNVERIFIED** и требует relevant cases без SKIP. Никакой native/socket/VM/router/registration запуск этой порцией не выполнялся.

## Actual HTTP Transport deadline follow-up

Root/VLESS подтвердили blocker `a0b8cec`: Go1.26 `http.Transport` сохраняет values, но снимает request deadline/cancellation перед DialContext, поэтому прежний SOCKS handshake отказывал до greeting; DoH терял DNS3s. Исправление в own `owned_probe_network.go` переносит actual bounded request operation context через private typed value, который оба production dial восстанавливают с fail-closed missing/canceled/unbounded проверкой. DoH заменяет inherited outer marker именно DNS child. SOCKS preflight проверяет deadline до Dial, per-request cancellation закрывает stalled greeting/CONNECT.

`owned_probe_dial_context_test.go` — portable context/HTTP-memory regression. `owned_probe_dial_context_native_test.go` + `scripts/test-cloud-owned-dial.sh` — по умолчанию выключенная настоящая loopback Transport/SOCKS/TLS проверка обеих production factories: success/literal+hostname, missing marker/no connection, greeting/CONNECT cancel/deadline с EOF при still-live socket owner, wrong TLS name/trust и actual DNS3s вместо outer20s. [Команда и ограничения](CLOUD_OWNED_DIAL_HARNESS_RU.md). Native fixture не даёт USQUE/WARP/UDP/semantic proof.

Portable `test -count=1 ./internal/usquediag` RC0,0.380s; `vet` RC0; Linux amd64/arm64 test binary cross-compilation RC0 (не исполнялись); runner syntax/diff RC0, выключенный runner actual RC2 до Go. Все native flags отключены, GOPROXY=off. Independent static review не нашёл blocking flow/TLS/EOF/cleanup defects; native cancellation assertions покрывают greeting/CONNECT, не отдельные stalled TLS/body. Actual native harness и USQUE consumer acceptance **UNVERIFIED**, выполняет root; UI/GET не получает network permission, consumer/receipt backend и VERSION/go.mod/go.sum не менялись.
