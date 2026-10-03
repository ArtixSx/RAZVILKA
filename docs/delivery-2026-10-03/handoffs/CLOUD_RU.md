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

Действующий producer `internal/dataplane/proxy.go` принадлежит VLESS и в этой порции **не изменён**. CORE/VLESS должны дописать после успешного exact native canary и подтверждённой очистки существующий receipt:

- `checked_at` и `valid_until` в RFC3339, `checked_at <= now < valid_until <= checked_at + MaxCanaryAge`;
- `transport`: ровно `HTTP/2` или `QUIC`, фактически проверенный native transport;
- `endpoint`: exact pinned canonical AddrPort с портом 443; H2 только из endpoint_h2_v4/v6, QUIC только из endpoint_v4/v6;
- `binding_id = CanaryBinding(SHA256 текущих usque.conf, session.conf, exact executable bytes, текущий environmentID)`;
- прежние warp/service facts только из native canary, без raw output/keys/token/device ID.

Экспортируемые capabilities содержат `http2/http3/udp` = `unknown|confirmed`, `fresh`, фиксированный `reason_code`. Они диагностические, не заменяют dataplane ownership/pin/CAS/revalidation/service proof. Producer обязан связать receipt с теми же bytes и epoch, реально использованными кандидатом; receipt от иной временной конфигурации нельзя переподписать под текущую. До этого wiring **вся legacy evidence unknown**. Exact kernel pin tuple, изменение WAN/DNS перед Apply и изоляция actual runtime остаются CORE/NET/VLESS и требуют отдельной приёмки.

### Источники / offline

`Sources.OfflineCatalog()` — новый memory-only read API; не вызывать Refresh/RefreshEnabled при входе, GET или fallback на offline. View показывает сохранённые Entries/SHA/provenance/expiry/settings; не даёт разрешения новой route mutation. `Sources.List()` тоже memory-only и теперь отдаёт detached metadata. Existing AutomaticUseReady/EntriesForService по-прежнему проверяют actual receipt и TTL; активную применённую политику эти функции не удаляют.

## Контракт UI

Показать TCP/443 отдельно от неизвестных HTTP/2, HTTP/3, UDP. `registration.ready` подписывать доступностью API; registered account брать из Status. `canary_evidence` без fresh capability — история с датой, не зелёный текущий статус. `offline=true`/offline-cache/stale/legacy/quarantined не представлять fresh; Entries и applied scope можно сохранять в read-only каталоге. Публичный activation error теперь фиксированный код, подробный process output возвращать нельзя.

## Ограничения и следующая приёмка

D13 **не закрыт**. Нет настоящей регистрации, HTTP/2/HTTP/3/WireGuard native canary, VM/router mutation, HIL, full Linux/race gate или физического crash/power-cut. Library tests не выдают production readiness. Новый callback и receipt fields ещё не подключены через CORE/VLESS; UI ещё не читает новые поля. Существующие POST diagnostics и source refresh authorization не менялись; login/GET не получили сетевых прав.

Координатору: принять diff/commit, запустить адресные пакеты на Linux, согласовать receipt writer + current environment callback и UI поля. После wiring проверить настоящий native H2 success при недоступном UDP, QUIC success, смену endpoint/WAN/DNS/boot, stale receipt, повтор unknown enrollment и сохранение активного LKG. Живую регистрацию проводить только в отдельном явно разрешённом owner-managed окне; эта порция её не требует и live harness не запускает.

NETWORK_POLICY_EXECUTOR_REQUIRED сохранён; auth/CSRF/TLS/Stop/CAS/ownership/recovery fence/LKG не отключены. Mihomo/HEV не получили production статус. Общие TASKS/VALIDATION и ownership docs остаются у координатора.
