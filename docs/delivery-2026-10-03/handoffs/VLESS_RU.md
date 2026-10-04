# VLESS: первая порция D02 — 03.10.2026

База первой порции: `52eee92c28af1b9ad3c789f2ee2c3ffc43a0e175`, ветка `sol/vless-20261003`, worktree `C:/Projects/RAZVILKA/worktrees/sol-vless`. Первая порция: `04dd691d4fee00ae4b44eef51b6a37ba0c71c402` (`Preserve exact Xray evidence and bound cross-engine node checks`). Последующие checkpoint описаны ниже; ограничения первой порции сохранены как исторический контекст.

## Результат и файлы

- `internal/nodestore/store.go`: RecordCheck/чтение private envelope принимают только точные `sing-box:<этот node-id>` и `xray:<этот node-id>`. Префикс сохраняется в Health/History, после Close/Open и в private backup; неизвестные движки, чужой ID и пустой результат отклоняются без записи.
- `internal/nodestore/routes.go`, `route_snapshot.go`, `groups.go`: добавлены явные engine-specific API. Старые API остаются Sing-box-only. Последняя попытка определяется отдельно для engine/node/service/network; неудача Xray не отзываёт Sing-box PASS и наоборот. Fresh origin, disabled, TTL, network и direct-leak guards сохранены. Группы разрешаются с тем же engine; здоровый previousNode сохраняет LKG/hysteresis.
- `routes.go`: `MaterializeXray` использует существующие VLESSProfileFromJSON/CompileXrayConfig. Не поддерживаемый транспорт отклоняется повторно на границе материализации. В результате `RouteMaterial.EngineID=xray`; Sing-box возвращает `sing-box`. Приватные endpoint hosts собираются из канонического материала. Xray имеет первым outbound blackhole, отдельные domain/IP правила и конечный tcp,udp blackhole; domain+IP не объединяются в условие AND. Inbound/TUN не создаётся.
- `internal/nodestore/source_utility.go`: положительные подсказки источников отделены по engine через SourceUtilityForEngine; отрицательная оценка источника не добавлялась.
- `internal/dataplane/nodecheck_dispatcher.go`: один ExactNodeDispatcher с квотой 1..4 для обоих движков. ForEngine возвращает фиксированный NodeChecker/TransportScreener/NodeCheckCapacity view, без автоматической подмены движка. DNS/TCP screening также занимает общую квоту; Check удерживает её до завершения cleanup. Busy не ставится в очередь. Unsupported проверяется до общей квоты и DNS, возвращается без ProbeID/наблюдения. Recover исключает все dispatched checks/screens и пытается восстановить оба движка, сохраняя индивидуальный poison fence при ошибке. Дубликаты движка, одинаковые/вложенные пути и пересечение всех четырёх потенциальных портов отклоняются.
- `internal/nodestore/routes_engine_test.go`, `internal/dataplane/nodecheck_dispatcher_test.go`: регрессии сохранения/выбора/материализации, wrong engine/network/service, TCP-only/leak/expiry/origin/disabled, невозможного compiler profile, LKG/manual/fallback, quota/cleanup/cancel/unsupported/recovery.
- `internal/dataplane/nodecheck_xray_store_native_linux_test.go`, `scripts/check-xray-native.sh`: подготовлена дополнительная opt-in проверка реальным `xray run -test` двух materialized TLS/REALITY exits с domain/IPv4/IPv6 rules. Synthetic CheckRecord здесь даёт доступ только к проверке синтаксиса и **не является native path proof**. Существующий native checker/server harness не переписан; добавлен один тест в его селектор.

`internal/app/**`, worker, общий manager/plan/policy, go.mod/go.sum/VERSION, VM, роутер и внешние публикации не менялись. Live-порты/сетевые namespace не использовались. Пакет не снимает NETWORK_POLICY_EXECUTOR_REQUIRED, Stop/recovery/auth/CSRF/CAS guards.

## Конкретный контракт для CORE

1. В `cmd/razvilka/main.go` создать два существующих checker с отдельными доверенными абсолютными каталогами и непересекающимися портами; оба обернуть **одним** dispatcher. Настроить Binary/FreshProfile до создания; после создания не менять checker и не вызывать исходные checker напрямую. Каталоги не должны быть alias/symlink друг друга: constructor проверяет лексическое пересечение, не владение всей файловой системой.

```go
slots := 2 // пример общей квоты, не 2+2
sing := dataplane.NewExactNodeCheckerSlots(filepath.Join(state, "node-check"), slots)
xray := dataplane.NewExactXrayNodeCheckerSlots(filepath.Join(state, "node-check-xray"), slots)
dispatch, err := dataplane.NewExactNodeDispatcher(slots, sing, xray)
// Обработать err; один Recover(ctx) восстанавливает оба engine.
singView, err := dispatch.ForEngine("sing-box")
xrayView, err := dispatch.ForEngine("xray")
// Передавать нужный fixed view в общий путь runAndRecordNode.
```

2. `internal/app/nodes.go`: общий runAndRecordNode должен знать **ожидаемый engine** из выбранного fixed view/доверенного route intent, а не определять его по ответу checker. Проверить NodeID, ServiceID, NetworkProfile, RoutePathID=`engine+":"+id`. Для положительной сервисной evidence сверить Engine/ExpectedRoutePathID/ObservedRoutePathID с тем же engine/path. Сохранить текущий CAS/generation, nodeStillCheckable, два свежих network readback и nodeRecordMu. В RecordCheck передать исходный RoutePathID без переписывания. Любой ранний error (включая Unsupported/Runtime/Busy/NetworkChanged) означает отсутствие нового CheckRecord/measurement/штрафа node/source, отсутствие Apply и отсутствие автоматического Sing-box retry.

3. `nodeRouteOptions`/review/apply/recovery и хранение выбора: разобрать engine и raw node/group ID один раз. Использовать:

```go
Nodes.RouteSnapshotForEngine(ctx, engine, profile, now)
Nodes.RouteServicesForEngine(ctx, engine, nodeID, profile, now)
Nodes.GroupServicesForEngine(ctx, engine, groupID, profile, now)
Nodes.ResolveRouteForEngine(ctx, engine, targetID, serviceID, profile,
    previousNodeOfSameEngine, previousSince, now)
Nodes.SourceUtilityForEngine(ctx, engine, allowed, protocols, serviceID, profile, now)
```

Ключи карты snapshot остаются raw ID, значения — service IDs **только указанного engine**. ResolvedRoute.Route содержит engine. Сохранять `xray:node-*`/`xray:group-*` целиком в draft/committed/applied/recovery, guards удаления и retained references проверяют оба префикса. Health.State — последнее отображаемое наблюдение любого engine; самостоятельных полномочий Apply не даёт. App ranking/refill/cleanup сейчас во многих местах hardcode Sing-box; использовать ожидаемый route/engine также для nodequality.ResponseMS и feedback. D10 алгоритм в этом коммите не менялся.

4. Materialization boundary: только `MaterializeXray` для Xray и `MaterializeSingBox` для Sing-box. Проверить RouteMaterial.EngineID перед передачей Config в соответствующий adapter; не отбрасывать engine при преобразовании в dataplane.NodeRouteMaterial. Config/EndpointHosts остаются приватными, не попадают в public plan/JSON/log. Это service-scoped материал, не all-except/default executor.

5. **Блокирующая граница D03:** текущие `ProxyTunnelAdapter.NodeRoutes`, scoped Stage и `Manager.ConfigureSingBoxNodeRoutes` подключены только для Sing-box. Нынешний `normalizeProxyConfig("xray")` требует единственный static remote exit и отвергает routing/blackhole: новый trusted материал туда подавать нельзя, general engine draft его не заменяет. CORE должен предоставить отдельный ConfigureXrayNodeRoutes/общий engine-aware registration контракт в своём manager/plan; расширение принадлежащего VLESS proxy/identity lifecycle будет отдельной D03-порцией после review. `internal/routecatalog`/`routekind` пока не назначены этому чату: координатору назначить владельца exact `xray:node/group` selector rules. До scoped adapter + TUN selected/control приёмки Xray route option не становится Selectable для применения.

6. Формат CheckRecord остаётся schema 4 без нового сериализованного поля: engine уже содержится в RoutePathID. **Старый бинарник этой базы не умеет читать Xray history и отвергнет такой envelope целиком**, сохранив файл; безопасный downgrade после появления Xray записей этим коммитом не доказан. CORE/OPS должны запрещать несовместимый downgrade или согласовать version/schema capability gate до выпуска. Не удалять Xray evidence/профили ради обхода gate. Восстановление/backup новой версией проверено unit-тестом.

## Проверки этого чата

Windows/amd64, штатный `C:/Projects/RAZVILKA/tools/go/bin/go.exe`, Go 1.26.5; `GOMAXPROCS=2`, `GOFLAGS=-p=2`, `GOTOOLCHAIN=local`. Production dependencies не менялись.

| Команда | RC и граница |
|---|---|
| `go test ./internal/nodestore ./internal/dataplane -run 'Test(XrayEvidence|Engine|Dispatcher)' -count=1` | 0, первый адресный прогон |
| `go test ./internal/providerprofile ./internal/nodestore ./internal/nodequality ./internal/nodecleanup ./internal/dataplane -count=1` | 0, профильные пакеты целиком |
| `go test ./internal/app -run 'Test.*(Node|Autonomy)' -count=1` | 0, существующие app/worker регрессии без правок их исходников |
| `go test ./internal/nodestore ./internal/dataplane -run 'Test(Xray|Engine|Dispatcher|ExactXray)' -count=3` | 0, финальный прогон после последних тестовых дополнений |
| `go vet ./internal/nodestore ./internal/dataplane ./internal/providerprofile ./internal/nodequality` | 0 после финальных дополнений |
| `go build ./...` | 0, Windows production build |
| `GOOS=linux GOARCH=amd64 go test -c -o <temporary file> ./internal/dataplane` | 0, только Linux test-binary compile; временный бинарник удалён |
| `GOOS=linux GOARCH=amd64 go vet ./internal/dataplane ./internal/nodestore` | 0, включая новый Linux-only syntax fixture; не Linux runtime |
| `sh -n scripts/check-xray-native.sh` | 0, syntax only |
| `git diff --check` | 0 |
| `go test -race ./internal/nodestore ./internal/dataplane -run 'Test(XrayEvidence|Engine|Dispatcher)' -count=1` | 1: `-race requires cgo`; GCC отсутствует в PATH, race не выполнялся |

Новые unit tests выполняют stateful library fixtures; процессы/пробы checker в dispatcher-тестах поддельные. Они не объявляются native Xray/LAN/TUN evidence. Старые native PASS из VALIDATION_RU.md относятся только к базе координатора.

## Unverified и приёмка координатора

- Запустить Linux адресный race: `go test -race ./internal/nodestore ./internal/dataplane -run 'Test(Xray|Engine|Dispatcher|ExactXray)' -count=3`, затем штатный integration gate. Linux runtime, полный gate и аппаратная проверка изменённого кода здесь не выполнялись.
- Эксклюзивно запустить существующий `RAZVILKA_XRAY_NATIVE=/absolute/path/xray GO=/absolute/path/go sh scripts/check-xray-native.sh`: теперь дополнительно включает TestNativeXrayStoreConfigSyntax. У этого дополнения здесь только успешная cross-compilation; результат native не заявлен. Секреты/конфиги создаются только во временных приватных директориях и не включены в Git.
- CORE wiring и scoped Xray adapter остаются открытыми. D03 TUN selected/control, endpoint changes, sidecar kill, app/router restart и verified rollback; D10 cold first-usable/fair refill; общий LAN/DNS executor и D14 — отдельные незакрытые этапы.
- Native syntax success тоже не станет доказательством TUN, всего Интернета или аппаратного LKG. В этой порции нет live-мутаций и релиза.

## D03 — ограниченный scoped Xray TUN adapter

Вход второй порции: интеграционная база `99ac304778f881bab24692f9d87f880d41da4d09`, включённая ff-only по поручению координатора. Результат — отдельная доверенная фабрика `NewScopedXrayTunnelAdapter`, lifecycle и воспроизводимый opt-in native стенд. **D03 не закрыт, XraySelectable остаётся false**: новый путь ещё не подключён CORE к реальному приложению и не принят native/HIL. Обычные Xray drafts сохраняют прежний single-exit validator.

Изменены только принадлежащие VLESS `proxy*`, `hev_sidecar.go`, `nodestore/history_compatibility*`, профильный native script и этот отчёт. manager/plan/policy/ownership/app/main/routecatalog не менялись; production go.mod/go.sum/VERSION неизменны.

- `proxy_nodes.go`: factory требует приватный NodeStore materializer; Stage принимает только `EngineID=xray`, resolved exact node IDs, явные client Sources и HTTPS service probes. Generic main draft, чужой engine, другой listener, freedom/default и изменение exact domain/IP/terminal-blackhole rules отвергаются до Start. Endpoint фиксируется в native config по свежему resolver, SNI сохраняется. Private manifest schema1 связывает полный config/sidecar digest, engine, WAN, routes, service destinations, host/IP/tag. При изменении endpoint или service address нужна новая transaction; RefreshPolicy не расширяет RPDB отдельно от Xray allowlist.
- `proxy_node_identity.go`: проверки используют launcher-created receipt полного routed process, cmdline, boot/starttime/PID, installed executable, config hash и принадлежность loopback SOCKS inode. Повторная запись receipt в verifier запрещена. Проверяются и Xray, и stock Sing-box sidecar, до/после проб. PID namespaces не нужны; ns/net используется только при наличии. Если оба ns/net отсутствуют с ENOENT (Netcraze), это не зависимость от namespaces; одностороннее отсутствие/ошибка чтения остаются fence.
- `proxy_node_interface.go`: private interface lease содержит boot, exact ifindex и config hash. Замена same-name интерфейса и неизвестный/нечитаемый inventory не дают права удалить его. Даже после ошибки команды отсутствие подтверждается успешным полным inventory. Остановка owned процессов предшествует точному удалению; ошибки сохраняют файлы/lease. JSON readback iproute2 обязателен; BusyBox без `ip -j` не принят этим checkpoint.
- `proxy_node_health.go`: `NodeTUNProbe` — доверенный callback настоящих selected/control LAN clients к одному pinned service IP. SOCKS/локальная подмена source/HTTP JSON не могут устанавливать этот callback. Health проверяет service acceptance, public distinct egress, source внутри/вне выбранного scope, actual kernel `route get ... from ... iif ...`, полный runtime до/после, WAN, config/manifest, ifindex и forwarding readback. Commit повторно делает Health. IPv4 TCP HTTPS — проверяемая граница; IPv6/UDP/media/voice ещё не доказаны.
- `proxy.go`, `proxy_rollback_verify.go`: snapshot и rollback сохраняют engine/manifest; dead sidecar можно восстановить по неизменному committed state. Activate/rollback не стартуют поверх неизвестного интерфейса. После rollback выдаётся read-only verified receipt только при точных файлах, boot, процессах, ifindex, forwarding/RPDB и отсутствии правил кандидата. Это proof восстановления A, а не утверждение, что сервис A здоров.
- `proxy_nodes_test.go`: lifecycle с actual NodeStore materializer (unit process/probe fixtures), свежий manifest, sidecar death/reconcile, verified rollback, stale endpoint без LKG mutation, wrong-client/same-egress/missing-proof/identity/config/manifest tamper, draft/engine/rules rejection, foreign ifindex и inventory errors. Native evidence из этих тестов не заявляется.
- `nodestore/history_compatibility.go`: `ExactHistoryReadVersion=2` отдельно от schema4; `RequiredHistoryReadVersion(ctx)` проверяет live validated store, `RequiredPrivateHistoryReadVersion(snapshot)` — retained backup без импорта. Invalid/cancelled/closed даёт error + version0, никогда не legacy fallback. Xray evidence после reopen и corrupted backup fence проверены.

### CORE/OPS контракт D03 и downgrade

1. Для scoped executor создать новый adapter через `NewScopedXrayTunnelAdapter(configs, trustedStateRoot, materializer)`. Callback преобразует `NodeRouteRequest` в `nodestore.RouteBinding` и вызывает **только** `Nodes.MaterializeXray`; передаёт `EngineID`, Config, EndpointHosts без потери engine. Задать Binary/stock Sing-box SidecarBin/Resolver/FreshProfile до использования. HEV остаётся opt-in experimental.
2. CORE — единственный владелец manager registration и планирования. Зарегистрировать этот exact adapter вместо generic Xray в подходящем trusted режиме; не менять существующий adapter backend на ходу. General engine draft не совместим со scoped node material. Разрешение `xray:node/group` и RequiresNetworkProof/CheckCommittedNodeHealth должны быть engine-aware через manager/plan CORE. Нужны реальные consent/Stop/SafeMode/network guards и независимый production LAN-client verifier для NodeTUNProbe. Пока его нет, Validate отказывает, Selectable не включать.
3. CORE добавить read-only binary capability flag `-node-history-read-version` с фиксированным выводом `2`. Это предложение контракта; CLI flag в этой порции **не реализован**. OPS перед stop/install/downgrade должен сравнить capability candidate с максимумом required version live store и всех retained backup/restore images, которые workflow может восстановить. Неизвестный flag/nonzero exit/невалидный вывод — fail closed. Capability1 разрешён лишь когда все актуальные/retained images требуют1 и другие schema/receipt gates также проходят. Xray history не удалять и не переписывать в Sing-box. Gate должен действовать до app начинает писать Xray CheckRecord.

### Native стенд для координатора

`proxy_nodes_native_linux_test.go` / `scripts/check-xray-tun-native.sh`: четыре созданных исключительно тестом namespace (router/server/selected/control); public-format fixture IP живут только в изолированных namespaces без uplink. Настоящие TLS VLESS servers A/B, Xray client, stock Sing-box gVisor TUN, kernel RPDB/iptables, два LAN HTTPS клиента. Проверяется A Apply/Health/Commit, новый экземпляр adapter из on-disk state, kill/restart sidecar, endpoint A→B с другим actual egress, kill B sidecar → rejected Commit → rollback A → VerifyRollback → actual selected/control traffic. Новый экземпляр adapter — **не app process restart**; reboot/app HTTP/CORE wiring остаются отдельной приёмкой. Fixture CA доверяется только дочерним процессам теста; TLS verification не отключается. Graceful stop server и exact-owned namespace PID cleanup предусмотрены также после timeout; чужие namespaces/процессы не затрагиваются.

Координатор подтвердил official pinned Xray 26.3.27 и Sing-box 1.13.3/1.14.2 с `with_gvisor/with_quic`, SHA256 проверены им. Сначала выполнить1.13.3, затем1.14.2 отдельным запуском; versions/logs сохранить раздельно:

```sh
RAZVILKA_XRAY_NATIVE=/home/art/.cache/razvilka-review/toolchains/xray-v26.3.27/xray \
RAZVILKA_SINGBOX_NATIVE=/home/art/.cache/razvilka-review/toolchains/sing-box-1.13.3/sing-box \
GO=/absolute/path/to/go sh scripts/check-xray-tun-native.sh
# Второй запуск: заменить только Sing-box путь на .../sing-box-1.14.2/sing-box.
```

Этот чат бинарники не скачивал/не устанавливал, VM/роутер/live порты не использовал и native тест не запускал.

### Проверки D03

Та же Windows/Go1.26.5 среда, GOMAXPROCS2/GOFLAGS=-p=2/GOTOOLCHAIN=local. Все команды ниже завершились RC0:

- `go test ./internal/dataplane ./internal/nodestore ./internal/providerprofile ./internal/nodequality ./internal/nodecleanup ./internal/providerfeed -count=1`;
- `go test ./internal/app -run 'Test.*(Node|Autonomy)' -count=1` — неизменённые app tests;
- финальные `go test ./internal/nodestore ./internal/dataplane -run 'Test(ScopedXray|RequiredHistory)' -count=3`;
- Windows `go vet ./internal/dataplane ./internal/nodestore`, `go build ./...`;
- Linux/amd64 `go test -c ./internal/dataplane` (временный бинарник удалён) и `go vet ./internal/dataplane ./internal/nodestore` — compile/static only;
- `C:/Program Files/Git/bin/sh.exe -n scripts/check-xray-tun-native.sh`, `git diff --check`.

Один промежуточный тестовый compile выявил повторное `:=` после добавления backup check; исправлено, финальные прогоны выше прошли. Linux race/native/full gate/hardware не выполнялись. Native-команды и оба runtime version остаются **unverified** до запуска координатором. D10 — следующая отдельная порция через CORE worker contract.

### D03 fixture permissions — отдельное исправление

Координатор сообщил native PASS RC0 на интеграции `0669514+b3bc486` с Xray26.3.27 и отдельно Sing-box1.13.3/1.14.2. Это результат координатора, не локальный прогон этого чата. Первый полный Linux gate обычным пользователем art затем обнаружил `private restore journal unavailable` в TestScopedXray*: fixture передавала уже существующий `t.TempDir` в engineconfig.StageRoot без private0700, а stageDirectory правильно отвергал0755. Исправлены исключительно каталоги fixture (nodes/stage/backup/state), Chmod errors теперь проверяются. Production permissions/guards не менялись. Адресный Windows test `TestScopedXrayRejectsDraftWrongEngineAndBlackholeMutation` прошёл RC0; Linux ordinary-user повтор принадлежит координатору. Native fixture создаёт отсутствующие drafts внутри своего private root и этого дефекта не имела.

## Shared policy receipt и proxy generations

Общий модуль поставлен в 0d49f3e, stricter promotion retry — 7253153. По отчёту координатора native-policy-receipt-01 (race и 12 real crash boundaries в отдельном netns) PASS RC0. Proxy теперь подключён к общему per-tuple receipt, сохраняет promoted generation при Commit и использует новые receipts для recovery/restoration. Подробный финальный контракт, ограничения и точные результаты проверок: VLESS_POLICY_ADDITION_RU.md и VLESS_PROXY_GENERATIONS_RU.md. Эти отчёты заменяют промежуточный aggregate-only checkpoint. D10 будет отдельной порцией; app/worker wiring остаётся CORE.
