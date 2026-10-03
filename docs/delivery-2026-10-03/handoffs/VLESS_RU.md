# VLESS: первая порция D02 — 03.10.2026

База: `52eee92c28af1b9ad3c789f2ee2c3ffc43a0e175`, ветка `sol/vless-20261003`, worktree `C:/Projects/RAZVILKA/worktrees/sol-vless`. Изменения и этот отчёт входят в один коммит `Preserve exact Xray evidence and bound cross-engine node checks` поверх базы. Следующие D03/D10 не начаты; ожидается review координатора.

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
