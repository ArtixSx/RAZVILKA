# CORE — первая порция D11, 03.10.2026

Base: `52eee92c28af1b9ad3c789f2ee2c3ffc43a0e175` (code `367ef14` + docs), ветка `sol/core-20261003`, только `C:/Projects/RAZVILKA/worktrees/sol-core`. Один исполнитель, без дополнительных чатов/агентов. Исходное дерево было чистым. Общие стенды, VM, роутер, порты и публикации не изменялись. Production go.mod/go.sum/VERSION сохранены.

**Статус: законченный HTTP-путь matching recovery и исправление routing managed updates; D11 целиком НЕ закрыт.** Нельзя выпускать эту порцию как готовое обновление рабочего приложения. Ниже перечислены конкретные блокеры, которые невозможно честно устранить подменой live доказательства или редактированием файлов OPS/VLESS/NET без согласования.

## Карта flow и проверок

1. Startup устанавливает `InitializeComponentRecoveryGate` до фоновых работ. Durable pending/corrupt component journal закрывает Enter/Exclusive. GET состояния и явный Stop остаются разрешены; private restore/network journal fences сохраняют приоритет.
2. Manual HTTP update: security middleware (auth/Origin/CSRF) → исключительный operation admission → component Plan → authority guard с текущими revision/SafeMode/Stopped → candidate/inactivity check → `ManagedUpdateGuarded`. Scheduled update использует ту же journaled ветку и дополнительно исходный scheduler guard. Неиспользуемый managed пакет больше не идёт в plain Apply. Для него также нужен сохранённый rollback package.
3. Successful package/candidate stage возвращает HTTP 202 и pending transaction; scheduler останавливает партию. Ни candidate, ни отсутствие использования не объявляются live acceptance. Журнал и LKG остаются.
4. GET `/api/v1/components/recovery` возвращает transaction и текущую config revision, без изменений и с no-store. POST этого же URL декодирует ограниченный strict JSON; требует точные transaction/component, expected_revision и `confirm=REPAIR_COMPONENT_TRANSACTION`. Действия: `accept-live`, `rollback`, `verify-rollback`, `abandon-prepared`. Опциональные `allow_unknown_rollback`/`external_repair_confirmed` разрешены только для своих действий; callback/PID/path из JSON не принимается.
5. POST получает отдельное исключительное admission, разрешённое только для текущей pending transaction. Manager снова проверяет matching под durable lock. Guard повторно читает revision/SafeMode/Stopped перед мутациями и после live check. Повтор завершённой операции отклоняется и не повторяет пакетную команду.
6. `accept-live`: Manager проверяет installed version; приложение требует exact committed/applied revision; новый `dataplane.Manager.CheckComponentLive` проверяет network/review guard, ownership, текущую policy и health рабочего пути. Stage/Canary/Activate/Reconcile не вызываются. Для proxy engine/sidecar требуется launch receipt + boot/start/cmd/config identity и `os.SameFile(installed, /proc/PID/exe)`, до и после health. Приложение отдельно проверяет текущие executable всех процессов компонента. WG — CLI: требуется живой owned interface/peer/path, а не постоянно работающий процесс wg. Отсутствующий health target или source-scoped proxy без exact-node service proof отклоняется. Это Linux-only доказательство; на Windows нет положительного fallback.
7. Known rollback/verify использует live proof для используемого компонента либо отдельную проверку отсутствия использования/процессов для dormant rollback. Ответ dormant rollback не заявляет `live_accepted`. Unknown upgrade/rollback не replay. Для unknown нужен trusted quiescence callback; булевое подтверждение оператора его не заменяет.
8. После durable settlement снимается только соответствующий scheduler checkpoint. Если его отдельная запись не завершилась, matching POST может повторить только checkpoint cleanup по уже terminal transaction; package/runtime side effects не повторяются. Другой компонент/transaction этого права не получает.

## Изменённые файлы

- `internal/app/app.go`, `component_managed_update.go`, `component_recovery.go`, `operations.go`: HTTP wiring/admission/authority, journaled unused updates, корректный статус ожидания (`running`, поскольку Manager отвергает несуществующий статус `pending`), plan warnings/rollback blocker.
- `internal/app/component_runtime_acceptance.go`: независимое proc/executable наблюдение, отсутствие использования, fail-closed quiescence.
- `internal/dataplane/manager.go`: bounded by request deadline live health/ownership verification существующих concrete adapters; installed executable/launch identity.
- `internal/app/component_inventory_test.go`, `component_recovery_http_test.go`, `component_runtime_acceptance_test.go`, `internal/dataplane/manager_component_acceptance_test.go`, `manager_component_process_linux_test.go`: регрессии и подготовленный Linux process fixture.

## Проверки и RC

Go `C:/Projects/RAZVILKA/tools/go/bin/go.exe` 1.26.5, `GOMAXPROCS=2`, `GOFLAGS=-p=2`, без изменения production module files.

| Команда | RC / результат |
|---|---|
| `go test ./internal/app ./internal/dataplane -run 'Component\|ProxyUpdate' -count=1` | Первый RC 1: старый тест требовал plain update без rollback для dormant пакета; требование обновлено с сохранением остальных assertions. Финальные прогоны RC 0. |
| `go test ./internal/app ./internal/components ./internal/dataplane ./internal/operationgate -count=1` | RC 0: app 193.356 s, components 6.623 s, dataplane 49.272 s, operationgate 0.194 s. Выполнен до добавления последних адресных scenarios; они затем отдельно прошли. |
| `go vet ./internal/app ./internal/dataplane ./internal/operationgate` | RC 0. |
| `go test -race ./internal/app ./internal/dataplane -run 'Component\|ProxyUpdate' -count=1` | RC 1 до тестов: среда Windows имеет CGO disabled (`-race requires cgo`). Race НЕ пройден и передан Linux gate координатора. Toolchain/компиляторы не устанавливались. |
| `GOOS=linux GOARCH=amd64 go build ./cmd/razvilka` | RC 0; только cross-build. Временный бинарник удалён, не коммитился. |
| `GOOS=linux GOARCH=amd64 go test -c -o %TEMP%/razvilka-sol-core-dataplane.test ./internal/dataplane` | RC 0; только компиляция, включая Linux process fixture. |
| `git diff --check` | RC 0. |

HTTP tests запускают настоящий `httptest.Server` и штатный Handler/security middleware/gate/config Store/component Manager/journal. Package runner и native observations явно моделируются. Проверены 401, foreign Origin 403, transaction/component/CAS mismatch, pending ordinary POST, отсутствие candidate→live, изменение SafeMode во время live check, Stop guard, repeat HTTP, scheduled pending и restart, corrupt journal, unknown upgrade, interrupted rollback, external confirmation + trusted callback, запрет callback из JSON. Это НЕ настоящий opkg/native live acceptance.

## Блокеры и точные запросы владельцам

**OPS — trusted package quiescence.** В базовом журнале нет durable process tree/cgroup/supervision receipt для package scripts. Два proc scans находят opkg/interpreters/scripts, но пустой список не доказывает завершения detached native child старого postinst. Production `nativeComponentQuiescence` поэтому всегда оставляет historical unknown fenced, даже при пустом scan. Положительные HTTP unknown сценарии используют явно доверенный test callback. Нужен модуль OPS с контрактом `Quiescence(ctx, transactionID, component) error`, основанный на сохранённом supervision identity, независимо проверяющий command + descendants/scripts и fail-closed для historical journal без такого identity. CORE подключит его в app. Не заменять это PID-age/name scan, HTTP boolean или повтором opkg. Повторная upgrade/rollback команда при unknown запрещена.

**OPS — dormant acceptance.** Нужен отдельный Manager action `accept-installed-idle` для awaiting-live-acceptance, с отдельным receipt acceptance (не live), matching ID/component/current guard, проверкой exact installed version/config и доверенным inactivity callback до/после. Не превращать candidate check в live. До этого unused update journaled и pending (202); rollback достижим, успешное принятие dormant пакета ещё недоступно. Ранее предлагаемый UI workaround «остановить и обновить без rollback» убран.

**OPS — automatic rollback evidence.** `ManagedUpdateGuarded` в базе передаёт один candidate callback и в `tx.rollback`; изолированный proxy check не подтверждает принятие старого executable рабочим процессом. Нужен отдельный rollback/live callback либо сохранение `awaiting-rollback-acceptance` до matching HTTP verify. Существующие `internal/components/**` не правились CORE. Новый явный recovery endpoint уже использует независимую live/inactivity проверку.

**VLESS/NET + CORE — adoption and fresh proof.** Endpoint намеренно наблюдает runtime, а не неявно перезапускает его. Старый proxy executable после package upgrade отклоняется; startup с pending не запускает общую recovery. Для завершения proxy update нужен следующий согласованный узкий journaled live-adoption flow с точной свежей network/node/profile proof, сохранением LKG и rollback. Нельзя вызывать общий Recover/Apply в обход component fence. Source-scoped proxy без live selected/control service proof также не принимается. Для WG native acceptance требуется review NET по fresh endpoint lease/WAN и отсутствию изменений endpoint при live health. Эти запросы не являются разрешением начать D03/D05/D07 сейчас.

**UI — recovery contract.** Использовать GET для причины/revision; POST отправлять ровно указанную transaction/component/revision с confirm. HTTP 202 update — ожидание, 409 recovery — неподтверждённый результат, 503 — fence/journal; не показывать green/installed acceptance по одному candidate/process. `live_accepted` только для завершённого `accept-live`. Historical unknown требует supervision evidence и сейчас не освобождается обычным операторским boolean. UI-файлы не менялись.

## Для координатора / unverified

- Linux full gate + race на этом коммите, адресный native process test: `go test ./internal/dataplane -run 'TestComponentInstalledExecutableAcceptanceUsesKernelIdentity' -count=1`. Он запускает только временный локальный Go test child, проверяет настоящий launch receipt/proc inode, изменение config и замену установленного файла при сохранении старого процесса. Никаких сетевых ресурсов или packages. Здесь тест только cross-compiled.
- Настоящие opkg fault boundaries, accepted NFQWS/proxy/WG live runtime, package-script supervision/orphans, concurrent external opkg, live adoption/restart/reboot, physical power cut, Linux durability, HIL/soak не выполнены этим чатом.
- Копия Linux test binary в `%TEMP%` — локальный артефакт сборки, не поставка. Секретов, бинарников и частных логов в коммите нет.
- D11 в целом, D07/D08 и HIL остаются открытыми. Следующая крупная вертикаль не начата; ожидается review координатора и принятие контрактов выше.

04.10.2026 independent authority checkpoint: `internal/operationgate/self_update_stop*.go` реализует persistent installation/epoch + Stop receipt вне rollback images; общий kernel lock сериализует revocation с bounded effect begin. Readonly absence ничего не создаёт, missing/corrupt/foreign marker и incomplete current/intent блокируют запуск. Exact Stop retry после interrupted publication сохраняет epoch; другой ID/revision не переписывает receipt; Initialize не очищает Stop. Подтверждение cleanup требует двух свежих trusted наблюдений и не возвращает running authority. Windows unit tests/vet RC0; Linux cross-process lock/crash tests добавлены, native execution остаётся координатору. HTTP + actual OPS supervised consumer ещё не подключены; production capability0 сохраняется, D11 не закрыт. Подробный фактический API и ограничения — CORE_SELF_UPDATE_STOP_CONTRACT_RU.md.
