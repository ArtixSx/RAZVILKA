# NET — первая порция D04 и аудит D05

Дата: 03.10.2026. Worktree: `C:/Projects/RAZVILKA/worktrees/sol-net`.
Ветка: `sol/net-20261003`. Base: `52eee92c28af1b9ad3c789f2ee2c3ffc43a0e175` (проверенный code `367ef14` + документы).
Один исполнитель; дополнительные агенты/чаты не создавались. VM, роутер, общие порты, другие worktrees и GitHub не изменялись. `go.mod`, `go.sum`, `VERSION` сохранены.

## Результат

**Same-peer Canary теперь запрещён до создания временного интерфейса.** Кандидат с локальной public identity уже настроенного WG/AWG-интерфейса возвращает `ErrWGCanaryIdentityInUse`. Это относится к своим и foreign интерфейсам, также administratively down; иной endpoint, server public key или PSK не отменяет запрет. Одинаковая private identity могла изменить удалённую Noise-сессию/roaming endpoint даже при правильных локальных SO_BINDTODEVICE/RPDB, поэтому локальная изоляция больше не объявляется достаточной.

Проверка читает `ip -j -d link show` и только `wg/awg show all public-key`. `showconf`, `dump`, private key и PSK readback не используются. Проверяется наличие kernel WG/AWG links в ответе соответствующего CLI. Отсутствующий CLI для существующего backend, ошибка/неполный/невалидный/слишком большой ответ запрещают старт с `ErrWGCanaryIdentityInspection`. Нет обхода «не удалось прочитать — считать свободным». Диагностика не содержит material ключей.

Исправлена неоднозначность `wgRuntimePublicKey`: helper больше не берёт первый PrivateKey из профиля с повторными Interface/PrivateKey или PrivateKey вне Interface. Такой WARP material мог пройти прежний `warp.ValidateProfile`, который сохраняет последнее значение, и получить несовпадение проверенного ключа и ключа setconf. Правка находится в NET-owned helper, модуль OPS `internal/warp` не менялся.

**D05: добавлена revalidation перед Canary.** Раньше новый Generic WG endpoint проверял WAN/DNS перед Activate/Reconcile, но Canary мог начать работу по устаревшему staged bootstrap path. Теперь `readStagedPolicy` + `revalidateWGEndpoint` выполняются до canary файлов и сетевых изменений. Изменённый WAN или noncacheable/expired DNS без прежнего выбранного IP дают `ErrWGEndpointChanged`, сохраняя live/LKG. TTL системному resolver не придуман.

## Файлы

- `internal/dataplane/warpwg.go`: identity guard и Generic WG endpoint revalidation в Canary.
- `internal/dataplane/wg_canary_identity.go`: bounded публичная inventory, два различимых локальных отказа.
- `internal/dataplane/wg_endpoint_lifecycle.go`: однозначное получение runtime public identity.
- `internal/dataplane/wg_canary_identity_test.go`: WG/WARP/AWG; иной peer/endpoint/PSK с тем же клиентским ключом; unknown/неполный inventory; ambiguity; pre-Canary DNS/WAN; настоящий Manager.ProbeCandidate сохраняет committed runtime/state без delete/restart.
- `internal/dataplane/warpwg_test.go`: fake runner явно моделирует новые inventory-команды, не зависит от ответа настоящего CLI на машине.
- `internal/dataplane/wg_canary_native_linux_test.go`: расширенный D04 harness и общая owned topology для D05.
- `internal/dataplane/wg_endpoint_native_linux_test.go`: opt-in Generic WG endpoint lifecycle с kernel WG/iproute2 и реальным HTTP.
- Этот отчёт.

## Выполненные локальные проверки

Windows/amd64, `C:/Projects/RAZVILKA/tools/go/bin/go.exe` 1.26.5; `GOMAXPROCS=2`, `GOFLAGS=-p=2`. Production module/version не менялись.

| Команда | Фактический результат |
|---|---|
| `go test ./internal/dataplane -run 'WGCanary\|WGEndpoint\|WGManagerSamePeer\|OwnWireGuard' -count=1` | RC 0, после identity ambiguity fix |
| `go test ./internal/dataplane ./internal/wireguardprofile ./internal/tunnelcheck ./internal/awgprofile -count=1` | RC 0, финальный прогон |
| `go vet ./internal/dataplane ./internal/wireguardprofile ./internal/tunnelcheck ./internal/awgprofile` | RC 0, финальный прогон |
| `GOOS=linux GOARCH=amd64 go test -c ./internal/dataplane -o <временный файл вне repo>` | RC 0, финальная компиляция обоих native harness; не Linux runtime |
| `go test -race ./internal/dataplane -run 'WGCanary\|WGEndpoint\|ResearchWGCold\|OwnWireGuard' -count=1` | RC 1 до тестов: `-race requires cgo`; race здесь не проверен |
| `git diff --check` и gofmt изменённых Go-файлов | RC 0 |

Первые адресные прогоны выявили ошибки новых тестовых данных/импортов: нулевой PSK запрещён строгим parser; недостающий import остановил vet. Исправлены, последующие адресные/vet прогоны RC 0. Отказы не скрывались отключением production-проверок.

## Native — подготовлено, запуск только координатором

В этой порции native **не запускался**. Компиляция не подтверждает результат kernel/Noise/lifecycle. Нужны Linux, root, kernel WireGuard, iproute2 JSON, wg и эксклюзивное окно координатора. Никакие внешние серверы/аккаунты не используются: все public-format адреса принадлежат созданным тестом namespace. Ключи только временные, каталог должен попадать в разрешённый AppArmor путь `/etc/wireguard/razvilka-*`; AppArmor не отключать.

```sh
# Выполняет координатор в своей Linux VM из проверяемой копии проекта.
# GO указывает на установленный Linux Go 1.26.5; dependencies уже подготовлены.
native_tmp=$(mktemp -d /etc/wireguard/razvilka-net-native.XXXXXX)
export TMPDIR="$native_tmp" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
RAZVILKA_WG_NATIVE=1 "${GO:-go}" test ./internal/dataplane \
  -run '^TestWGNative(CandidateIsolation|EndpointLifecycle)$' -count=1 -v -timeout=4m
native_rc=$?
# Go test удаляет собственные TempDir; непустой каталог требует осмотра владельца.
rmdir "$native_tmp"
exit "$native_rc"
```

Запускать без унаследованных `RAZVILKA_WG_NATIVE_ROLE/ROOT/READY/RECOVER_ROOT/ENDPOINT/NOW`. Логи и временные material/bin не включать в коммиты. Namespace создаются до регистрации cleanup, поэтому занятой чужой namespace не удаляется. Сетевые изменения выполняются только в successfully-created test namespace; server processes завершаются до удаления namespace.

**D04 матрица:**

1. Один live поднимается один раз, работает через оба payload семейства; пересоздание между IPv4/IPv6 удалено.
2. Кандидаты с live private identity и с правильным/неверным server public key обязаны вернуть `ErrWGCanaryIdentityInUse`; counters live не меняются во время попытки; затем реальный TCP/UDP live отвечает.
3. Успешный независимый кандидат имеет ту же Address, но отдельно выделенные клиентские credentials и remote peer state в третьем namespace. После него live TCP/UDP отвечает, его counters не использованы кандидатским трафиком.
4. Неверный server key независимого кандидата приводит к отказу; затем live TCP/UDP снова отвечает. Последняя очистка проверяет отсутствие temporary interface/table/rule, Sources сохраняются.

Отдельный сервер для независимого кандидата не обходит проверку same-key: оба запрещённых сценария используют прежнюю live identity и первоначальный peer. Он обеспечивает валидную независимую peer-конфигурацию для проверки локальной изоляции одинаковой Address. Смена remote AllowedIPs или server peer configuration не является production-способом сохранения LKG.

**D05 матрица:** полный Snapshot→Stage→Validate→Canary→Activate→Health→Commit для named profile; transport endpoint IPv4 и IPv6, payload HTTP IPv4. Проверяются mark/точный WAN host route, чтение committed state новым subprocess, отказ на expiry/DNS и WAN changes с live-after-reject, controlled loss интерфейса/rules/pin с новым subprocess Reconcile, rollback начальной транзакции без прежнего live, новая cold транзакция и Stop. Unrelated host route в той же table 206 и исходный hostname/revision профиля должны сохраниться. Resolver и clock в harness явно тестовые; handshake, HTTP, WG/socket mark и iproute2 настоящие.

## Аудит D05 и оставшиеся границы

- `OwnsPolicyRoute` уже подключён координатором в base `367ef14`; повторное изменение main не требуется.
- Endpoint tuple/rule full mark mask, gateway/device/source, protocol/metric и runtime digest остаются обязательными. Ни priority range, ни один runtime.conf не дают новых cleanup прав. Старый committed state с nil endpoint не получает pin authority.
- Crash window kernel mutation→transaction marker остаётся открытым. Эта порция не присваивает orphan ресурсы и не заявляет power-cut durability.
- Native сценарий не проверен; контролируемое удаление kernel-state не является настоящим reboot/power cut. Rollback с восстановлением предыдущего *другого* live peer остаётся отдельным native/HIL сценарием.
- Запрет консервативен: даже изменение endpoint/политики того же live ключа нельзя проверять вторым Canary. Автоматического временного Stop/пересоздания live здесь нет. Для такого изменения нужен отдельно принятый протокол serial switchover/recovery или явный Stop и новая cold транзакция пользователя.
- Inventory видит текущий namespace и доступные WG/AWG backends. Нет гарантии против несогласованного внешнего создания/переноса интерфейса во время проверки, неизвестного устройства с копией того же ключа или удалённого владельца. Все network owners обязаны сериализовать изменения с координатором; ключи одного peer нельзя одновременно использовать на разных устройствах/namespace для candidate.
- WARP/AWG endpoint pins/TTL, AWG ABI/module/server, профили app CRUD/резервы, LAN/DNS executor, D08/D09 и HIL остаются открытыми. `NETWORK_POLICY_EXECUTOR_REQUIRED` не снят. D06 до review этой порции не начат.

## Точный контракт CORE (без изменений чужих файлов)

1. **Классификация отказов.** Сохранять `errors.Is` через adapters/API: `ErrWGCanaryIdentityInUse` = локальный safety reject, `ErrWGCanaryIdentityInspection` = local inconclusive. Ни один не является failed handshake/service и не ухудшает profile/peer reputation, не запускает Stop/rollback/restart live, не разрешает Apply. Предложенные HTTP machine codes: `WG_CANDIDATE_IDENTITY_IN_USE` (409) и `WG_CANDIDATE_IDENTITY_INSPECTION_REQUIRED` (503). UI должен объяснять необходимость отдельной peer identity или явного cold flow; не показывать «проверено». Общий Manager уже не делает live Rollback после Canary rejection; regression `TestWGManagerSamePeerProbePreservesCommittedLKG` проверяет ProbeCandidate на committed WG.
2. **CRUD.** Один private `wireguardprofile.New(<absolute data-root>/wireguard-profiles)`; `List(ctx) -> []Metadata`, `Get(ctx,id) -> Profile`, `Put(ctx,id,name,config,expectedRevision) -> Metadata`, `Delete(ctx,id,expectedRevision) -> error`. Adapter `Profiles` принимает этот Store напрямую. Proposed API: `GET /wireguard/profiles`, `PUT /wireguard/profiles/{id}` с `{name,config,expected_revision}`, `DELETE /wireguard/profiles/{id}` с точным `expected_revision`. Обычный ответ — только `Public()` metadata; `Config()` не сериализовать/логировать. `Verification=syntax-only` не считается пригодностью. `main` зарезервирован для legacy engineconfig; остальные ID только `ValidID`. Create требует отсутствия ID и пустого expected revision; replace/delete — точной непустой revision; `ErrRevision`→409, `ErrForeign` сохраняет чужой файл.
3. **Владение/guard API.** Auth/CSRF, текущие CAS/Stop/SafeMode/recovery fence и общий operation gate проверяются приложением. Под тем же gate отклонять PUT-replace/DELETE профиля, на который ссылается active runtime, LKG/rollback snapshot, queued/in-flight transaction или выбранный резерв. Сам Store не знает app references и не заменяет эту проверку. Не выполнять implicit Stop ради DELETE и не допускать TOCTOU между проверкой references и Store mutation.
4. **Выбор/резервы.** План сохраняет `Resolved="wireguard:<id>"`; engine/adapter остаётся `wireguard`. Единственный runtime допускает один selected profile ID на план. Snapshot фиксирует named ID+revision, Stage/Activate/Commit сверяют неизменность. Для candidate reserve evidence нужны profile ID/revision, проверенный endpoint, WAN tuple/network epoch, проверенный service scope, probe time/expiry. Metadata или старый handshake не создают fresh evidence. Резерв с тем же client public identity активного peer не проверяется параллельным Canary; отказ не отравляет резерв.
5. **DNS.** Подключать `WARPWireGuardAdapter.EndpointResolver` типа `func(context.Context, string) ([]netip.Addr, time.Time, error)`. Expiry — реальный минимум TTL адреса и всей CNAME-цепочки; ноль означает noncacheable, поэтому resolve повторяется перед Canary/Activate/Reconcile. Возвращать только bounded полный ответ, ошибка/пустой/private/mixed-private answer отклоняются. Без настоящего TTL callback оставить zero expiry; fixed TTL системного resolver не добавлять. `ErrWGEndpointChanged` требует новой review/candidate транзакции и сохраняет нынешний LKG; нельзя переписать endpoint/pin при чтении статуса.
6. **Интеграционная приёмка.** Координатор запускает Linux race/vet/full gate и оба native теста, затем проверяет busy/Stop/CAS/expiry/WAN через настоящий app HTTP. Открытый journal/recovery fence и отсутствие общего LAN/DNS executor сохраняют текущие блокировки.

Следующая крупная вертикаль ожидает review координатора. Эта передача завершает локальную реализацию запрета/регрессий и подготовку native стенда, **не объявляет D04/D05 аппаратно принятыми**.
