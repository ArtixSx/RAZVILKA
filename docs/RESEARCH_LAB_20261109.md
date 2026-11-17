# Исследование и лабораторные проверки, 2026-11-09

Последняя контрольная точка16.11: [результаты492e813b и CPU-профиль4e83](measurements/2026-11-16/README.md#контрольная-точка-492e813b).
Восстановление пары и public modern rollback подтверждены отдельно от DNS,
NFQWS2 и Mihomo race ACK. Историческая reader4 библиотека закреплена за
`4cc9f869974713c9cebd833fccca383c03c102b7`, MIT; её исходники извлечены вне
production tree из проверенного source archive. Единственный добавленный
fixture entrypoint собирается против неизменённой старой библиотеки.
Реальные receipt4/pending5/terminal4 проходят старый Current/RequiredReadVersion;
архивная evidence-проверка намеренно моделируется, old main/router не заявляется.

```sh
go build -tags razvilka_historical_reader_fixture -o /tmp/offline-reader4-probe ./cmd/offline-reader4-probe
# Previous command runs inside the pinned historical source with the copied entrypoint.
# Next command runs inside the current source.
RAZVILKA_HISTORICAL_READER4_PROBE=/tmp/offline-reader4-probe go test -count=1 -v ./internal/selfupdatejournal -run '^TestPairedOfflineRetryActualHistoricalReader4$'
```

Старые версии/лицензии для будущего fresh GitHub сохранены отдельно: восемь
полных source archives с Git blob/tree и SHA256-проверкой. Это подготовка
воспроизводимости; архив не разрешает переход версии и не заменяет actual
software/router acceptance. Новый репозиторий пока не создан.


Владелец лаборатории и `cmd/nodeeval`: lab_sources; интеграция: Root.
База RAZVILKA: `0e2db5ab2120b20e249e3da7a8e861b558506550`.
Это приложение к [основному roadmap](ROADMAP.md), не отдельный план выпуска.

## Первая волна: закреплённые исходники

Получены shallow clones отдельно от production tree:
`C:/RAZVILKA-research-20261109/sources`. Полный локальный manifest с SHA256
лицензий: [sources-manifest.json](measurements/2026-11-09/research/sources-manifest.json).
Дата проверки — 2026-11-09. Изменения default branch не подменяют эти SHA.
Ни код, ни бинарники внешних проектов в поставку RAZVILKA не добавлены.
Использованы собственная реализация измерений и общая идея ограниченного context.

| Источник и закреплённый файл | SHA | Лицензия | Ветка |
|---|---|---|---|
| [blackbox_exporter](https://github.com/prometheus/blackbox_exporter/blob/b8fb49f909bc72dd7458e606309a03ebfb3c6e0b/prober/http.go) | `b8fb49f909bc72dd7458e606309a03ebfb3c6e0b` | Apache-2.0 | `master` |
| [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime/blob/882a9130ed21938b9c40974e83fc5f588ddfde7b/pkg/reconcile/reconcile.go) | `882a9130ed21938b9c40974e83fc5f588ddfde7b` | Apache-2.0 | `main` |
| [mihomo](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/adapter.go) | `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` | GPL-3.0 | `Meta` |
| [nfqws2-keenetic](https://github.com/nfqws/nfqws2-keenetic/blob/0cdd3103ecbb47ccb5d76e3dbbfdb4cbb67a7d10/etc/init.d/common) | `0cdd3103ecbb47ccb5d76e3dbbfdb4cbb67a7d10` | MIT | `master` |
| [sing-box](https://github.com/SagerNet/sing-box/blob/8295e4910f14d3041c948d2ad74bf3af384a064d/protocol/group/urltest.go) | `8295e4910f14d3041c948d2ad74bf3af384a064d` | GPL-3.0-or-later; naming/association restriction in LICENSE | `testing` |
| [tailscale](https://github.com/tailscale/tailscale/blob/62d055f4c38b610d63a8cee7fa4a7e65b01564eb/net/netcheck/netcheck.go) | `62d055f4c38b610d63a8cee7fa4a7e65b01564eb` | BSD-3-Clause | `main` |
| [toxiproxy](https://github.com/Shopify/toxiproxy/blob/49299d8838525126e09c85ebe0ba89940a3261e5/toxics/timeout.go) | `49299d8838525126e09c85ebe0ba89940a3261e5` | MIT | `main` |
| [v2rayN](https://github.com/2dust/v2rayN/blob/f07e3dc41511a196f8ab563bcd2a16d1310ca8dd/v2rayN/ServiceLib/Services/SpeedtestService.cs) | `f07e3dc41511a196f8ab563bcd2a16d1310ca8dd` | GPL-3.0 | `master` |
| [Xray-core](https://github.com/XTLS/Xray-core/blob/af8f9673afe8533390e0200637ad30508de803a5/app/observatory/burst/ping.go) | `af8f9673afe8533390e0200637ad30508de803a5` | MPL-2.0 | `main` |
| [xray-knife](https://github.com/lilendian0x00/xray-knife/blob/a579d42d2ca2b40293c20db0353d39ad4495066b/pkg/http/parsed.go) | `a579d42d2ca2b40293c20db0353d39ad4495066b` | MIT (embedded engines retain their licenses) | `master` |

## Механизм → существующая реализация → проверенная дельта

| Источник | Сопоставление с RAZVILKA и решение | Проверка / цена / владелец |
|---|---|---|
| Xray burst ping | Tagged dial и HTTP timeout; `MeasureDelay` сам не проверяет ожидаемый HTTP status. ExactNodeChecker уже проверяет service verdict отдельно. Не заменять его observatory delay. | Глубоко прочитаны `ping.go`, `healthping.go`; bounded readiness context реализует probe_performance. Никакой новой runtime-зависимости. |
| Mihomo | `HealthCheck.check` использует `singleDo`, `errgroup.SetLimit(10)`; `URLTest` возвращает delay независимо от `satisfied` expected status. Exact checker gate уже ограничивает конкуренцию, но Mihomo — отдельный lifecycle. | Изучены `adapter/provider/healthcheck.go`, `adapter/adapter.go`. Пул движков отложен до сравнимых cold/repeated native данных, лимит10 не переносится на роутер. |
| Blackbox Exporter | `roundTripTrace` разделяет DNS/connect/TLS/response на каждый redirect. Checker уже имеет стадии; nodeeval их терял при JSONL выводе. | Исправлено: закрытый список ID/status/duration, максимум32, wall/prep/candidate-wait. Тесты redaction/cleanup/следующего кандидата; lab_sources. Фазовые HTTP traces не приписаны имеющимся грубым стадиям. |
| Toxiproxy | TCP timeout/latency с cleanup позволяют воспроизводить сбои; не моделируют UDP/NFQUEUE. | Собран и запущен вместе с native Xray на Windows loopback, см. ниже. Только лабораторная зависимость. |
| v2rayN | Отдельные Tcping/RealPing, core/batch и `finally` cleanup. RAZVILKA также различает transport и service, сохраняет ownership. | Изучен SpeedtestService; desktop batching не принят без ресурсов/отмены/изоляции на роутере. No demonstrated missing batch correctness. |
| sing-box | URLTestGroup имеет idle timeout, batch, сохранённые результаты. RAZVILKA использует freshness и first usable; cached delay не доказательство service. | Исследован `protocol/group/urltest.go`; testing branch не объявлена stable. Копирование GPL и naming условий не требуется для общей идеи. |
| xray-knife | `ParsedLink` разбирается один раз для semantic dedup/prescan/examiner. RAZVILKA уже хранит canonical node identity. | Исследован `pkg/http/parsed.go`; обязательность второго parse как bottleneck пока не доказана. Не менять config identity на endpoint dedup. |
| tailscale | `GetReport` ограничивает весь netcheck budget, отдельные STUN/ICMP/HTTPS бюджеты. | Изучен `net/netcheck/netcheck.go`. Идея общего deadline применима, константа5s не переносится на полный apply/LAN/cleanup; Root/probe. |
| nfqws2-keenetic | Init/common и netfilter workflow — материал для platform-specific retry и applied-state audit. RAZVILKA имеет ownership/rollback. | Исходники/лицензия получены; Windows не имеет Linux namespace; отдельный disposable Linux runner уже использован: core/HTTP/closing PASS, полный LAN workflow пока не принят. См. [lifecycle evidence](measurements/2026-11-09/research/lifecycle/README.md). Router acceptance требует аппаратуры; installer на host не запускается. Root владелец. |
| controller-runtime | `Reconcile` различает terminal error, backoff и RequeueAfter; desired/actual уже есть в reconciler RAZVILKA. | Изучен контракт `pkg/reconcile/reconcile.go`. Новая Kubernetes dependency отклонена: цена несопоставима с необходимой общей идеей. Доказанного нового reconciler дефекта в этой волне нет. |

## Native Windows: контролируемый VLESS TCP и сбойный канал

Собраны из указанных SHA:

```powershell
$go = 'C:/Projects/RAZVILKA/tools/go/bin/go.exe'
Set-Location C:/RAZVILKA-research-20261109/sources/Xray-core
& $go build -o C:/RAZVILKA-research-20261109/bin/xray.exe ./main
Set-Location C:/RAZVILKA-research-20261109/sources/toxiproxy
& $go build -o C:/RAZVILKA-research-20261109/bin/toxiproxy-server.exe ./cmd/server
```

Сборка обоих PASS; автоматически выбран Go1.27.0, требуемый их go.mod.
RAZVILKA сохраняет свой Go1.26.5. Xray сообщает26.10.31 и commit af8f967.
Запуск из checkout RAZVILKA:

```powershell
python cmd/nodeeval/lab_loopback.py --xray C:/RAZVILKA-research-20261109/bin/xray.exe --toxiproxy C:/RAZVILKA-research-20261109/bin/toxiproxy-server.exe --output C:/RAZVILKA-research-20261109/loopback-components.json
```

Все listeners привязаны к127.0.0.1, порты выделяются динамически, используются
одноразовые конфигурации и публичный fixture UUID. Скрипт завершает только свои
процессы и проверяет закрытие своих listeners. Маршруты/DNS/firewall host не меняет.
Это реальный engine/transport/HTTP-body опыт, **не** ExactNodeChecker, TLS,
production selection, сервис Telegram, TUN, LAN, NFQUEUE или UDP.

Первый запуск выявил важное различие версии: в новом Xray freedom `finalRules`
по умолчанию блокируют private destination после VLESS inbound, с задержкой
blackhole (в логе конкретного опыта51s). Открытый TCP работал, HTTP не проходил.
Для fixture добавлено только разрешение TCP к127.0.0.1/32 и точному порту его
HTTP server. Production-конфигурации и защитные правила не изменялись. Это не
основание автоматически обновлять production Xray26.3.27 до новой версии.

| Сценарий | Первый HTTP запрос, мс | Повторы, мс (N3) | TCP | Ожидаемое тело |
|---|---:|---|---|---|
| Valid UUID | 16.290 | 1.519 / 13.747 / 15.574 | открыт | PASS4/4 |
| Wrong UUID | 16.557 | 30.433 / 15.874 / 1.102 | открыт | отказ4/4 |
| Valid + Toxiproxy downstream latency100ms | 102.584 | 101.876 / 102.393 / 122.269 | открыт | PASS4/4 |

Client process→TCP-ready: 513.684 / 526.127 / 507.990ms; это нижний readiness
уровень, не service proof. Cleanup с завершением процессов, shutdown HTTP и
проверкой закрытых портов:14702.575ms; Windows connect-refused latency входит в
эту величину. Все5 owned процессов reaped, listeners закрыты. [Полный JSON](measurements/2026-11-09/research/loopback-components.json) содержит SHA256 бинарников; [build info](measurements/2026-11-09/research/native-builds.json) фиксирует Go и vcs revision.
Предыдущая проверка закрытия портов с1.5s timeout честно завершилась `cleanup-unconfirmed`: Windows может отвечать connection-refused позже. Итоговый запуск ждёт до3.5s и требует именно refusal, не любой socket error. [Промежуточный отказ](measurements/2026-11-09/research/loopback-cleanup-unconfirmed.json) сохранён.
Динамический port handoff имеет race: ошибка bind/readiness прекращает опыт, не даёт права завершать чужой PID. API Toxiproxy использует opener без ambient HTTP proxy. Частичный результат сохраняется при ошибках, тело ограничено64KiB. Здесь нет
сравнения оптимизации RAZVILKA: это причинный контроль задержки и ложного TCP
успеха. До/после исправления checker измеряется отдельно Root/probe_performance.

## Воспроизведение полного checker на Linux

Существующий `scripts/check-node-native-performance.sh` запускает настоящий
Xray, TLS/DNS/paired egress, Check, App queue и cleanup в `unshare --net --mount`.
Для сравнения новой правки запускать одинаковый проверенный Xray26.3.27 и
скрипт на базе0e2db5ab и текущем commit. Сравнивать `current-reuse` между этими
двумя builds: встроенный `historical-request-reference` — контроль старого
дублированного запроса, **не** baseline этой новой правки. CSV содержит cold
first-check и12повторов по live/dead-service/cancel/dead-node, stage JSON и
resource observations. Сумма перекрывающихся стадий не равна wall time.

Windows `wsl --list --verbose` не нашёл установленных дистрибутивов. Поэтому
local native Linux/NFQUEUE/IP policy PASS не заявлен. Root готовит отдельный CI
lab; его результаты относятся к своему SHA и не подтверждают router profile.
Аппаратная приёмка требует NC-1812/KeeneticOS5.01.C.6.0-1/Entware и отдельного
LAN-клиента, утверждённого scope/exclusions/native VPN и явной авторизации
изменения действующего роутера. Эти условия не блокируют unit/loopback/CI работу.

## Проверки изменения nodeeval

`go test ./cmd/nodeeval -count=1`: PASS (1.323s).
Новый тест включает cleanup failure с nil Go error, запрет следующего кандидата,
redaction сообщений/неизвестных ID/status, отрицательных длительностей и bound32;
второй тест проверяет wait второго кандидата. Независимый reviewer одобрил diff.
При первоначальном параллельном cold build старый тест20ms deadline не успел
вызвать checker (FAIL); повтор этого и нового теста3раз PASS, полный повтор PASS.
Это не скрывается как стабильный нагрузочный benchmark.


## Native Mihomo: positive delay и ожидаемый статус — разные данные

Собран Meta `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` на Go1.26.5:

```powershell
Set-Location C:/RAZVILKA-research-20261109/sources/mihomo
& C:/Projects/RAZVILKA/tools/go/bin/go.exe build -o C:/RAZVILKA-research-20261109/bin/mihomo.exe .
# Из checkout RAZVILKA:
python cmd/nodeeval/lab_mihomo.py --mihomo C:/RAZVILKA-research-20261109/bin/mihomo.exe --xray C:/RAZVILKA-research-20261109/bin/xray.exe --output C:/RAZVILKA-research-20261109/mihomo-components.json
```

Mihomo запускался с единственным VLESS outbound `fixture-vless`, MATCH на него,
TUN/DNS/geo auto-update выключены, controller/mixed listener только127.0.0.1.
Peer — native Xray указанной версии; endpoint — локальный HTTP server с204/503.
`/proxies/fixture-vless/delay?expected=204` сопоставлялся с URL-specific health
и отдельным HTTP GET через mixed listener (absolute request, без OS proxy bypass).

| Ожидаемый сценарий | API HTTP | delay, N3 | global alive | URL alive | Независимый HTTP через тот же VLESS | Strict PASS |
|---|---|---|---|---|---|---|
| healthy | 200 | 1 / 1 / 1ms | true | true | 204 / 204 / 204 | 3/3 |
| unavailable | 200 | 1 / 1 / 1ms | true | false | 503 / 503 / 503 | 0/3 |

Полный [mihomo-components.json](measurements/2026-11-09/research/mihomo-components.json)
фиксирует все6строк, binary SHA256, controller+listener-ready526.071ms и подтверждение
cleanup двух owned процессов/listeners/временной папки. Это воспроизводит код
`adapter/adapter.go:URLTest` и `hub/route/proxies.go:getProxyDelay`: верхний alive
отражает отсутствие transport error, URL-specific alive учитывает expected status.
Доказано на actual engine, а не только выведено из README.

Сборка без release ldflags выводит `Mihomo Meta 1.10.0 ... unknown time`;
идентичность определяется SHA256 и чистым vcs.revision в [native-builds.json](measurements/2026-11-09/research/native-builds.json),
а не этим label. RAZVILKA не получила права допускать путь по delay или global alive.
Этот опыт не заявляет production Mihomo lifecycle/route/LAN готовность и не
подменяет полную service/TLS проверку. Внешняя новая dependency в продукт не добавлена.

Лабораторные скрипты сохраняют частичный JSON с фиксированным failure code;
`finished` сбрасывается при любом сбое, а temporary cleanup выполняется после
завершения процессов (на Windows Mihomo держит свои файлы открытыми). Неуспешный
cleanup не выдаётся за PASS. Параллельные запросы/namespace/ресурсы роутера здесь
не измеряются. Пины engine не обновлены в production.


## Повторная проверка ledger и минимальная приёмка оставшихся фаз

Повторно проверены все 10 строк: локальный HEAD, чистота checkout, существование
закреплённого файла, SHA256 каждой LICENSE и удалённый `refs/heads/<branch>` через
`git ls-remote`. Все совпали с manifest на 2026-11-09. У v2rayN актуальная ветка
`master`; Mihomo намеренно закреплён на `Meta`. В sing-box LICENSE подтверждены
GPL-3.0-or-later **и** отдельное ограничение имени/подразумеваемой связи с проектом;
это не записано как обычная лицензия GPL без дополнительных условий.

Ниже — воспроизведение имеющимися средствами, не новый roadmap. Команды Linux
предназначены исключительно для disposable host с Go1.26.5, namespace/mount
правами и закреплёнными артефактами. Подготовка URL/SHA256/пакетов и точные
команды sudo уже находятся в [.github/workflows/research-probes.yml](../.github/workflows/research-probes.yml).
Не подставлять Windows research Xray26.10.31 вместо reviewed native26.3.27.

| Фаза / сценарий | Существующая команда или документ | Минимальный критерий / статус этой лаборатории |
|---|---|---|
| DNS, TLS trust, HTTP через точный Xray | `RAZVILKA_XRAY_NATIVE=/usr/local/lib/razvilka-fixtures/xray sh scripts/check-xray-native.sh` | Actual owned client, проверенный TLS, paired egress, hostname и literal-IP service path, cleanup. В Windows component опытах **не выполнено**; Linux CI оценивается по конкретному SHA, PASS не предполагается. |
| Ошибочный transport/TLS name/path XHTTP | Предыдущая команда с `RAZVILKA_XHTTP_NATIVE=1` | Неверный материал отвергнут, правильный снова проходит; нет подмены transport. **Не выполнено** этой Windows лабораторией, это доступная software задача Linux CI. |
| Общий Check, очереди и cleanup до/после | `RAZVILKA_NODE_PERF_ALGORITHM=current-reuse RAZVILKA_NODE_PERF_OUTPUT=/tmp/research-output RAZVILKA_XRAY_NATIVE=/usr/local/lib/razvilka-fixtures/xray sh scripts/check-node-native-performance.sh` | Одинаковые baseline/candidate, binary, endpoints, live/dead-service/cancel/dead-node, cold отдельно от повторов; исходные CSV/resources и App HTTP readback. Результаты Root-owned workflow отдельно, не обещание ускорения. |
| Mihomo service handler с TLS | `RAZVILKA_XRAY_NATIVE=/usr/local/lib/razvilka-fixtures/xray-node26.3.27/xray RAZVILKA_MIHOMO_ARCHIVE=/usr/local/lib/razvilka-fixtures/mihomo.gz sh scripts/test-mihomo-probe-native.sh` | Обе original native service/HTTP проверки должны завершиться PASS без SKIP; status503/delay опыт выше этого не заменяет. Проверка включена в отдельный Linux CI job. |
| DNS ownership и настоящий путь domain scope в Linux | `scripts/test-domain-original-native.sh`; варианты DNS_ONLY/DNS_DETACH/DNS_COEXISTENCE заданы непосредственно в script | Новый namespace, exact scope/exclusions, отсутствие чужих mutation, подтверждённый retirement. Linux2924 original successor preparation recovery clean/2partialACK PASS (diagnostic30); strict12 GEN1 publication FAIL. Полные исходные результаты в [lifecycle журнале](measurements/2026-11-09/research/lifecycle/README.md). Tagged platform classification не становится допуском ordinary router Apply. |
| Managed NFQUEUE с LAN fixture | `sh scripts/test-managed-probe-lan-native.sh` | Pinned archive/member hashes, реальные namespace packet/FD/cleanup доказательства; требования пакетов/прав в delegated script `test-managed-probe-native.sh`. Disposable Linux core/HTTP/closing выполнены; LAN/native race результаты и следующие исправления учитываются отдельно в lifecycle журнале, не закрыты успехом компонентного probe. |
| Реальный LAN-клиент и точный router profile | [ROUTER_ACCEPTANCE_RU.md](ROUTER_ACCEPTANCE_RU.md) | Отдельный физический профиль и явная авторизация стенда, before/after scope/native policies/маршрута, оригинальный владелец, counters/packet path, shutdown/recovery. **Не доказано** PC/CI результатами. |

Отдельное измерение DNS/connect/TLS/TTFB/body на каждый redirect пока не добавлено
в exact checker: существующие coarse stages и HTTP-status lab этого не дают.
Blackbox `httptrace` — исследованный образец, а не выполненная интеграция. Это
**не подтверждённая software возможность**, а не аппаратный блокер. Строгие
DNS/TLS/service проверки нельзя смешивать с будущими отдельными duration полями.

Для уже авторизованного LAN стенда готовый read-only клиент:

```sh
go build -trimpath -o telegram-soak ./scripts/telegram-soak
./telegram-soak --lan-client 192.168.1.100 -duration 1h -interval 30s > telegram-lan-soak.json
```

Адрес здесь пример: нужен существующий адрес отдельного клиента. Этот sampler
не меняет сеть и не выбирает VLESS; он требует предварительно проверенный
Root-ом route/owner и не доказывает путь сам. Сначала принять профиль по аппаратному
сценарию, потом запускать полное окно. MTProto/media/voice не следуют из HTTPS;
опция `-mtproto` добавляет лишь unauthenticated resPQ, не account/server auth.
Ни часовой прогон, ни изменение действующего роутера здесь не выполнялись.


## Linux held-FD mount identity: адресное исследование 09.11

Профиль strict DNS показал значительную цену свежих procfs-наблюдений. Старый
`xraySelectedTCPProc.mountID` каждый раз открывал fdinfo, проверял procfs/type,
читал mount ID и закрывал descriptor. Все вызовы Current и проверки scope
остаются необходимыми; заменяется только способ получить тот же mount ID.

Первичные источники Linux v6.1, SHA
`830b3c68c1fb1e9176028d02ef86f3cf76aa2476`:
[fs/stat.c](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/fs/stat.c#L222)
и [fs/proc/fd.c](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/fs/proc/fd.c#L57).
Оба публикуют исходный `mnt_id` удерживаемого file path. Анализ GPL-2.0 исходников;
чужой код не копировался. Локальная копия двух исходников находится вне проекта
в `C:/RAZVILKA-research-20261109/sources/linux-v6.1-mount-id`.

Новая реализация использует существующий golang.org/x/sys v0.47.0:
STATX_MNT_ID + AT_EMPTY_PATH для исходного FD, свежий syscall при каждом вызове,
проверка mask/nonzero и отмены. STATX_MNT_ID_UNIQUE не используется. При отсутствии
поддержки или запрете syscall выполняется прежний защищённый fdinfo-путь;
неожиданные ошибки не становятся успехом. Остальные proc/root/child/type и
mount checks сохранены; новых зависимостей и cache нет.

Независимое code review одобрено; native parity, bind поверх того же inode,
замена исходного FD, ошибки/отмена и normal/race ещё требуют CI. Native N1000
сравнивает fdinfo, statx и принудительный ENOSYS fallback отдельно от полного
DNS сценария. На реальном NC-1812 с ядром4.9 будет прежний fallback: ускорение
устройства этой правкой не заявляется. Это одиннадцатый адресный источник,
а не новая обязательная runtime-компонента.


Ограничение старого ядра: прежнее тело fdinfo-reader сохранено, но перед ним
добавляется одна неуспешная попытка statx на вызов. Принудительный ENOSYS в
микроизмерении не включает цену этого syscall. Поэтому неизменность стоимости
на ядре4.9 не утверждается; отрицательный capability cache не добавлялся.


Адресное продолжение: тот же syscall применён в `netidentity.audit.mountID`.
В сохранённом CPU-профиле bfc strict12 этот helper занимал1.09с (8.80%),
а Xray-specific mountID —0.42с (3.39%). Все исходные `mountsMatch`, `stable`,
проверки content FD и полные mount-layout наблюдения до/после callbacks остаются.
Новые native tests проверяют настоящую подмену fdinfo bind-mount поверх того же
inode внутри `Provider.WithCurrent`: closing должен отказать; после unmount
новый Current должен пройти. Для порта также требуется сравнение N1000 и
normal/race; CPU-профиль объясняет выбор участка, а не доказывает ускорение.


### Проверенная и отклонённая идея: ETXTBSY вместо SHA

Исходники того же pinned Linux6.1 проверены отдельно: локальный i_writecount
не является неизменяемой печатью содержимого удерживаемого FD. При смене exec
write denial прежнего образа снимается, хотя PID/start/group и sole Wait могут
остаться теми же; overlayfs и NFS дополнительно ограничивают такое допущение.
[Источники и независимое ревью](measurements/2026-11-09/research/reviewed-manual-wave/exec-write-independent-review.json).
Это вывод из исходников, не выполненный native bypass эксперимент; ctime
может отвергнуть конкретную модификацию раньше SHA. Проверки полных байтов не
заменялись. Чужой GPL-код не копировался, runtime dependency не добавлялась.


### 16.11: проверка возможности сократить IP version children

Решение: оставить фактический `ip -Version` при каждом Check. В Ubuntu
6.19.0-1ubuntu1.1 функция версии читает `/proc/self/maps` и извлекает суффикс
из первого pathname с `libbpf.so.`; fallback может дать ожидаемый stdout и
exit0, но warning в stderr остаётся отказом. SHA файлов/загрузчика не заменяет
это наблюдение конкретного дочернего процесса. Изучен pinned upstream
[dac1bc6021693902b25a961227e289791e429b91](https://github.com/iproute2/iproute2/blob/dac1bc6021693902b25a961227e289791e429b91/lib/bpf_glue.c#L33-L78),
GPL-2.0; код не переносился.

У Entware4.4.0-11 version branch статична по upstream
[92a0236a3cdf3438000834121b7ea8a09f1f52b1](https://github.com/iproute2/iproute2/blob/92a0236a3cdf3438000834121b7ea8a09f1f52b1/ip/ip.c#L158-L234)
и [рецепту541289a115d32d1ab044e87608bc0ca6b2154ee9](https://github.com/Entware/Entware/blob/541289a115d32d1ab044e87608bc0ca6b2154ee9/package/network/utils/iproute2/Makefile),
GPL-2.0. Но текущий опубликованный ELF `2a83e983…` не совпадает со старым
stock pin `cce8d3fa…`; номер пакета не доказывает идентичность сборки.
Кроме того, нынешний контракт отдельно требует подлинные Start/Wait и пустой
stderr. Уже существующий native тест индуцирует IP Start EAGAIN внутри того
же scope после первого годного batch и требует отзыва retained xtables fact.
Повтор известной строки пропустил бы этот отказ. Из4011 IP Starts следует
не менее8022 metadata attempts, но это число вызовов, не доля времени.

Полные hashes архивов/ELF, зависимости, лицензии и callgraphs сохранены в
`C:/Projects/RAZVILKA/artifacts/entware-review-2026-11-16.txt`, раздел
«Исследование ip -Version». Новые профили Entware исследуются отдельно;
старые guards и буквальный argv сохранены. Подмена `-Version` на `-V`
проходит ту же ветку и не ускоряет проверку.

### Стадии одного HTTP обмена

Дополнительно изучен исходник поставляемого Go1.26.5
`src/net/http/httptrace/trace.go` (BSD-style Go license): WithClientTrace
составляет hooks, callback может исполниться асинхронно после возврата запроса.
В4979 optional telemetry использует этот стандартный API, mutex и закрываемый
bounded snapshot; чужой код не копируется. Продолжение существующего подхода
blackbox-exporter к разделению сетевых стадий, без переноса его verdict в RAZVILKA.

CLI nodeeval получает отдельные local resolver / SOCKS / TLS / TTFB / body
наблюдения, привязанные к текущему node/service/profile result. Redirect —
отдельный RoundTrip; multiple internal dial/TLS явно не изображаются одним
измерением. Raw URL/error/body/certificate не попадают в JSON. В4979/1a50 native queue
включает эти наблюдения только в отдельном CPU-profile проходе; обычные paired
samples той ревизии не получают telemetry overhead. Вeb1 это изменено ниже. Существующие service predicates,
scope guards, таймауты и cleanup сохраняются. Нужны адресные normal/race и
original pinned SOCKS/TLS проверки нового SHA; это не аппаратное доказательство.


### Целостный classic inventory вместо отдельных table children

Изучены официальные Netfilter iptables1.8.10/1.8.11, GPL-2.0-only;
исходные версии, архивы, SHA и точные функции сохранены в
[исследовании](measurements/2026-11-09/research/reviewed-manual-wave/classic-save-research.txt).
Source code не копировался. Два фиксированных save applets используют тот же
удерживаемый SHA-reviewed multicall image. Приватный nonblocking xtables lock
остаётся удержан между двумя дочерними процессами; -w и альтернативного lock нет.
Строгий parser сохраняет набор/порядок таблиц, цепочки, policy и rule bytes;
счётчики и timestamps отсутствуют в прежнем -S и не выдаются за scope proof.
Внешние fresh image/bookend/source/metadata/cleanup проверки сохранены.
После частичной ошибки нет fallback к более слабому наблюдению.

Это узкий Ubuntu1.8.11 fast path и явно классифицированный native1.8.10/1.8.11
стенд. Stock NC-1812/1.4.21 продолжает прежний serial -S. Raw save headers и
counters входят в неизменный1MiB лимит; крайний по размеру inventory может
получить более ранний отказ. Native parity/6pairs/lock mutation/cancel нужны
до заявления об ускорении; аппаратная готовность не следует из этого порта.

Отклонены параллельные -S: официальный xtables берёт общий LOCK_EX|LOCK_NB и
может вернуть новый exit4 при одновременном чтении. Также отвергнут переход
ReadDir→Readdirnames: исчезает проверка lstat при DT_UNKNOWN между bookends.
Вместо него ddaa8823 оставляет свежий Fstat под исходным os.File RawControl FD
reference lock и EINTR loop, переиспользуя только обнулённый scratch, не metadata.
Allocation benchmark и real concurrent Close parity ещё должны пройти CI.

Actual native binary —1.8.10, а production Ubuntu profile отдельно pinned1.8.11.
Identical save source не подменяет испытание actual1.8.11 artifact или stock роутера.


### Повторная парная проверка 1a50bf07

[Анализ182строк и raw](measurements/2026-11-09/research/ci-1a50bf07/paired-analysis.json)
проверяет SHA исходников, одинаковый Xray hash, verdict/cleanup и точные
service/profile/route identities. Baseline363f на том же runner, порядок фиксирован.
N12 repeated p50/p95мс: live313.427/334.199→224.543/227.401;
dead-service313.848/316.278→223.924/227.139; cancel274.007/277.347→184.391/188.019;
selected2 completion1440/1461→1261/1280. Первые samples сохранены отдельно.
Profile40.46wall/26.57CPUс: CheckWrite20.04с75.42%, hashRegularFile19.11с71.92%,
SHA-NI16.15с60.78%. Это вложенные CPU доли большого тестового controller image,
не lock wait, не production абсолютная стоимость и не основание убрать hashes.
Actual per-exchange observations находятся в profile/native-performance.log;
набор с профилированием не смешан с парным измерением.

Следующая App API/UI реализация собирает до32 обменов и в обычной проверке.
Поэтому следующие paired candidate samples включают стоимость штатной telemetry;
это отличается от1a50, где collector в App включался лишь в profile pass.
Не следует вычитать overhead или переносить результаты старого SHA автоматически.
Original invocation collector закрывается, произвольное поле checker затирается,
публикация происходит только после исходных resource/network/history/RecordCheck
проверок и проверки времени именно этого вызова. Данные не входят в CheckRecord,
ranking, capability или evidence. HTTP503 может иметь завершённый TLS/TTFB,
но остаётся отказом сервиса; canceled/foreign/earlier results не получают эти времена.

Fresh held Fstat normal/race и concurrent Close прошли на1a50;6samples median
808.1→731.8ns,208B/1allocation→0/0. Полный NFQ Apply ещё FAIL по deadline.
Classic-save6pair benchmark доe9 не дошёл: iptables запрещает DROP в nat;
fixture исправлен на RETURN в неподключённой цепочке. Это не production изменение
и не доказательство completed parity. Native1.8.10 != actual1.8.11/router.


### Уточнение actual xtables lock ABI

Native1.8.10 xshared.c при wait=0 использует blocking LOCK_EX и alarm(0);
1.8.11 использует LOCK_NB. Поэтому actual1.8.10 busy test с прежним-S ждёт,
а не немедленно возвращает4. D762 ограничивает только этот тест `-w1`/2с и
проверяет тот же удерживаемый inode;1.8.11 fixture остаётся без-w. Production
save lock по-прежнему собственный nonblocking, без изменений deadline/fallback.
Source-identical save output не означает одинаковые busy semantics двух ABI.
Fair serial/save comparison использует один original readonly observer с обеих
сторон; прежние0f equal74rows/20→4children подтверждают parity, но цифры
80–84→29–30мс пока предварительные из-за различавшихся wrapper bookends.


### Измеренный6df и следующая проверяемая реализация

[Paired182rows](measurements/2026-11-09/research/ci-6df3d753/paired-analysis.json):
live p50/p95 314.281/317.072→225.115/256.070мс; selected2 1445/1468→1261/1280мс.
Обычный candidate App уже включает новую telemetry; это сохраняет общий выигрыш,
но не изолирует её overhead. Cleanup101→11мс и все прежние verdict/identity/cleanup
assertions сохранены. Cold sample не cold OS cache; fixedorder ограничение остаётся.

Fair save1.8.10 normal/race: exact74rows,20→4children,44→12metadata; steady N5
80.696→28.465мс normal и108.845→38.093мс race. Cold sample0 отдельно88.405→28.559мс.
Package1.8.11-2ubuntu3 из официального Ubuntu pool содержит exact productionda62
ELF; libc>=2.42 требуетubuntu26.04. [Provenance](measurements/2026-11-09/research/reviews/iptables-1.8.11/)
сохраняет4deb hashes и distro patch series; это не воспроизводимая сборка пакета.
[Официальный GA runner](https://github.blog/changelog/2026-09-17-ubuntu-26-generally-available-and-latest-migration/)
позволяет отдельную actual1.8.11 проверку без подмены библиотек24.04 илиpins.

Mountinfo chunk4096/16K/32K: все варианты4reads/pair,5030bytes; median
103.342/104.521/105.533µs и30,000/54,576/87,344B/op. Гипотеза ускорения отвергнута,
production4096 оставлен. Pathname racepool2104ns/1216B, stack1454ns/0B; normal
1583/1603ns и0B — ускорение normal не заявлено.5cb переносит measuredstack,
сохраняя каждый fstatat/no-follow/error/metadata check; production parity нужен вновь.

Go1.26 os/exec→io.Copy→os.File.WriteTo→genericWriteTo достигает private output.ReadFrom.
866 переиспользует только очищаемый32KiB scratch, сохраняя output.Write/limits,
WriterTo precedence, child Start/cancel/soleWait. Actualchild/alloc normal/race
измерения ещё требуются. [Исходники/контракт](measurements/2026-11-09/research/reviews/output-reader-source-audit-20261109.md).
IP version children намеренно НЕ убираются: get_libbpf_version читает /proc/self/maps;
потери readonly context нет. [Аудит](measurements/2026-11-09/research/reviews/nfq-ip-version-fanout-audit-20261109.md).

`cad54dba`: mountinfo unescape возвращает исходную immutable строку без builder,
если в поле нет обратного слеша. Escaped decoder и точная byte/NUL/invalid UTF-8
семантика сохранены; оба локальных потребителя не удерживают substring.
Независимое source review PASS; normal/race parity и отдельный actual-corpus
before/after decoder benchmark назначены следующему CI. Это не результат
свежего kernel read и не доказательство ускорения маршрута.

Сравнение между runs ubuntu-latest учитывает миграцию24.04→26.04; для
выводов о скорости используются пары одного host/образа, а не разность wall time
между разными CI. Dedicated1.8.11 закреплён на26.04.


### Проверка4cc9f869 и очередная интеграция

Paired363f→4cc:182rows/verdicts/cleanup/exactbinary PASS. Повторные N12:
live p50/p95 319.681/323.445→229.028/231.712мс; selected2 server completion
1497/1522→1300/1313мс. Fixed order/samehost; first samples отдельно, не cold OS cache.
Все4 Mihomo native PASS. Sameboot42642470617: normal96.53с/race113.13с PASS;
normal retirement/history/completed ACK PASS; normal terminalpair и5race cuts
FAIL120с. Inclusive absence80calls/80.54с и source-current245/34.15с перекрываются.
Reviewed e75 оборачивает только hardcoded absence в существующий original tool
readonly scope, сохраняя Current/process/interfaces/kernel/Current, full cold-read
SHA и каждый IPVersion. Callback count/ошибка/identity и frozen association
проверяются до возврата; эффекты и публикации вне scope. Скорость ещё не измерена.

4cc coordinator actual3/3: на одинаковых завершённых стадиях DNS firstanswer132→126,
beforeStop138→132, joined143→137 SHA; все460Current сохранены. Strict12 ещё FAIL.
Mount unescape actual48plainfields:2445→385.7ns,896→0B,72→0alloc; decoder-only.
Production parser сохраняется; 4d310544 тестирует FieldsSeq candidate на exact
Unicode/escaped grammar, limits и полном actual corpus прежде решения о promotion.

OutputReader actualchild normal82976→27896B/op, но6.424→6.589мс (+2.6%,3x×3);
race82656→38882B/op и~1.033с с runtime exit delay. Pure copy32840→88B/op normal.
Это подтверждённое сокращение allocations, не ускорение полного маршрута.
Managed profile отдельно показал nfqws2ManagedFilesCurrent io.Copy46.94MB; a6feb69d
заменяет только scratch полного SHA-чтения, сохраняя реальныеbytes/limits/FD/path/
close checks. Собственный paired actualfile benchmark назначен nextCI.

Actual1.8.11 exact4cc preflight отказал: installed same-version member bytes
не совпали с pinned archive. Возможная причина — Ubuntu amd64v3 variant; в failed
run variant не был напечатан, поэтому это inference. af305 + workflow устанавливают
ровно4verified baseline .deb на26.04, затем прежний полный preflight и public Acquire.
Public pair4cc обнаружил реальный fixture ABI gap: genuine oldinit требует -O,
которого нет в Ubuntu BusyBox. 1e4 копирует actual dpkg daemon после namespace guards,
проверяет >=1.20.6/--output и совпадениеSHA. Old init/argv не меняются; nextCI pending.
[Точные результаты](measurements/2026-11-09/research/lifecycle/4cc9f869/).


### Отрицательные измерения и фактические отказы60e0d4ba

FieldsSeq candidate не переносится вproduction: actual24line parser5363→6555ns
(другой paired runner5281→6573), хотя7296→3072B и26→2alloc. Audit16reserve
прошёл normal/race realcapture/sourceparity/actualFDclose/cancel/fallback>16;
48560→44240B/op и224→220alloc, время~311–312us без существенного изменения.
Reviewed e30cfec1 переносит только эту инициализацию; append fallback/каждыйFD/
все kernel reads/cleanup сохранены, stack placement не обещается.

60e: sameboot firstabsence FAIL, exact route207 read отсутствовал в observed ABI;
0cc сохраняет четыре исходные формы и проверяет native bytes+actual child exit.
Generic новая fixture неправильно private-mode, managed default не собирал нужный
dataplane.test; обе причины исправляются вfixture/build, productionguards unchanged.
Public source config schema1 Inspect нормализует без сохранения; header раньше
получал normalized fingerprint, а original guard видел rawtyped schema1. 7fb32e53
разделяет physical-source fingerprint и migration semantics, originalbytes/SHA retained.
Actual1.8.11 exactarchive install требует explicit --allow-downgrades; толькоdisposable4files.
Warm Mihomo110s failures послеcommit-adapter требуют сравнения с4cc наsamehost;
новый diagnostic baseline идёт послеcandidate, поэтому cache/order/noise сохранены
как ограничения. Не меняется ни110с, ни120с sameboot acceptance.
[Точные отчёты](measurements/2026-11-09/research/lifecycle/60e0d4ba/).

### Проверка 35797378 и продолжение 3b27bd6e

Общий CI 35797378 остановился на gofmt после успешных адресных тестов;
полные normal/race не запускались. Форматирование исправлено в 3b27bd6e,
его CI оценивается отдельно. Последняя полная общая проверка — 4cc9f869.

- Парная проверка VLESS (182 строки, один стенд): live p50/p95
  313.900/320.086→223.606/227.777 мс; selected-batch 1454/1465→1250/1263 мс.
  Verdict, identity, отмена и joined cleanup проверены. Это не WAN/LAN-приёмка.
- Настоящий iptables 1.8.11-2ubuntu3: public AcquireUbuntuLegacy, normal/race,
  74 одинаковые строки, lock/mutation guards PASS. Медиана пяти повторов
  57.252→20.439 мс (race 102.467→37.297), процессов 20→4. Все четыре архива
  и установленные байты проверены. Entware stock1.4.21 этим не подтверждён.
- Mihomo lifecycle, два Apply/Stop, восстановление baseline и normal/race
  bookends PASS. На одном runner кандидат 214.56 с, preserved4cc 210.61 с:
  ускорения нет. Manual/settlement превысили deadline, post-CAS остановился
  на sidecar-start до намеченного сбоя. В 3b27 добавлены фиксированные стадии
  диагностики без изменения ошибок, владения ресурсами и deadline.
- Same-boot parent normal/race и все пять normal ACK cuts PASS; race
  retirement/history PASS. Race completed.json не дошёл до ACK из-за
  route-process-unavailable; terminal transaction/global достигли 120 с
  при повторной проверке отсутствия ресурсов. Полная матрица не принята.
- NFQWS2 consumer и closing guards normal PASS; full-copy normal/race PASS:
  1 MiB normal 32952→184 B/op при близком времени полного SHA. Полный LAN/manual
  и race consumer FAIL. Quarantine и cleanup-only retry normal PASS; новое
  Apply не прошло. Защитные fences сохранены.
- StrategyLab pair/restored panel PASS. Public configured-old193 прошёл
  preparation, затем отказал на quiesce-network-provider. В 3b27 исправлен
  скрытый второй /proc mount частного стенда; production provider не менялся.
- DNS strict12 selected/canceled-ready FAIL; diagnostic30 все три recovery
  PASS. Новая проверка измеряет полное чтение pinned Xray блоками
  32/64/128/256 KiB. Production размер не изменён до измерения и ревью.

[Исходные результаты и SHA256](measurements/2026-11-09/research/lifecycle/35797378/)
и [парные измерения](measurements/2026-11-09/research/ci-35797378/) сохранены.
Аппаратная приёмка, выпуск и изменение действующего роутера не выполнялись.

### Проверка 3b27bd6e и следующая исправленная интеграция

Оба generic CI завершились: полный normal и race PASS, затем go vet обнаружил
копирование mutex в тесте structural input identity. Это исправлено созданием
отдельного объекта с теми же полями; assertion сохранён. Shell/UI/cross-build
шаги на 3b27 не запускались. Следующий gate выполняет тот же go vet раньше
полных тестов, сохраняя весь набор проверок.

VLESS paired182 PASS: live p50/p95 317.644/321.353→228.483/230.573 мс;
selected-batch 1465/1487→1285/1302 мс. Dead-node slightly worse
8.905→9.114 мс, поэтому универсальное ускорение не заявляется.
Mihomo lifecycle/settlement/postCAS PASS, manual HTTP FAIL на прежних110с.
Lifecycle same-host candidate251.58с против4cc247.97с, ускорения нет.
Следующая проверка отдельно сравнивает manual-http с4cc на том же runner,
с теми же бинарниками и бюджетами; порядок candidate→baseline диагностический.

Public configured-old193 всё ещё отказал до restore. Исправлена реальная
ошибка классификатора: он не распознавал уже допустимые составные DNS причины.
Добавлены actual pipe cap regressions и отдельный opt-in empty/draft matrix:
настоящий старый HTTP API создаёт draft, после публичного restore проверяются
исходный SHA состояния и нынешний production reader. Это не доказательство
старого live reader, сохранения ручного выбора или default legacy-layout.

Full managed NFQWS2 LAN/manual остаётся FAIL; original core normal и
cleanup-only retry PASS. DNS strict12 FAIL, diagnostic30 все3recovery PASS.
Увеличение Xray ReadAt блока отклонено: actual36577406B file,32KiB29.450мс,
256KiB28.966мс (~1.64% warm), больше allocation и хуже отмена. Production32KiB
сохранён. Новый names benchmark проверяет только стоимость полного прежнего
metadata traversal с bounded backing slice; production алгоритм не менялся.

[Raw и SHA256](measurements/2026-11-09/research/lifecycle/3b27bd6e/),
[paired182](measurements/2026-11-09/research/ci-3b27bd6e/).
Новые исправления и сценарии требуют своего CI; router/LAN не подтверждены.

### Проверка 8434e9ae и следующая интеграция

Оба общих CI (PR42655707310, push42655695807) SUCCESS на точном
`8434e9ae2183ef926a123b1fe4217bc0114d214a`: normal/race, go vet, shell/UI,
четыре Linux cross-builds. Это не закрывает отдельный native lifecycle workflow.
В минимальной обвязке build-targets обнаружен скрытый лишний UI-вызов;
его перенос в общий Node-блок и fail-fast дочернего shell проверены отдельно.

- Paired baseline363f →8434: 182 строки, verdicts, identity, полная cleanup PASS.
  Повторные N12, p50/p95: live315.190/317.779→228.505/236.826мс;
  selected2 1456/1463→1287/1323мс; all1473/1489→1304/1341мс.
  Dead-node8.232→9.079мс: общего ускорения всех сценариев не заявляем.
- Все4Mihomo native jobs SUCCESS. Manual на одном runner: candidate288.01с,
  preserved4cc287.93с; Apply~100с у обоих при прежнем110с deadline.
  Lifecycle254.40с против251.50с. Ускорения нет, запас времени ограничен.
  Отдельная полная same-boot/race/ACK-cut матрица остаётся незавершённой.
- DNS strict12 FAIL; diagnostic30 все3recovery PASS. Actual iptables1.8.11
  normal/race PASS. NFQ normal core/recovery/cleanup retry PASS, fullLAN/manual
  и race FAIL. Сетевые ограничения и исходные deadlines сохранены.
- Public empty bootstrap теперь даёт точную причину: 2с scoped DNS inactivity,
  proc.installer-role-close. Draft достигает настоящего old193 HTTP writer,
  затем корректно отказывает на обычном StrategyPair admission.

Следующая интеграция прошла независимое source review, но ещё требует своего CI:
первая SHA + повторные полные чтения executable внутри одного bootstrap-role call;
отдельное offline сохранение неизменных schema1 StrategyLab bytes без приписывания
old193 нового reader ABI; резервирование ограниченного names slice.
Последнее экономит~4.4KiB/6–7alloc на обходе, wall ускорение не подтверждено.
Offline proof не разрешает live downgrade или private replay; история/manual
selection и восстановленный старый live panel не объявлены проверенными.
Полный Xray image compare пока только измерительный тест: retained~37MB,
первый capture/SHA/clear учитывается отдельно; production cache не добавлен.

На действующем роутере только read-only: SHA256 установленного30.3MB бинарника
занял0.58/0.59/0.59с, stat неизменен. Это внешний sha256sum прежнего rc106,
не Go/candidate benchmark и не подтверждение нового LAN маршрута.
[Профиль и raw](measurements/2026-11-09/research/router-readonly.md).
[Native raw/review/SHA256](measurements/2026-11-09/research/lifecycle/8434e9ae/),
[paired182](measurements/2026-11-09/research/ci-8434e9ae/),
[offline-контракт](measurements/2026-11-09/research/bootstrap-offline-strategy-contract.md).

### Контрольная точка344912c1

[Актуальные результаты и ограничения](CURRENT_STATUS_RU.md#проверка-344912c1-и-следующая-интеграция).
Оба generic, все4Mihomo, совместимая pair/restored-panel проверка PASS;
strictDNS/NFQ/publiclegacy остаются незавершёнными. Xray primitive37MB:
original18.08мс, firstcapture/SHA/clear20.54мс, repeat allbytes2.89мс.
Решение67f4557c: один scoped outer image, фиксированный<=64MiB storage,
полное чтение каждого original opening/closing; source review есть, full-runtime
проверка нужна отдельно. Разные CPU CI исключают причинный вывод по соседним
runs: новый matched plan использует A–B–B–A на одном runner, N2 на сторону,
не смешивая build/harness wall, run-through-join profile и route readiness.
IP -Version не оптимизируется статическим кэшем: исходный контракт учитывает
runtime get_libbpf_version; actual Start и прежние metadata проверки сохранены.

### Интеграция 2ecf9961 после ea36873e

[Текущая приёмка и оставшиеся направления](CURRENT_STATUS_RU.md#исходники-и-приёмка-на-09112026).
Независимые source reviews bootstrap join, classic-save copy, полного startup
measurement, ABBA и CI wiring сохранены вместе с [точными ea368 raw](measurements/2026-11-09/research/lifecycle/ea36873e/).
Команды нового измерения: `sh scripts/compare-domain-image-native.sh` через
`domain-image-comparison.yml`; исходные strict бюджеты не изменяются.
`sh scripts/test-managed-probe-native.sh` запускает actual-child classic-save
benchmark и test-only full startup image measurement normal/race. Переиспользование
буфера не пропускает общий Write budget. Cumulative allocation profile включает
подготовку процесса; его нельзя выдавать за allocation delta одного HTTP-вызова.
Первые и повторные VLESS samples, CPU/RSS и cleanup остаются раздельными.

### Измерения5289 и public history976

[Exact raw, CPU profiles и независимые выводы5289](measurements/2026-11-09/research/lifecycle/5289a7d8/)
сохранены отдельно от [focused history976](measurements/2026-11-09/research/lifecycle/976fa47c/).
History165.09с включает настоящий public bootstrap58.46с и public restore105.79с;
три старые HTTP-пробы и ручной выбор создаются через старый API. Исправления
fixture: точный legacy iptables alias в private namespace; JSON body `{}` для
Validate (старый middleware требует Content-Type). Положительный тест не снимает
unknown/finalizing и stale evidence guards. Команда воспроизведения:
`gh workflow run research-lifecycle.yml --ref <exact-ref> -f focus=public-history`.
Focus помечен в run-name и concurrency group; пропуски прочих jobs не означают PASS.

NFQ original RPDB pair измерен на том же runner normal53.738→22.639мс,
race90.661→44.300мс; fullLAN/manual всё ещё FAIL. DNS GEN2 current profile:
12.01 CPUс/12.745 wallс, counterfactualRows5.32с cumulative, ordinary Xray Current
4.61с, в том числе successor listener2.41с. Это failed-stage attribution, не
готовность маршрута. GEN1 и полные exec-child CPU этим профилем не представлены.
7428 передаёт только уже открытый exact pre-add file view successor listener,
сохраняя независимые старые source reads и closing. Результат требует native run.
[Независимое ревью изменений и gates](measurements/2026-11-09/research/reviewed-successor-wave/).

### Панель по референсам NetZapret, 10–16 ноября

Основа реализации — предоставленные владельцем скриншоты NetZapret 1.5.3.
Для сопоставления структуры ранее просмотрены `MainWindow.xaml` и
`Theme/Palette.xaml` на закреплённой ревизии NetZapret
[`4cb02c140d8807c18cc730095a5e86be751a951c`](https://github.com/RixyPow/netzapret/tree/4cb02c140d8807c18cc730095a5e86be751a951c/gui/NetZapret.Gui).
Использован принцип группировки задач и визуальной иерархии; сторонний код,
иконки и новые библиотеки не переносились. Владелец общих UI-файлов — ведущий,
независимый source reviewer — catalog_product_analysis.

Существующие 21 страницы сохранены. Пять ранее вложенных инструментов стали
самостоятельными пунктами; 13 владельцев меню однозначно соответствуют модели.
Переключатель краткого/подробного вида не меняет текущую страницу и не скрывает
управление черновиками или scope. HEV/Mihomo recovery-контролы перенесены в
диагностику с сохранением ID и disabled/admission. Выбор, запуск, реальная
проверка сервиса и готовность LAN по-прежнему разные состояния.

Команды локальных проверок (Node, без Go build):

```powershell
node scripts/build-interface.mjs
$suites = @('interface-contract', 'interface-unified', 'bundle-integration', 'simple-home', 'active-panel', 'hev-recovery-ui', 'mihomo-recovery-ui', 'app-update-ui', 'workspace-controls-ui', 'console-route-hash')
foreach ($suite in $suites) {
  $ext = if ($suite -eq 'interface-unified') { 'cjs' } else { 'mjs' }
  node "scripts/test-$suite.$ext"
  if ($LASTEXITCODE -ne 0) { throw "Failed: $suite" }
}
# Existing Playwright module directory; no install/download is performed.
$env:NODE_PATH = '<installed node_modules containing playwright>'
$env:RAZVILKA_UI_CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe'
$env:RAZVILKA_UI_ARTIFACTS = '<directory outside the source tree>'
node scripts/test-panel-navigation-browser.mjs
```

Результат PASS: Chromium desktop 1440×1000/mobile 390×844, 28 переходов,
все 21 страницы, открытие подменю в кратком виде, сохранение страницы при смене
вида, passive update read, Tab/Escape/фокус, no overflow, ноль JS exceptions,
внешних запросов и API writes; recovery read/repair не вызывается навигацией.
49 реальных статических ресурсов проверены, SHA256 сохранены в report.json.
Локальные артефакты: `C:/RAZVILKA-research-20261110/panel-netzapret/`.
Браузер использует синтетический transport: остановленный проект/пустой каталог,
прочие непредоставленные API отвечают 503. Это проверка представления и доступности,
не backend, скорость соединения или router/LAN acceptance. Ни ускорение, ни
готовность выпуска этим изменением не заявляются.

### Повтор50bd и измерение полной цены namespace workers

[Полная bounded evidence серия50bd](measurements/2026-11-09/research/lifecycle/50bd038c/):
public history повторёнPASS164.20с; все4Mihomo PASS, sameboot10/14PASS;
strictDNS/NFQ полные сценарии FAIL. Native diagnostic30 отдельно достиг нового
GEN2 file-view path36/72/72; этот более поздний cut прочитал377 полных images
и не сравним с прежним незавершённым342-read strict сценарием как ускорение.

Команда в исходном native namespace: compiled `startuptools.test`
`-test.run '^TestMetadataParallel.*$' -test.count=3 -test.v -test.timeout=100s`
`-test.bench '^BenchmarkMetadataParallelCostModel$' -test.benchtime=300ms -test.benchmem`.
Нормальный serial0.644мс против2workers1.837мс; race1.179 против4.897мс.
Полные original Provider/FD/thread boundaries и joins включены; CPU normal
0.665→3.437мс, race1.233→8.876мс. Это отрицательный результат, production unchanged.
Измерительный prototype сохраняется для воспроизводимости, не является новой
возможностью продукта. Следующий actual0470 run измеряет ожидание существующей
очереди инструмента отдельно от удержания и исполнения, без изменения admission.


## 16.11: точные архивы и стадии fresh-byte наблюдений

Контрольная точка `fc5bcc6c`: [числовые результаты](measurements/2026-11-16/release-fc5bcc6c.json)
и [условия замеров](measurements/2026-11-16/README.md#последующая-контрольная-точка-fc5bcc6c).
Compatibility helper проверяет8 конкретных commit/tree/tar/gzip pins, лицензии,
новый destination и no-follow writes. Linux12 tests и16 actual restorations PASS.
Повторное gzip-сжатие другой реализацией не эквивалентно immutable asset;
первый отказ сохранён, pins не изменены. Временная data-only ветка передала
точные исходные gzip; no release/main/tag mutation. После пересоздания отдельно
проверяется fixed release URL, до его публикации HTTP-path не отмечен PASS.

Отдельная диагностика HEV использует официальный2.17.1 ELF
SHA256 `a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03`,
источник `heiher/hev-socks5-tunnel` commit
`9a06bc6e7989da54e3d32ff701ef7a7ce4995d3a`, MIT. Исходники хранятся вне production:
`C:/RAZVILKA-research-20261116/hev-2.17.1-source`.
8 untraced и8 separate traced запусков в private PID/network/mount namespace;
closed syscall/errno/numeric altstack diagnostics, exact Wait/cleanup. Это не
route admission, не трассировка исходного acceptance и не доказательство
причины exit254 до результатов. Источник stack detector включён; runtime
размер altstack должен проверяться численно, а не предполагаться.


### IP version: отвергнутое сокращение subprocess

Источник iproute2 v6.19.0, commit
`dac1bc6021693902b25a961227e289791e429b91`, официальный source tar
SHA256 `9332213d35480b647086a70c302de8568de83455a98774d35de216c4ce191006`.
Ubuntu6.19.0-1ubuntu1.1 amd64 и amd64v3 точно совпали с используемыми ELF pins;
исходники и distro patches исследованы вне production в
`C:/RAZVILKA-research-20261116/ip-version-fact-source/analysis-contract.json`.
COPYING GPLv2; отдельные файлы GPL-2.0/GPL-2.0-or-later, исходники не копировались
в продукт. [Фактический getter](https://github.com/iproute2/iproute2/blob/dac1bc6021693902b25a961227e289791e429b91/lib/bpf_glue.c)
читает собственный `/proc/self/maps`; отказ поиска даёт stderr. Поэтому даже
закреплённый binary/hash не превращает результат нового запуска в статическую
строку. Существующий scoped xtables fact на IP не расширен. Обе свежие metadata
проверки вокруг IP child также сохранены. Это подтверждённое ограничение
конкретной оптимизации, не внешний блокер всей разработки.

### HEV: воспроизведён платформенный silent startup failure

Standalone run43900067221 (`fc5bcc6c`) PASS16/16 на машине с
AT_MINSIGSTKSZ3632: наблюдалось выделение altstack8192. В следующем original
sameboot run43901063124 (`9e73d133`) HEV снова exit254/нулевой вывод. После
исходного FAIL на той же машине отдельно запущены8 untraced+8 traced:
все16 отказали доTUN, cleanup16/16 подтверждён; AT_MINSIGSTKSZ11952,
sigaltstack syscall отсутствует. Проверяется гипотеза отказа libc до syscall;
исходный acceptance не трассировался и его FAIL не заменён диагностикой.
[Linux описывает](https://www.kernel.org/doc/html/v5.17/x86/elf_auxvec.html)
различие минимального размера сигнального кадра и дополнительного стека
обработчика. Исходники/бинарник должны подтвердить конкретную ветку отказа
до выпуска исправленного компонента; на этой точке такого исправления ещё нет.


## 16.11: полное сравнение Mihomo на одном host

Run43916682582, exact42b83032, два исходных архива отличаются ровно аргументом
scratch в cold self-image reader. Фиксированная ABBA последовательно для
normal и race; все8 samples/log SHA и source manifests проверены независимо.
Normal image47.83/47.13с против two-SHA52.80/52.93с: среднее47.48→52.865с,
то есть normal медленнее на11.34%. Race image дважды FAIL120с; two-SHA
PASS103.53/103.74с. Overall workflow честно FAIL, поскольку старые отказы
не исключены.120с — отсечка незавершённого теста, не время успешного baseline.

Наdc5829fd принят общий для всех сборок существующий fallback двух свежих
полных SHA. Проверки metadata/EOF/context/parent/process/socket и120с
сохранены. Ускорение normal и уменьшение RSS не заявляются. Проверка всех
точек ACK exactdc5829fd идёт отдельно в43921540920. Источники, времена
consumer и отдельный driver wall с компиляцией:
[полная серия](measurements/2026-11-16/mihomo-self-image-42b83032.json).

## 16.11: подтверждённые остатки DNS и NFQWS2

Наb31ff873 strict selected не дождался первоначальной DNS publication12с,
а canceled-ready — GEN2 witness12с; diagnostic30PASS. Одиночный timeout stack
показывал nodestore decode, но exact pprof16.76CPU даёт load0.20с и decode0.12с.
Не вводим новый JSON cache по этому стеку:
[числа, SHA профиля и ограничения](measurements/2026-11-16/nodestore-profile-b31ff873.json).

На66f00639 общий managed run43919362707 FAIL. Core production прошёл,
intent/settlement recovery достигнуты и прошли, но последующий fresh Apply
вновь не завершился в исходном18с. Failed Apply отдельно подтвердил закрытие
и отсутствие принадлежащих ему объектов; первичный FAIL сохранён. Значения
общего Apply41–48с включают rollback, а не увеличение forward deadline.
Показатели version counters послеClose ошибочны (unsigned underflow);
перенос источника измерения черезClose исправляется отдельно. Все11 log SHA,
результаты и пределы: [native66f](measurements/2026-11-16/managed-66f00639.json).

## 16.11: проверенный путь замены HEV

На `374bbd46c602302363b4f087e627ae6370bdbcad` run
[43916940407](https://github.com/ArtixSx/RAZVILKA/actions/runs/43916940407)
прошли Linux normal/race: все7 компонентных тестов и actual HTTP update через
панель. Старый официальный и желаемый исправленный ELF, запущенные под другим
именем, блокируют замену; sole Wait предшествует успешному повтору. Проверены
три согласованных файла, отмена, cursor/CAS, crash recovery и pending refusal.
Same upstream version2.17.1 различается точным SHA, повтор после установки
не предлагает ту же замену. HTTP fixture1.12/1.97с; это не LAN throughput.
[Результаты](measurements/2026-11-16/hev-replacement-374bbd46.json) и
[хеши артефактов](measurements/2026-11-16/hev-replacement-374bbd46-files.json).

Подготовлен непубличный vendor bundle в
`C:/RAZVILKA-backups/hev-vendor-2.17.1-r1-prepared-374bbd46-v2`: raw ELF
`1170182f821cec62b03c1443747e52b45f48baa7d7595f45e95c2ccf958972d9`,
source/notices tar.xz895024байт
`47c1b454ee801a5e2585a48a6f923b3265e4324e0add6bc431b35d155ffdcdb8`.
Полный исходный архив, patch, fault-test, квалифицированный build helper,
metadata и129 notices сохраняются; compiler archive остаётся в прежней
проверенной резервной копии. Root независимо сверил обе внешние SHA256.
Default pin и ARM64 не изменены; full-route ACK, доставка и роутер — отдельные
этапы. Последующая правка collector сохраняет COPYRIGHT/NOTICE и полный
toolchain share/licenses; она меняет только полноту доказательств, не ELF.

## 16.11: NetZapret — оформление панели и Releases

Изучены установленная Windows-версия 1.5.3 (видимое окно «Главная» и окно
обновления до 1.6.2) и [релиз 1.6.2](https://github.com/RixyPow/netzapret/releases/tag/v1.6.2)
от 14.11. Исходники закреплены за `c6f0e6007bd6d63de094a815458876d25b9a6e87`.
MIT, copyright RixyPow. Девять выбранных файлов с LICENSE, URL и SHA256 лежат
отдельно: `C:/RAZVILKA-research-20261116/netzapret-v1.6.2/source-manifest.json`.
Программа не обновлялась, её подключения/настройки не менялись; секретные
подписки не читались. Автоматизация видит окно с повышенными правами только
частично: показанные карточки осмотрены, полный интерактивный обход новой
версии не заявляется. Предоставленные владельцем снимки дополняют обзор 1.5.3.

| Приём | Что подтверждено источником | Применение в RAZVILKA |
|---|---|---|
| Постоянное меню и единые карточки | `MainWindow.xaml`, `Theme/Palette.xaml` | Уже есть 13 пунктов/4 группы, краткий и подробный вид; desktop/mobile и клавиатура проверены отдельно. Сохраняем собственные названия и возможности роутера. |
| Изменения по вкладкам | `Updates/NotesCategories.cs`: категории совпадают с меню; новые функции и исправления разделены | Примечания выпуска группируются по задачам пользователя; открытые ограничения не прячутся в техническом списке коммитов. |
| Версии рядом с содержанием | `Views/UpdateWindow.xaml` и `.xaml.cs`, видимое окно 1.5.3 | Полезно для будущего просмотра истории обновлений; не даёт разрешения автоматически обновлять действующий роутер. |
| Небольшая обложка, затем конкретные изменения | Фактическое тело GitHub Release и `docs/release-notes.md` | Используем собственный баннер/реальную панель и короткое описание, без заимствования логотипа и снимков чужого продукта. |
| Хеши и воспроизводимая сборка | `release.cmd`: подвал собирается из действительных ZIP/EXE и версии SDK | В примечания RAZVILKA добавляются точная ревизия, назначение файлов и суммы фактически собранных файлов. Побитовая воспроизводимость не заявляется без отдельного сравнения. |

Польза — одинаковые названия в меню и описании выпуска, понятный выбор файла
и видимая граница между изменением, проверкой и ограничением. Для этого не
требуются WPF/.NET, новые фоновые процессы, внешние шрифты или CDN в панели.
Код NetZapret в RAZVILKA не переносился; лицензия сохранена с исследованными
исходниками. Не перенимаем Windows-драйверы, настройку антивируса, автоматическое
расширение охвата трафика или утверждение, что задержка доказывает работу сервиса.

Повторить получение версии: `gh api repos/RixyPow/netzapret/releases/latest`;
закреплённый исходник:
[NotesCategories.cs](https://github.com/RixyPow/netzapret/blob/c6f0e6007bd6d63de094a815458876d25b9a6e87/src/NetZapret.Core/Updates/NotesCategories.cs),
[UpdateWindow.xaml](https://github.com/RixyPow/netzapret/blob/c6f0e6007bd6d63de094a815458876d25b9a6e87/gui/NetZapret.Gui/Views/UpdateWindow.xaml),
[release.cmd](https://github.com/RixyPow/netzapret/blob/c6f0e6007bd6d63de094a815458876d25b9a6e87/release.cmd).

## 16.11: повтор полного VLESS Check и очереди на `33de2dde`

Run [43908564102](https://github.com/ArtixSx/RAZVILKA/actions/runs/43908564102)
завершился PASS. Сравнение на одном Linux runner: baseline
`363f433611620cda4d14db2d0a7ae2475b0278f1` → candidate
`33de2dde69d7599234714a3ea61e99f58ea5772e`, одинаковый закреплённый Xray,
исходный алгоритм `current-reuse` с обеих сторон. Одна первая проверка и
12 повторов каждого сценария. Фиксированный порядок baseline→candidate может
влиять на прогрев/нагрузку; это не случайное чередование и не физическая WAN.

| Сценарий | Медиана повторов до, мс | После, мс |
| --- | ---: | ---: |
| Доступный сервис, полный Check | 309.118 | 216.1785 |
| Недоступный сервис | 305.922 | 216.383 |
| Отмена | 265.8735 | 175.5525 |
| Недоступный узел | 6.2735 | 6.3515 |
| Один узел: POST→очередь→ответ HTTP | 633.8165 | 541.825 |
| Выбранная группа | 1360.45 | 1190.335 |
| Все VLESS | 1401.15 | 1189.915 |

Cleanup подтверждён во всех сценариях с созданными ресурсами; для недоступного
узла он не требовался. Отдельный настоящий Mihomo handler: 2977мс, из них
подготовка518мс и adapter Check2459мс; service/cleanup verified, live route=false.
Эти результаты не означают готовность LAN-маршрута, прохождение race ACK или
проверку роутера. Медиана здесь — среднее двух центральных значений; текстовый
вывод старого fixture выбирает нижнее центральное, поэтому числа немного разные.
[Сырые хеши CSV, первые проверки и стадии](measurements/2026-11-16/probe-comparison-33de2dde.json).

## 16.11: точный граф NFQWS2 при равных счётчиках

Внешний Entware review предложил проверять подмену одного принадлежащего
RAZVILKA правила чужим при неизменных общих числах правил и NFQUEUE. На
`0652bc5b` добавлены оба направления pre/post: classifier должен вернуть
`owned-graph-partial`, а NDM restore — отказаться без команд и изменения таблиц.
Windows model PASS; отдельный Linux normal/race run43911510337 запущен,
его результат не объявляется заранее. Это проверка существующего точного
контракта, а не новый допуск по числу строк.

Уточнение внешнего отчёта: Linux BPF attach type18 — `BPF_CGROUP_SYSCTL`,
а `BPF_CGROUP_INET4_BIND` имеет номер8. Root cgroup attachment остаётся причиной
защитного отказа независимо от названия; оно не удаляется ради теста.

Повтор на `befedef5`, run43913993782: native normal **PASS5.35с**, race
**PASS8.52с**, включая обе подмены при равных счётчиках и частичные сбои
восстановления. Стенд использует прежний exact ELF iptables1.8.11; исходные
отказы MAIN_PIN при другом пакете и unreadable queue inventory сохранены как
неуспешные попытки. Подготовка устанавливает проверенные архивы, загружает
`nfnetlink_queue` и проверяет доступность inventory от того же root, который
выполняет тест. Отсутствующий файл не считается пустой очередью.
[Точная ревизия, хеши доказательств и границы моделирования](measurements/2026-11-16/nfq-ndm-befedef5.json).

## 16.11: измеренные решения по памяти и обходу метаданных

`a74c74c1`, run43912334464: bounded retained byte scratch перед прежним
`sync.Pool`, без сохранения FD/идентичности/SHA/результата проверки. Полный
verifier и очистка ёмкости включены в каждый замер; модель485957байт,
по четыре наблюдения на комбинацию режима/варианта, чередование ABBA.
В normal steady медиана0.796→0.820мс: ускорения нет. После двух GC
normal0.976→0.813мс, race4.333→3.693мс; средние выделения после GC
639352→98968байт и714780→153804байт соответственно. Это подтверждает
уменьшение выделений, но не прохождение полного Apply.
[Результаты и SHA](measurements/2026-11-16/runtime-scratch-a74c74c1.json),
[32 отдельных замера](measurements/2026-11-16/runtime-scratch-a74c74c1-samples.json).

`e4e74291`, run43913329305: **отклонён** переход к удержанию родительских
FD в production. Полный обход168 nodes/134 images с четырьмя parent anchors,
всеми свежими проверками и закрытием стал медленнее: normal среднее
1.086→1.301мс (+19.8%), race1.503→2.798мс (+86.2%), по шесть чередующихся
пар. Остался только тестовый эксперимент с проверкой совпадения исходного
полного тела. [Результаты](measurements/2026-11-16/metadata-parent-e4e74291.json).

Generic CI `33de2dde` run43908375410 и `74c7a0c0` run43909060138 PASS.
Полный CI не запускается автоматически на шести специальных префиксах
веток измерений; PR, основная рабочая ветка и ветки выпуска сохраняют
прежние проверки. Итоговый интегрированный SHA обязательно проходит полный
CI отдельно; focused/native PASS его не заменяет. Лишние generic runs
0652/7231/e4e отменены, их статус — CANCELLED, не PASS.


## 16.11: fresh mount identity и воспроизводимая упаковка HEV

На7a338026 тот же подход, уже применённый в netidentity/Xray selected TCP,
перенесён в inactive process observer: fresh statx(held FD, empty path,
AT_EMPTY_PATH, STATX_MNT_ID). Каждый вызов сначала подтверждает удерживаемый
fdinfo; old-kernel/отсутствующий mask сохраняет исходный bounded fdinfo reader.
Zero ID и неожиданные ошибки отказывают. Нет кэша результатов или доступности
syscall. Называемые anchors, inode/mount, namespace, birth, Threads и закрытие
не переставлены. На modern path отдельная читаемость fdinfo/<fd> больше не
условие: mount получается непосредственно с удерживаемого FD.

Независимое source review сопоставило Linux v6.1
[fs/stat.c](https://github.com/torvalds/linux/blob/v6.1/fs/stat.c#L188-L236),
[fs/namei.c](https://github.com/torvalds/linux/blob/v6.1/fs/namei.c#L2406-L2428)
и [fs/proc/fd.c](https://github.com/torvalds/linux/blob/v6.1/fs/proc/fd.c#L52-L60).
Исходники Linux не копировались; новый adapter написан в проекте.
Actual normal/race43945773992: O_PATH magic-link/followed NSFS parity,
повторное использование FD,5 same-inode bind fences,live worker/Z1/exec PASS.
Команда leaf comparison:
`go test ./internal/dataplane -run '^TestInactiveProcMountID' -bench '^BenchmarkInactiveProcMountIDPair$' -benchmem -benchtime=200ms -count=10 -v`
(отдельно с `-race`). [Числа и границы](measurements/2026-11-16/inactive-statx-7a338026.json).
Это не full lifecycle/router proof и не замер Linux4.9.

HEV9da0e4e2: `build-hev-runtime-altstack-lab.sh` →
`prepare-hev-vendor-assets.py --repo ... --build-dir ... --output NEW_DIR`.
Два fresh Linux builder43945667501 подтвердили точный ELF1170182f…,
полные129 notices и LICENSE,143 regular archive members/142 SHA.
Повторная упаковка одинаковых inputs побайтно одинакова; preserved build logs
различаются между hosts, поэтому source archives не обязаны иметь общий SHA.
Ссылки/версии/лицензии закреплены в manifest, полный source и patch включены.
[Проверки](measurements/2026-11-16/hev-vendor-9da0e4e2.json).
На этом историческом этапе default pin, ARM64 и router admission не менялись.

### Последующая интеграция default delivery и проверка границ ускорения

ec62ac2a переводит обычный AMD64 selector на те же проверенные vendor bytes;
ARM64 остаётся прежним. Native43949636941: по10 обязательных PASS normal/race,
actual HTTP replacement1.19/3.23с, отказ при занятом процессе, подмене SHA,
прерывании и незавершённой замене. Это local exact-URL transport, не публичный
GET. URLv0.20.0 подготовлен для будущего пересоздания GitHub; старый tag
наaef3a398 не меняется. Stage2 сохраняет official fixture отдельно для
исторических сравнений; они больше не считаются изолированным замером кода.
[Точная ревизия и raw SHA](measurements/2026-11-16/hev-default-ec62ac2a.json).

6cba005b43948051402 подтвердил оба original NFQ recovery cuts в двух режимах:
pre-ledger29.95/62.59с, prepared-active26.78/56.95с. Все6 логов независимо
сверены по SHA, по16 контрактов в каждом режиме и полные4 маркера восстановления.
[Доказательства](measurements/2026-11-16/nfq-recovery-6cba005b.json).
Full Apply остаётся отдельным FAIL. 6db7a49e измеряет закрытый список стадий
WG inactivity только в native fixture; bounded40 записей выводятся после
исходной функции. Два прохода и8с сохранены, обычная сборка не читает часы
или окружение и ничего не пишет. Независимое review и focused Windows PASS.

Sameboot7a завершился12/14 PASS: parent/private4 и8 ACK; два race ACK120с FAIL.
[Стадии](measurements/2026-11-16/mihomo-sameboot-7a338026.json).
Исходные opening/closing self SHA разделены проверками ядра и процессов;
повторное использование старого hash не эквивалентно свежему доказательству.

Test-only netidentity.readFile experiment1cdb:8 AB/BA пар на режим,512 чтений
на сторону, normal2224.34→2018.93ns, race4253.65→3812.53ns. Это лишь1.64µs
или3.53µs на8 чтений capture; production-оптимизация отклонена как решение
четырёхсекундного DNS отказа. [Измерения и пределы](measurements/2026-11-16/netidentity-readfile-1cdbbfae.json).
Внешнее review дополнительно нашло mixed-mask/zero-ID край в test-only
кандидате; исправление и новые негативные тесты проверяются отдельно и не
наследуют исторический PASS замера. Исправленный test-only кандидат df4aa938
прошёл normal/race43951327655, все3 exact tests без skips; raw SHA добавлены
отдельным verified_followup в первоначальный measurement JSON.

### Подтверждённая коллизия baseline и отказ от неполезных оптимизаций

Независимое source review Linux4.9 (commit
69973b830859bc6529a7a0468ba0d80ee5117826, GPL-2.0, source/COPYING вне checkout)
обнаружило недостаточность одного tuple для владения ответным пакетом.
[ipset tuple](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/net/netfilter/ipset/ip_set_hash_ipportip.c)
и [NOTRACK](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/net/netfilter/xt_CT.c)
не знают исходного accepted FD. Клиент вправе одновременно открыть C:p→S:443
и C:p→R:443, где S — synthetic, R — real. Пять existing compiler effects
baseline выбирают ответ R:443→C:p и не отличают соседнее direct соединение.

b86af84d43953680219 воспроизвёл это в трёх disposable namespaces: no-effect
direct echo PASS, другой исходный порт PASS без изменения counters; на исходном
порту remote отправил ответ, оба raw/MARK counters выросли на7 и доставка
нарушилась. Все exact effects удалены, children joined,1.17с.
[Raw SHA и предел доказательства](measurements/2026-11-16/domain-tuple-collision-b86af84d.json).
Это успешное воспроизведение дефекта, а не routing acceptance. Production owner
не подделывался, роутер не изменялся. Перенос predicates в ipset остановлен:
он сохраняет коллизию и добавляет race между raw/mangle lookup.

Владельцу предложено явно выбрать новый baseline source contract с обычным
router-originated соединением и доказанным ограниченным policy subset либо
сохранить исходный tuple и не включать небезопасный сценарий. До ответа source
semantics не меняются. Случайный порт при прежнем LAN IP сам по себе не резервирует
его в клиентском стеке. Native VPN/marks/VRF/programmable policies нельзя обходить
ради такого fallback. Исходное четырёхсекундное ограничение остаётся отдельно.

7657fe7d43951976231: private256KiB buffer вместо двух allocations сохраняет оба
полных fresh SHA, но8 AB/BA пар на режим не дали устойчивого wall выигрыша:
normal48.889→48.913мс, race76.705→77.560мс. Только262144B allocation экономии
на пару. В production не принят. [Данные](measurements/2026-11-16/mihomo-hash-buffer-7657fe7d.json).

a0ac default HEV route43950768764: lifecycle, post-CAS recovery и failed-Check
settlement PASS. Manual HTTP apply FAIL123.77с после успешных activation stages;
CPU profile155.8с, SHA block127.87с. Это подтверждённая следующая цель измерения,
не основание убрать fresh reads. [Статусы и profile SHA](measurements/2026-11-16/default-lan-a0ac0bb3.json).
25da7ba9 завершает только исходный retained sole Wait внутри прежнего cleanup5с;
исходный unknown не превращается в успешное evidence. Native сценарии3с initial
и8с retry проверяются отдельно. Первоначальный fd3554 gate выявил0755 test ancestor;
3a6c09ef исправляет только собственный test directory на0700, сохраняя production guard.

## 17.11.2026 — выбор безопасного DNS fallback по внешним исходникам

Владелец поручил самостоятельно выбрать подход после исследования других
проектов. Отдельного решения пользователя по source tuple больше не требуется.
Выбран обычный исходящий TCP socket роутера с точным закреплённым realIP:port
и собственным портом ядра. Неподходящее имя не направляется в выбранный VLESS.

Изучены закреплённые Mihomo `3f27ef39`, sing-box `8295e491`, Xray `af8f9673`
и redsocks `19b822e3`; [полные SHA, ссылки и хеши 14 файлов](measurements/2026-11-16/direct-fallback-source-review.json).
Mihomo и sing-box используют отдельный outbound dialer; параметры interface/mark
не означают наследование политики LAN-клиента. Xray Freedom также создаёт
отдельный socket, optional source IP не сохраняет клиентский TCP-порт.
Redsocks — TCP-to-proxy relay, не готовый DIRECT; полезен только как пример
независимого outgoing socket и его закрытия. Лицензии: GPL-3.0, GPL-3.0-or-later
с дополнительным условием именования, MPL-2.0 и Apache-2.0 соответственно.
Исходники сохранены вне checkout, код не копировался, новых зависимостей нет.
Обычный socket использует уже существующий relay; новый демон, DNS-поиск и
чужие retry/timeout политики не требуются. Буферы и descriptors остаются
ограниченными исходным числом одновременно допущенных потоков.

Независимое внешнее ревью сверило ещё 29 файлов, включая release pins и Linux
4.9 `69973b830859bc6529a7a0468ba0d80ee5117826`. Найден риск: совпадение FIB не
доказывает разрешённый доступ. FORWARD может запрещать клиенту Интернет, хотя
OUTPUT роутера разрешён. Поэтому local route lookup сам по себе недостаточен:
перед SYN нужен исходный положительный policy/ACL допуск MAC/ingress/publication.
Старый iproute2 нельзя считать поддерживающим современные TCP/UID selectors.
Ошибка обязательного bind/interface отказывает до Connect; продолжение после
ошибки sockopt, встречающееся в upstream Xray, для нас неприемлемо.

Сценарий `2d6d4aa6`, run43957616364 PASS1.15с: три реальные network namespaces,
одновременные C:p→synthetic и C:p→real, relay через обычный router socket;
сервер увидел1.1.1.1:55814, оба payload echo дошли. Затем прежние5 effects снова
перехватили соседний direct reply (raw+7/MARK+7); после теста effects удалены,
дети joined. [Сырые логи и SHA](measurements/2026-11-16/domain-router-source-2d6d4aa6.json).
Это подтверждает механизм разделения соединений, не production-owner admission,
не native VPN policies и не готовность физического роутера.

Интеграция: приватный socket внутри существующего original accepted-flow/capture
lifetime, source/mapping/current и mandatory local endpoint proof до/после Connect,
исходный control.WithStart, joined cancellation, sticky failure при ошибке close.
Долговременных per-flow packet effects нет: новая BF journal schema не нужна.
Старые schema1 BF pending/unknown записи не переинтерпретируются и требуют
прежнего recovery. Чужие/неподтверждённые native VPN, NAT и ACL остаются отказом
этого режима. Обязательные negative tests: одинаковый FIB при FORWARD DROP и
OUTPUT ACCEPT даёт ноль SYN; stale publication, cancel и owner drift не выдают
socket; partial connect/close не создают ложную terminal retirement.

## 17.11.2026 — фактические результаты оставшихся оптимизаций

Полный CI43950766568 наa0ac0bb3 PASS; это не LAN-приёмка новых ревизий.
NFQ cleanup3a43954920899: оба original Wait scenarios production PASS;
race initial FAIL на closing counter original14s deadline, late NOT_RUN.
ACK граница уже пройдена, remaining receipt-effects cleanup не завершился;
[полный отрицательный результат](measurements/2026-11-16/nfq-wait-cleanup-3a6c09ef.json).
Исходные сроки не продлевались, неизвестный результат не превращён в успех.

Pair-stream experiment6e16b03843957131063 normal/race PASS, 32ABBA rows,
но кандидат медленнее во всех8 парах каждого режима: normal median38.955→54.026ms,
race52.089→143.620ms. Normal CPU−18.47% не улучшает Apply latency, поэтому
переход на один SHA плюс byte comparison отклонён. Первоначальный aab run
ошибочно использовал неограниченный test context: guard корректно отказал,
валидных timing rows там нет. Исправлена только fixture; guard сохранён.
[Сравнение и ограничения](measurements/2026-11-16/expected-pair-stream-6e16b038.json).

WG9b43955853678 contracts PASS, полный manual Apply FAIL40.73с на policy-apply;
rollback verified и независимый Close PASS. Четыре WG observations завершились,
но сравнение с другим host не принимается за ускорение. Запущен отдельный
same-host fixed ABBA: полный исходный observer и две исходные8s проверки,
разница source copies ровно один table reader. Этот тест не называется полным Apply.


## 17.11: реализованный DIRECT и полные сравнения исходных наблюдателей

После изучения четырёх закреплённых проектов (ссылки и лицензии в
[manifest](measurements/2026-11-16/direct-fallback-source-review.json)) выбран
router-originated DIRECT. На69423dfe исходный accepted flow, конечный realIP,
поколение, original capture/control и прежние complete RPDB/packet checks
остаются обязательными. Новый socket получает один проверенный адрес egress
и собственный порт ядра, обязательный SO_BINDTODEVICE; IP_TRANSPARENT,
SO_MARK и пять старых per-flow BF effects не используются. Unknown/pending BF
история по-прежнему запрещает новое соединение. Context cleanup/read/preadd
не даёт forward authority. Native FORWARD DROP/OUTPUT ACCEPT fixture проверяет
явное закрытие принятого TCP, positive-control пассивного наблюдателя и zero
outbound SYN, затем восстановление политики и join. Это ещё ожидающий actual
run43962866341, а не готовность router или разрешение ordinary DomainApply.

Полные наблюдатели измерены на одинаковых исходных ресурсах:

| Измерение | До → после, мс | Ограничения |
| --- | --- | --- |
| WG original inactive observer7419, normal | 3850.813 → 2590.614 | same-host ABBA,4/arm; весь WG observer, не Apply |
| WG original inactive observer7419, race | 5908.976 → 3936.060 | обе реализации WG/AWG и32 вызова прошли; не router |
| Source.Current ce2, normal | 87.398 → 52.867 |8 пар, все быстрее; paired totalCPU +11.22% |
| Source.Current ce2, race |117.511 →68.549 |8 пар, все быстрее; paired totalCPU +1.61% |

[WG raw/result](measurements/2026-11-16/wg-pair-7419b4e5.json),
[full Source.Current](measurements/2026-11-16/source-current-ce2e09e2.json).
Полный Mihomo43959574318 terminal SUCCESS4/4: manual HTTP два Apply80.294/80.412с,
Stop5.678/5.643с, service probes, replay refusal, physical baseline; lifecycle,
post-CAS failure/undo и settlement тоже PASS. [Полный результат](measurements/2026-11-16/default-lan-e0a5eb15.json).
Это e0 с отдельно позднее отклонённым NFQ clear экспериментом;72db Mihomo код
сохранён наce2, но точная ревизия не подменяется. Историческое4cc сравнение
прошло на тех же hosts, однако другой HEV не позволяет приписать весь эффект
одной оптимизации. Отдельный race parent/ACK43961200477 FAIL и не закрыт этим PASS.

Воспроизведение на disposable Linux:

```sh
sh scripts/compare-wg-empty-table.sh /tmp/wg-pair-new-output
RAZVILKA_MIHOMO_ARCHIVE=/path/to/pinned-mihomo.gz RAZVILKA_SOURCE_CURRENT_MEASURE=1 go test -tags razvilka_native_fixture ./internal/components -run '^TestMihomoLiveSourceCurrentNative' -count=1 -v
RAZVILKA_XRAY_NATIVE=/path/to/pinned-xray RAZVILKA_DOMAIN_DIRECT_DENY_NATIVE=1 sh scripts/test-domain-original-native.sh
```

Точные pin/setup, flags и режимы находятся в wg-empty-table-comparison.yml,
source-read-comparison.yml и domain-router-direct.yml. Deadline production не
изменены; generic CI, native Linux и router/LAN считаются отдельно.


### 17.11: исходные дедлайны и отдельные границы стенда

- Точный93463d85: общий CI43963543947 PASS; actual Mihomo LAN43963543994 PASS4/4. Manual Apply79.678/79.134с, Stop5.611/5.681с; два обязательных probes, replay refusal, прямой physical baseline восстановлен. Это новая ревизия, не аппаратная приёмка и не причинное сравнение с историческим4cc.
- be7 sameboot43964362768: parent/private4/4 PASS, ACK6/10. Три race ACK превышают прежние120с при повторении уже завершённого префикса. Root перепроверил136 файлов manifest. Работа продолжается над узким exact pending ACK suffix; новый кеш evidence не вводится.
- normal terminal-global не дошёл до consumer: ordinary umount вернул EBUSY. По [Linux man-pages6.19, umount(2)](https://man7.org/linux/man-pages/man2/umount.2.html) это busy mount; force/lazy меняют смысл завершения.432fc1c2 повторяет только EBUSY с прежним общим5с, каждый раз проверяя исходный private mount ID/dev/inode. Сам syscall в original bounded child (timeout/kill/Wait), flags0, без сигналов держателям mount.6 модельных контрактов PASS, actual Linux persistent own FD refusal→joined close→ordinary success включён в43968515807; результат ещё ожидается.
- da0e369e: ровно один linker выбор debug/production-strip; default debug сохранён. ELF25.39% меньше, Go pclntab сохранён. ABBA43968451025 same-source/samehost с прежними publication12с и client4с; ошибки сохранены. Отдельный actual direct-deny уже PASS17.22с: положительный контроль observer, затем FORWARD DROP/OUTPUT ACCEPT и ноль outbound SYN при explicit EOF/reset, восстановление правила и join. Canceled-ready FAIL до successor cancellation witness, не считается готовностью recovery.
- NFQ e52643967605929: ordinary ABBA4/4 service+cleanup PASS, candidate320/320/0 frames; чтений/байт меньше, median Execute7.602→7.802с (+2.63%). Race ещё выполняется. Уменьшение bytes само по себе не оправдывает принятие нового production механизма.


## 17.11: завершённые сравнения и следующий точный кандидат bcc7

Root сверил SHA256 шести raw NFQ файлов; [ABBAe526](measurements/2026-11-16/nfq-read-e526a661.json)
не подтвердил ускорение, поэтому production022 и harness отменены66d79f96/f75221d3.
Исходники и результаты сохранены на отдельной experiment ref. Production
median7.602→7.802с, race4/4 deadline FAIL; меньший объём чтения не основание приёмки.
[DNS build fidelityda0](measurements/2026-11-16/domain-build-da0e369e.json): четыре
ABBA arms не прошли прежние12/4с. Debug59,148,339B и stripped44,122,377B —
один source, но не подтверждённое ускорение. Actual deny17.22с PASS отделён от
positive/cancel. Canceled-ready GEN1 проходит, GEN2 witness не достигнут.

[Image fixture432](measurements/2026-11-16/sameboot-image-432fc1c2.json) прошёл
normal parent/private/terminal-global3/3. Только ordinary umount с тем же mount
identity и прежним5с, без force/lazy/убийства чужих держателей. Actual private
FD удерживает busy mount, затем joined close разрешает обычное снятие;
исходный transient real-case не заявляется воспроизведённым.
Источник: [Linux man-pages6.19 umount](https://man7.org/linux/man-pages/man2/umount.2.html).

bcc7 retained ACK продолжает исходный terminal publisher с исходными FD,
свежими history/home/absence/runtime/tree/documents проверками. Завершённые
effects не повторяются; unknown и Close-loss потребляют право retry.
Independent lifecycle review выявил и проверил исправление root/name alias;
four contracts включены в normal/race workflow с обязательным PASS/noSKIP.
Full native43972077940 запускается с mode=all, ack_cut=all,
consumer_profile=true, hev_lab=false. Исходный120с неизменён; до результата
runtime acceptance не заявляется.

Router host-key blocker оказался устаревшим: исходная человеческая запись
16.11.2026 19:50МСК подтверждает точный новый ED25519 fingerprint, совпавший
с existing verified known_hosts. Root проверил оба локально; ключ не менял.
Следующий шаг — свежий read-only inventory после независимой переустановки
Entware, с сохранением NDMS queues/policies и отдельным backup до установки.


## 17.11.2026: Entware discovery, DNS ABBA и ошибка памяти NFQ

- `16817239`: одна функция обнаружения Entware opkg для components/systemprobe,
  только canonical /opt/bin|sbin. Firmware PATH больше не источник пакетов.
  Отказ до Runner/state/feed writes; explicit test injection сохранён. Полные
  Windows3packages, vet и Linux crosscompile PASS; independent review воспроизвёл
  и помог исправить промежуточный state-directory write. Actual Linux CI отдельно.
- DNS accepted-prefix293 source-only ABBA43977358908: selected HTTPS4/4 PASS,
  mismatch4/4 FAIL; три sequential prefix стадии1031.14→708.98мс. Это частичное
  измерение, а не доказанная готовность маршрута; новые таймауты не вводились.
- WG full manual43979666415 на source63d5: metadata graph prerequisite PASS;
  первый baseline отказал на read-close-classic, original rollback подтверждён,
  затем GC fatal `found pointer to free object`. Семь последующих arms не запускались.
  Independent audit8 unsafe/syscall source files не установил overflow/lifetime bug.
  Runtime/pprof allocation — место обнаружения, не доказанная причина повреждения.
- `133b89c3` добавляет отдельную диагностическую матрицу44031025392:
  Go1.26.5 checkptr=2, race+checkptr=2 и Go1.26.11 ordinary. Один exact baseline
  source63d5, original240s/internal budgets и profile сохранены. ELF SHA/size
  сверяется до/после; supervisor подтверждает отсутствие потомков до artifact handoff.
  Все3 fullApply FAIL, rollback/cleanup PASS; memory/race/checkptr report не повторился.
  Это не доказательство исправления runtime. [Точные данные](measurements/2026-11-16/wg-memory-diagnostic-133b89c3.json).

Источники: [Go releases](https://go.dev/doc/devel/release),
[Go1.26.5→1.26.11](https://github.com/golang/go/compare/go1.26.5...go1.26.11),
[reportZombies diagnostic issue80799](https://github.com/golang/go/issues/80799).
Точная runtime attribution пока отсутствует. Дополнительный primary-source audit
не нашёл доказанного совпадения этой AMD64 ошибки с выпущенным исправлением.
Не отключались GC, profiling, rollback verification или freshness checks.

Воспроизводимые CI entrypoints:

```sh
sudo env PATH="$PATH" GOTOOLCHAIN=local python3 scripts/wg-tools-comparison/diagnose-memory.py "$PWD" /tmp/new-memory-diagnostic old-checkptr
# Other isolated jobs use old-race-checkptr with Go1.26.5 or patch-production with Go1.26.11.
# The output directory must not already exist; original native fixture dependencies are in the workflow.
```

Native, generic CI и физический router/LAN остаются разными уровнями приёмки.


### 17.11: каталог DNS, отказ неиспользуемой WG оптимизации и offline restore

Полный CI133b89c3 SUCCESS. На38a native StrategyLab/modern rollback/legacy history,
Mihomo LAN и probe comparison проходят; strict DNS и full NFQWS2 Apply ещё FAIL.

Allocation profile исходного DNS38a: providerByIDFor629,72МиБ/0,33CPUс.
d88fd384 строит только постоянные code-only шаблоны один раз и возвращает
независимую копию выбранного провайдера; текущие NextDNS/custom settings
применяются заново. No DNS/config/evidence cache. Пять parity/mutation/concurrency/
freshness тестов normal/race PASS. На Windows lookup known13,464→0,339мкс,
46112→832B/op; это leaf-only fixed-order сравнение.
Source-only full ABBA44035522831 (workflow3a9, source d88, единственная разница
— dnscontrol.go38a/d88) подтверждает sampled allocations2465,18→1978,18МиБ,
но selected4с FAIL4/4 до mismatch/opaque; latencygain не установлен.
Оба ELF44,151,049B; raw SHA и завершение всех потомков проверены. Cumulative
profile включает setup и возможный GC lag, без forcedGC/изменения sampling.
[Полные границы](measurements/2026-11-16/domain-provider-catalog-3a9b0e1c.json).
Команда: `RAZVILKA_DOMAIN_CATALOG_REPO=<checkout> RAZVILKA_DOMAIN_CATALOG_OUTPUT=<new-private-output> RAZVILKA_XRAY_NATIVE=<pinned-fixture> bash scripts/compare-domain-provider-catalog.sh`.

Повтор original WG ABBA9c88 attempt2:4productionApply FAIL,4rollback PASS;
race prerequisite HASH_INPUT,4arms NOT_RUN. Optional scope308 не действовал
при обязательной cleanup-session настоящего Apply; он удалён c200, исходные
current/metadata checks сохранены. Не расширяем scope ради активации оптимизации.
Full Apply allocation profile показывает backendInventoryReadProcBounded389МиБ
из2077МиБ. b6d15c1b переиспользует только очищаемый4096B scratch через sync.Pool:
данные результата независимы, чтения/EOF/EINTR/limit+1/cancel/FD ownership
не изменены. Normal Windows model concurrency/refusals PASS, Linux compile
PASS, independent source review APPROVE; original fullApply normal/race ABBA
на a6dece77 ожидается. sync.Pool может сбрасываться GC и хранить несколько
буферов; это не обещание фиксированных4КиБ общей памяти.
Команда: `python3 scripts/wg-tools-comparison/compare-proc-scratch.py <checkout> <new-output>`.

Offline router backup в отдельной diskless VM:10synthetic PASS,925content/targets
совпали, strict metadata INCOMPLETE из-за реальных symlink0755. Не меняем
исходный manifest на777. Reviewed ext4 drill отдельно; original verifier
и raw failed result сохраняются. Роутер не изменён. [Данные](measurements/2026-11-16/router-offline-restore-20261117.json).


#### Завершение native измерений и offline restore17.11

Оба полных CI38a (44034309197/44034314348) SUCCESS. Scratch source ABBA44036930470:
шесть normal/race контрактов PASS; production4Apply FAIL/4rollback PASS,
sampled allocation median1961,96→1639,18MB (−16,45%); Apply37,2655→37,243с
на неуспешных запусках не является успешным latencygain. Full race4NOT_RUN:
малый metadata fixture фактически копировал весь startup.test, превышающий
startup maxImageBytes16МиБ даже после stripping. Controller64МиБ — отдельный
лимит; прежнее общее объяснение64МиБ было неточным. Production предел не меняем;
готовится отдельный небольшой diagnostic helper. [Исходные данные](measurements/2026-11-16/proc-scratch-a6dece77.json).

Offline ext4 restore завершён: synthetic14+4badmap+3uncertainattach PASS,
actual925entries/578files/263symlinks с exact namespace/uid/gid/mode/mtime и
исходным payload/target PASS; fsck чистый, owned loop отключён. Bundle297entries
22,386B проверен независимо; private payload/config не публиковались.
Изолированная VM выключена/снята с регистрации. RAM image не экспортировался:
его SHA получен внутри гостя, а не повторным host readback. Это не live untar,
не router boot/firmware и не ACL/xattrs/capability proof.
[Результат](measurements/2026-11-16/router-offline-ext4-20261117.json).

Pinned Go1.26.5 ReadDir-аудит отклонил production raw getdents replacement:
сохранить DT_UNKNOWN/fstatat/ENOENT budget/EINTR/close-error поведение требует
слишком большого нового reader. Readdirnames пропускает исходный stat и не
эквивалентен. Вероятный allocation gain не является measured fullflow gain;
production stdlib/toolchain не менялись. Первичные исходники:
[dir_unix.go](https://github.com/golang/go/blob/go1.26.5/src/os/dir_unix.go),
[statat_unix.go](https://github.com/golang/go/blob/go1.26.5/src/os/statat_unix.go),
[poll fd](https://github.com/golang/go/blob/go1.26.5/src/internal/poll/fd_unixjs.go).


#### Малый WG helper и ARM64 loader search

5727f217 выделяет только существующий diagnostic child protocol в отдельный
ordinary stripped CLI1,700,002B; maxImageBytes16МиБ не менялся. Наe3377c67
run44039785005 original producer/kernel-source/ABI/refusal четыре контракта
normal/race PASS, SKIP нет. Родительский race включён; helper моделирует обычный
внешний CLI, не fullApply consumer. Не устанавливались GORACE overrides.
[Проверенные результаты](measurements/2026-11-16/wg-small-helper-e3377c67.json).

973afdba сохраняет отсутствие ARM64 cpuid variant по трём library roots в
существующих capture/digest/closing. Профиль и статические факты не расширены.
Независимое source review APPROVE. Первый полный native capture отказал на
host /opt ownership; это корректная production проверка. Native fixture
изолируется через private mount namespace/tmpfs, без chmod/chown host paths.

Завершение loader gate: d60ca908/run44041702644 — все4 CPUID +4 WG normal/race
PASS без SKIP. a901 сначала скрыл установленный Go вместе с /opt и завершился
до тестов; d60 компилирует исходный normal/race test binary до unshare в
новой защищённой /root папке, затем выполняет его при тех же90с в private
mount namespace. Umount и удаление только собственного binary/каталога входят
в результат. Production guard и старые pins неизменны. Команда:
`sudo env PATH="$PATH" GOTOOLCHAIN=local bash scripts/test-startup-loader-native.sh race`.
[Результаты](measurements/2026-11-16/startup-loader-d60ca908.json).


#### Измерение actual Apply вместо пустого probe счётчика

В full HTTP/Apply стенде выводился `NativeFixtureNFQWSProbePhases(consumer)`,
хотя actual Apply записывает фазы по `NFQWSActiveMaterial`. Измеритель теперь
снимает разницу неизменённых native-only счётчиков вокруг единственной HTTP
популяции и её завершённого cleanup. Смена поколения, незавершённые операции,
переполнение и повторное чтение отказывают; результат не является admission.
Полные CPU/allocation pprof сохраняются после выхода исходного child в новый
явно указанный каталог (каждый до64МиБ, SHA manifest). Исходный FAIL сохраняется.
Полный профиль включает setup/Apply/rollback, вложенные интервалы не складываются.
Следующий integrated native run проверяет Linux исполнение и даст attribution
forward/cleanup; compile/vet и независимое source review оцениваются отдельно.

Read-only source audit обнаружил, что static-version path уже использовался:
2078 IP version starts против564 пар xtables означает минимум1514 пропущенных
пар через существующий exact-profile механизм. Оставшиеся564 пары пока не
разделены на новый original scope, обычную Check и invalidation после ошибки.
Расширение whitelist или отключение настоящего IP Start/Wait не выполнено.

#### Sealed executable: решение по сохранению исходных гарантий

Независимый аудит кода49c25e20, Linux4.9
`69973b830859bc6529a7a0468ba0d80ee5117826` и Go1.26.5 отклонил прозрачную
замену Xray/Mihomo на executable memfd ради устранения свежего source hash.
WRITE/GROW/SHRINK/SEAL действительно фиксируют байты отдельного shmem inode,
но не исходного именованного файла. Actual `/proc/PID/exe` также показывает
новый inode. Текущие source/runtime association и fresh named-source reads
останутся обязательными; их удаление меняет контракт. Seals не сохраняют
исходные mount/noexec/LSM/xattrs/capability условия. PT_INTERP, DSO и assets
отдельны; дополнительная копия требует примерно34–59МиБ на процесс.

Решение: **NO-GO для этой оптимизации при текущем контракте**, production и
роутер не менялись. Это анализ исходников, не результат executable эксперимента.
Закреплённые исходники сохранены вне production tree в
`C:/RAZVILKA-research-20261117/sealed-executable-4.9`.
Первичные источники: [seals/shmem](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/mm/shmem.c),
[exec policy](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/fs/exec.c),
[actual proc exe](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/fs/proc/base.c),
[ELF interpreter](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/fs/binfmt_elf.c).

#### Точный текущий Entware профиль и интеграция startup

5031d70d закрепляет отдельный набор40ELF/30имён расширений из проверенных
пакетов, с точными SHA и двумя буквальными module links. Ожидаемый набор
сравнивается после прежнего полного capture; старые профили сохраняют свой
контракт. Новый профиль не получает static-version/classic-save shortcuts.
[Происхождение пакетов и закреплённые исходники](measurements/2026-11-16/entware-profile-sources-20261117.json).

497a9e4b подключает выбор одного старого/нового профиля в panel startup и
CLI inactivity. Защищённый fixed-path read основного image выдаёт только
SHA hint. После закрытия FD выбранный factory независимо повторяет полный
capture/identity/version child path. Ошибка не запускает другой профиль.
Hint и первая фаза acquire делят исходный абсолютный2с deadline; lifetime
остаётся исходным panel context. Отдельная WG-фаза сохраняет прежние2с.

Independent source review, Windows whole startuptools, targeted app/CLI и
vet PASS; Linux compile/vet и ARM64 compile PASS. На503 native normal/race
4package+4CPUID+4helper PASS; на497 дополнительно4selector, всего16 в каждом
режиме безSKIP. Используется прежний isolated /opt runner, synthetic ARM64
ELF никогда не исполняются. Реальный ARM64 version child/fullvendor acquire
и аппаратный LAN остаются отдельными: текущие UID1001 и missing ip-full
по-прежнему отказывают. Роутер не изменялся.
[503 точные результаты](measurements/2026-11-16/entware-profile-5031d70d.json),
[497 точные результаты](measurements/2026-11-16/entware-selection-497a9e4b.json).

Все пять runs49 завершены: push/PR CI, Mihomo и probe SUCCESS; native
lifecycle11/15jobs PASS. Strict DNS и managed NFQWS failures сохранены,
включая fullLAN rollback-failed при исходном24с cleanup. Успешные profiles
не закрывают эти направления. [26 independently verified rawfiles](measurements/2026-11-16/integrated-49c25e20.json),
[managed33rawfiles/8profiles и исходы](measurements/2026-11-16/managed-phases-49c25e20.json).


## 17.11.2026 — d1: joined cleanup и prepared DNS read

Исходные функции и новые пути независимо проверены. WG candidate e3297ff1,
baseline9971aa1b: отличаются только два kernel-read leaf файла. Все остальные
исходники, helper и тесты одинаковы; normal/race порядок ABBA. Скрипт
`scripts/wg-tools-comparison/compare-wg-cleanup.py CHECKOUT NEW_OUTPUT` требует
Linux root в disposable CI и pinned supervisor. [Run44053144205](https://github.com/ArtixSx/RAZVILKA/actions/runs/44053144205).
4 completedWG calls:8,303481→5,243943с normal;11,612504→8,842598с race.
Числа member reads/bytes внутри режима одинаковы.16CPU/alloc profiles проверены.
Все8 full manualApply FAIL,8 independent cleanup PASS; это улучшение cleanup
read cost, не доказательство работающего маршрута.

DNS candidate76378802: baseline заменяет только checkPreparedWithFiles на точную
функцию997; generic readWithFiles и новые helper definitions одинаковы.
`scripts/compare-domain-prepared-read.sh` с RAZVILKA_DOMAIN_PREPARED_REPO,
RAZVILKA_DOMAIN_PREPARED_OUTPUT и pinned RAZVILKA_XRAY_NATIVE; original12/4с.
[Run44053144237](https://github.com/ArtixSx/RAZVILKA/actions/runs/44053144237).
Selected HTTPS4/4 успешен, process-current delta270→238; cumulative1,572→1,391с.
Все4 mismatch unknown.example.com FAIL4с доrelay; opaque не достигнут.
capture-prepared-read86 completed calls у каждого candidate, включая ошибки.
Это подтверждает фактическое использование пути, а не его readiness.83 comparison
raw SHA и86 artifact files проверены. Scope/cancellation/cleanup не ослаблялись.

Отвергнуто объединение двух NFQ o.observe: второй содержит отдельную Q2 kernel
queue/rules sample; её удаление меняет контракт. Более узкий V2/V3 вариант имеет
менее~0,14CPUс возможной части при сложной provenance-проверке; не реализован.
Также generic DNS mapping/material callbacks нельзя объявить чистыми:
FreshProfile/guard/resolver могут быть внешними callbacks. [Разбор NFQ](measurements/2026-11-16/nfq-observation-no-go-9971aa1b.json),
[разбор DNS critical path](measurements/2026-11-16/domain-mismatch-d1e44b1d.json).

На997 generic push+PR CI PASS; наd1 full managed44053982264 FAIL, loader2PASS.
Программные отказы остаются задачами реализации. Установленный роутер не изменён;
проверки Windows, genericCI, privileged Linux native и router/LAN не подменяют друг друга.


## 17.11.2026 — namespace fixed-FD scratch и проверка измерителя

00fcfec348ec2f7063f9e786545fe996f50ac7b2 сохраняет generic callback reader с
его отдельным буфером и вводит fixed syscall.ReadDirent путь с4KiB stack-buffer.
Один общий parser сохраняет partial names, cookies, DT_UNKNOWN, errors и границы;
два original callers и те же два callers capacity comparator переведены вместе.
Windows package/vet и LinuxAMD64/ARM64 compilation прошли; независимое source review APPROVE.

Actual [namespace-reader44059135619](https://github.com/ArtixSx/RAZVILKA/actions/runs/44059135619):
7exactPASS/noSKIP и8пар×512calls в каждом normal/race. Net allocated bytes
5200→1360 normal,5312→1472 race (−3840Б); allocation count23→24 normal.
Paired median wall delta−1008,644ns normal (6/8 faster),−1658,927ns race (7/8).
Это полный leaf с fresh open/read/close, а не полный Provider/DNS или router/LAN.
Исходный CPU selector−1 был RUSAGE_CHILDREN: thread_cpu_ns недействителен.
Исправленный analysis-v2 исключает этот столбец из пригодных метрик, сохраняя
оригинальный artifact. Вe6122870 две test-only строки исправлены на
syscall.RUSAGE_THREAD; production reader не менялся. [Отчёт](measurements/2026-11-16/namespace-reader-00fcfec3.json).

Полный generic CI44053143961 завершился SUCCESS дляd1e44b1d, до namespace изменения.
[Точная ревизия и raw log SHA](measurements/2026-11-16/ci-d1e44b1d.json). Это не закрывает
последующие изменения или strict full managed/DNS отказы.

Повторный actual run [44061086488](https://github.com/ArtixSx/RAZVILKA/actions/runs/44061086488)
на f54e091482effc536d38124066e219e4970b4493 завершён: по7 PASS/noSKIP,
16 ordered rows (8 пар по512 calls) normal/race. RUSAGE_THREAD действительно
использован, все значения ненулевые; API ZIP digest, четыре raw SHA и пересчёт
пяти метрик проверены независимым reviewer. Парная медиана wall delta
−947,369/−957,791ns, threadCPU −855,469/−830,078ns normal/race. Net bytes
−3840Б, allocation count +1. Разброс и лишь8пар ограничивают вывод; абсолютные
значения двух разных hosted runs не сравниваются как эффект изменения.
[Отчёт](measurements/2026-11-16/namespace-reader-f54e0914.json),
[review](measurements/2026-11-16/namespace-reader-f54e0914-review.json).
Воспроизведение: workflow `.github/workflows/namespace-reader.yml` на том же SHA.

Отдельный identity regression44059135497 на00fcfec3 завершился всеми3 jobs PASS:
100/100 live TLS+cleanup, оба rollback cuts normal/race, historical reader retry.
Generic platform/root skips явно сохранены в
[отчёте](measurements/2026-11-16/identity-contract-00fcfec3.json); они не считаются
native проверками. Это не результат physical router/LAN и не закрытие strict DNS.

## 17.11.2026 — раздельные границы DNS и managed Apply

`6b0b246a` добавляет native-only request-local Guard/decision/compare до и после
dial:32 accepted carriers, максимум8 записей на carrier, фиксированные labels,
без адресов/имён/FlowID. Snapshot отделяет начатое от завершённого, возвращает
копию и не принимает completion старого поколения. Context budget здесь
серверный, не4с клиента. Независимое review устранило вызовы интерфейсов под
mutex измерителя; normal/race проверки stale completion, concurrency и bounds
прошли в actual run44065917683. Ordinary build — no-op, исходные callbacks,
порядок ошибок, dial/relay и cleanup сохранены.

В [actual6b](measurements/2026-11-16/domain-forward-6b0b246a.json) mismatch
останавливается до post-dial check, внутри direct-current-post. Guard389,147мс
и baseline decision283,862мс относятся к pre-dial конкретного request2;
сравнение решения занимает0,939мкс. Прямой TCP connect измерен микросекундами.
Это уточнение места исчерпания client4с, не доказательство доли всей задержки
и не ускорение относительно f54 на другом runner. Direct-deny прошёл;
canceled-ready не прошёл первую публикацию12с, поэтому GEN2 там не исследован.
Воспроизведение: research-lifecycle.yml focus=domain на6b0b246a; исходный debug
fixture, original12/4с, профили и ошибки сохранены.

`1bd49fc8` аналогично разделяет managed policy effects/guard/complete-readback,
negative-before/negative-after/positive-after counter и prepared-owner read.
Сохраняет исходные короткие замыкания и ошибки; cause означает последнюю
достигнутую ветку, не точное сравнение внутри составного условия. Native-only
до5 интервалов на вызов, invocation ordinal не равен identity операции.
Independent review, Windows regression/vet и Linux compile PASS; actual run
44066476354 focus=managed сохраняет исходные budgets, ACK/ECHILD и wrong-source.
