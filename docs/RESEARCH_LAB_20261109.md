# Исследование и лабораторные проверки, 2026-11-09

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


### Стадии одного HTTP обмена

Дополнительно изучен исходник поставляемого Go1.26.5
`src/net/http/httptrace/trace.go` (BSD-style Go license): WithClientTrace
составляет hooks, callback может исполниться асинхронно после возврата запроса.
Новая optional telemetry использует этот стандартный API, mutex и закрываемый
bounded snapshot; чужой код не копируется. Продолжение существующего подхода
blackbox-exporter к разделению сетевых стадий, без переноса его verdict в RAZVILKA.

CLI nodeeval получает отдельные local resolver / SOCKS / TLS / TTFB / body
наблюдения, привязанные к текущему node/service/profile result. Redirect —
отдельный RoundTrip; multiple internal dial/TLS явно не изображаются одним
измерением. Raw URL/error/body/certificate не попадают в JSON. Native queue
включает эти наблюдения только в отдельном CPU-profile проходе; обычные paired
samples не получают telemetry overhead. Существующие service predicates,
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
