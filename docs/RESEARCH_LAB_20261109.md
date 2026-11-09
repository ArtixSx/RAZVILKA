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
