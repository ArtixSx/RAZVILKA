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
| nfqws2-keenetic | Init/common и netfilter workflow — материал для platform-specific retry и applied-state audit. RAZVILKA имеет ownership/rollback. | Исходники/лицензия получены; local native NFQUEUE воспроизведение BLOCKED отсутствием Linux namespace в этой Windows лаборатории; отдельный Linux CI остаётся доступным направлением, router acceptance требует аппаратуры. Не запускать installer на host. Root дальнейший владелец. |
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
