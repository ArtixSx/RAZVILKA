# Локальные измерения 31.10.2026

Среда: Windows amd64, Go 1.26.5, 16 логических CPU. Все TLS/SOCKS sockets
локальные; public literal назначения перенаправляет тестовый SOCKS server.
Секреты и внешние подключения не используются. Это измерение транспорта
на стенде с моделируемым runtime/admission, не аппаратный результат роутера.

## Изменение этого прохода: повтор первой literal-IP пробы

`nodecheck_literal_reuse_test.go` использует настоящий pinned HTTPS через SOCKS,
доверенный тестовый CA, ответ HTTP 204 с искусственной задержкой 40 мс.
Запуск native proxy, validation, egress, identity и cleanup runtime моделируются.
Время — весь `checker.Check` этого стенда; время процесса и LAN не измерены.

До исправления guarded service probe уже обращался к первому literal IP, затем
service_ip повторял тот же HTTPS запрос. После исправления успешная проба
используется внутри одного Check после повторного DNS и scope admission.
Первый IP, исчезнувший из свежего DNS, не заменяет проверки нового IP.

| Выборка | До, мс | После, мс |
| --- | --- | --- |
| Первый sample | 94.047 | 50.580 |
| Повторные, N=12, p50 | 93.651 | 50.622 |
| Повторные, N=12, p95 nearest-rank | 94.937 | 51.990 |
| HTTP-запросов на Check при одном IP | 2 | 1 |

Сырые результаты: `literal-before.txt`, `literal-after.txt`. Before снят на
интеграционной базе с добавленным только nil-default test CA seam и тестом,
ещё без повторного использования первой пробы. After — после исправления.
Первый sample не следует считать измерением холодного запуска native ядра.
Для воспроизведения before нужен вариант до оптимизации, а не текущий тест,
который теперь требует ровно один запрос.

```powershell
$env:RAZVILKA_EGRESS_PERF='1'
C:/Projects/RAZVILKA/tools/go/bin/go.exe test ./internal/dataplane -run '^TestGuardedLiteral' -count=1 -v
```

## Уже существовавшая параллельная direct/proxy пара

`egress-local.csv` сравнивает последовательный reference с действующей
`measureNodeEgressPair` на одинаковом production HTTPS getter. Параллельная
оптимизация уже была в a36f5343 и не является новым результатом этого прохода.
Live/503 ответы задержаны на 40 мс, stalled ограничен 80 мс на попытку.
Оба направления возвращают одинаковый тестовый IP: это измеряет получение
наблюдений, но никогда не подтверждает пригодный proxy egress.

| Сценарий, N=12 повторных | Sequential p50/p95, мс | Paired p50/p95, мс |
| --- | --- | --- |
| Live | 84.965 / 85.533 | 42.596 / 43.093 |
| HTTP 503 | 84.706 / 86.169 | 42.451 / 43.076 |
| Stalled | 160.735 / 161.279 | 80.248 / 80.537 |

Ещё по одному первому sample на режим записано отдельно. Cancel→joined return
N=12 ниже разрешения сохранённого значения 0.001 мс; это не обещание нулевой
задержки. Дополнительное ожидание освобождения локальных HTTP handlers и TLS
connections после отмены 1.020–1.523 мс; максимум по всем sample 1.606 мс.
Оно не доказывает очистку managed процессов, интерфейсов или kernel rules.

```powershell
$env:RAZVILKA_EGRESS_PERF='1'
$env:RAZVILKA_EGRESS_PERF_CSV='C:/path/to/egress-local.csv'
C:/Projects/RAZVILKA/tools/go/bin/go.exe test ./internal/dataplane -run '^TestNodeEgressLocalPerformance$' -count=1 -v
```

CPU utilization, RSS, очередь→admission, validation/native start, Apply,
LAN verification, UI delivery, WAN/reboot и длительная устойчивость здесь
не измерены. CSV содержит Go HeapAlloc и число goroutines; они не равны RSS
и числу принадлежащих приложению native процессов. Повторный sample всегда
открывает новое TLS соединение (production getter отключает keepalive).
Race локально недоступен: `-race requires cgo`. Linux CI и роутер проверяются
отдельно. Временные пороги ускорения не превращены в flaky assertions.

## WG/WARP/AWG: бюджет наблюдения handshake

`handshake-before.txt` и `handshake-after.txt` сохраняют выдержки фактического
вывода инструмента, снятого до и после изменения `confirmHandshake`. Это модель
контекстно-зависимого command runner: она ждёт завершения переданного контекста;
реальные `wg`, модуль ядра, сеть, регистрация аккаунта и trace не запускаются.
N=1 для каждого EngineID; p50/p95 и аппаратное ускорение из этой выборки
не выводятся. До исправления команда получала 500 мс при handshake budget
30 мс; после вся попытка, включая команду, ограничена 30 мс.

| EngineID | До, мс | После, мс |
| --- | --- | --- |
| warp-wg | 500.7291 | 30.1095 |
| wireguard | 500.5454 | 30.5591 |
| amneziawg | 500.7960 | 30.3439 |

Отдельное воспроизведение показало: возвращённый одновременно с отменой свежий
handshake timestamp раньше принимался; теперь возвращается `context.Canceled`.
Родительский deadline сохраняет `context.DeadlineExceeded`. В итоговом тесте
проверяется deadline, выданный команде, а не жёсткий wall-clock порог на загруженном
CI runner; исходные диагностические времена оставлены в выдержках вывода.
Неотзывчивый runner нельзя принудительно завершить одной передачей контекста;
реальный owned executor и cleanup требуют своих native проверок.

## Наблюдение очереди → admission → завершение → чтение

`queue-local.csv` снят существующим reconciler/operation gate через HTTP
handlers `POST /node-checks` и `GET /node-checks/current` на тестовом приложении.
Это контролируемая модель: каждый checker выполняет четыре ожидания по 5 мс
(validation/egress/service/cleanup моделируются), чужой exclusive lease
удерживается ещё 10 мс. Native ядро и реальная сеть не запускаются.
Пригодность узла заменена моделью, а durable queue, admission и сохранение
результата исполняются настоящим кодом приложения. Времена не являются
ускорением и не подтверждают точность маршрута.

| Сценарий | Размер batch | N повторных | enqueue→server completion p50/p95, мс |
| --- | --- | --- | --- |
| Single | 1 | 12 | 62 / 64 |
| Selected batch | 2 | 12 | 108 / 112 |
| All VLESS fixture | 2 | 12 | 108 / 121 |

Ещё по одному первому запуску отдельного fixture записано как `first-fixture`.
Повторные sample также создают новый fixture: это повторения опыта, а не
измерения прогретого native процесса. All VLESS содержит только два узла,
не реальный каталог. В тесте `now` планировщика продвигается между шагами;
реальный такт координатора и ожидание следующих rounds этим не измерены.
`http_readback_ms` — вызов настоящего HTTP handler в `httptest`, без TCP-сети
и без браузерного event loop. Windows amd64, Go 1.26.5; CPU/RSS не измерены.

```powershell
$env:RAZVILKA_QUEUE_PERF='1'
$env:RAZVILKA_QUEUE_PERF_CSV='C:/path/to/queue-local.csv'
C:/Projects/RAZVILKA/tools/go/bin/go.exe test ./internal/app -run '^TestDurableNodeLocalTimingExperiment$' -count=1 -v
```

Новый API diagnostic `job.timing` использует существующее durable `CreatedAt`
для enqueue и процессное время получения первого exclusive lease для admission.
После перезапуска admission неизвестен (`null`), а время окончания остаётся
существующей durable отметкой. На панели отдельно показаны очередь до первого
допуска, общее время до серверного завершения/снимка, полное время последней
проверки (уже включающее cleanup), существующие этапы и получение текущего
ответа браузером. Эти интервалы не складываются: этапы могут пересекаться,
readback относится к получению снимка отдельно от серверного времени.
Browser readback измеряется только после существующего session/epoch guard
и привязывается к job ID; чтение shared cache тоже не выдаётся за native работу.
Отсутствующий или обратный timestamp не превращается в 0 мс.
