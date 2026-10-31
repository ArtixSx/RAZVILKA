# Полная native VLESS проверка на изолированном стенде

Источник: [run 41251195752, commit 6be05d55](https://github.com/ArtixSx/RAZVILKA/actions/runs/41251195752/job/124684879983),
Linux amd64, Go 1.26.5, официальный Xray **26.3.27**. Архив SHA256
`23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`,
извлечённый бинарник SHA256
`8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`.
Точные версии, kernel и границы опыта записаны в `environment.txt`.

Это настоящий Xray VLESS XHTTP TLS server/client, production validation,
исходный OS process controller/receipt/cleanup, физические UDP DNS, TLS
с доверенным тестовым CA, SOCKS, парный direct/proxy egress и сервисный HTTPS.
Namespace содержит только loopback с локальными public-format адресами;
внешнего маршрута нет. WAN identity задана моделью, ответ сервиса задержан
на **40 мс**. Роутер, LAN, реальный WAN, внешние узлы, Apply и reboot этим
опытом не проверяются.

`historical-request-reference` исполняет текущий полный Check, скрывая только
локальную `literalServiceObservationKey` у исходного serviceProbe. Поэтому
повторяется прежний второй запрос к тому же literal IP. Это воспроизводимый
reference старого алгоритма, **не запуск исторического release-бинарника**.
`current-reuse` исполняет production Check без этой обёртки. DNS, scope,
валидация, egress, процесс и cleanup в обоих режимах одинаковы.

Измеряется монотонное время **от входа в Check до его возврата после cleanup**.
Первый live sample записан отдельно; затем N=12 повторных. Каждый Check,
включая повторный, создаёт и завершает новый native клиент. Отдельно
перезапускается весь Go процесс между алгоритмами, чтобы CA/SystemCertPool
не переносились между ними. Первые sample остальных сценариев не называются
холодным запуском процесса. Квантили ниже — nearest-rank, p50=sample6,
p95=sample12 отсортированной повторной выборки.

| Сценарий, N=12 | Reference p50 / p95, мс | Current p50 / p95, мс |
| --- | --- | --- |
| Live HTTP 204 | 502.681 / 506.826 | 396.741 / 398.146 |
| Сервис HTTP 503 | 397.119 / 564.884 | 397.594 / 448.912 |
| Отмена после входа в реальный сервисный запрос | 356.381 / 493.929 | 357.107 / 362.588 |
| Остановленный native VLESS server | 6.140 / 6.746 | 6.256 / 6.852 |

Live p50 уменьшился на 105.940 мс (21.1%) в этом опыте. Счётчик физического
HTTPS handler подтверждает **2→1** сервисных запроса на live Check. При HTTP
503, отмене и недоступном узле повторное использование успешного результата
не возникает; из разброса этих выборок ускорение не выводится.

В current live Check наблюдаемые этапы p50/p95: configuration 14/15 мс,
route_identity 103/104 мс, egress 64/65 мс, service 104/105 мс,
cleanup 100/101 мс. `protocol` и `egress` описывают один перекрывающийся
интервал; складывать этапы нельзя. Нулевое целое `duration_ms` означает
разрешение этой диагностики, а не обещание нулевой работы. Полный wall timer
включает также native version admission до первого именованного этапа.

На всех live/dead-service/cancel sample original cleanup имеет статус
`verified`, дополнительная проверка не находит работающего клиента.
При dead-node temporary client не запускался. Сырые CSV содержат каждую
попытку, UTC отметки, полное монотонное время, `Check.LatencyMS`, cleanup,
реальный счётчик запросов и существующие stages. Профили/credentials не
экспортируются. CPU/RSS, UI paint и аппаратная производительность не измерены.

## App queue и HTTP

В этом исходном run отдельный App тест **отказал до native Check**:
presentation inventory не устанавливал настоящий бинарник в путь detector.
Полный исходный `native-performance.log` сохранён, результат не скрыт и не
смешан с успешными standalone выборками. Fixture исправлен в `4551f490`:
тот же закреплённый Xray устанавливается в `/opt/bin/xray` только внутри
нового mount namespace с tmpfs `/opt`; никакой grant/production gate не
подменяется.

После исправления [полный D job прошёл на 4551f490](https://github.com/ArtixSx/RAZVILKA/actions/runs/41251595527/job/124686087311):
оба standalone алгоритма и весь App queue/HTTP сценарий. Очередь измерена
текущим алгоритмом; reference полного Check выше и App queue не смешиваются
в сравнение разных интервалов. Источники очереди: `queue-http-current.csv`,
`queue-http-environment-4551.txt`, `queue-http-run-4551.log`.

| App сценарий, N=12 | First admission, p50 / p95, мс | Enqueue→server completion, p50 / p95, мс | POST→HTTP readback, p50 / p95, мс | Сам GET, p50 / p95, мс |
| --- | --- | --- | --- | --- |
| Single, 1 узел | 26 / 36 | 733 / 748 | 734.368 / 750.357 | 0.409 / 0.935 |
| Selected batch, 2 узла | 26 / 37 | 2582 / 2601 | 2584.734 / 2603.824 | 0.558 / 1.260 |
| All VLESS, 2 узла | 26 / 38 | 2588 / 2603 | 2590.291 / 2606.250 | 0.543 / 1.107 |

Ещё по одному первому sample сценария сохранено отдельно. Все 65 actual
native Checks в этих 39 jobs завершились с положительным сервисным доказательством
и `cleanup=verified`; фикстура проверяет число настоящих вызовов Check, а не
подставляет результат. Два элемента batch также сохраняют штатное ожидание
очередного шага исходного reconciler. Время App включает admission и работу
истории/Store; оно не равно сумме или умножению standalone Check.

Воспроизведение в отдельном Linux CI host с уже проверенным официальным
бинарником и Go cache:

```sh
sudo env PATH="$PATH" GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" \
  RAZVILKA_XRAY_NATIVE=/absolute/verified/xray \
  RAZVILKA_NODE_PERF_OUTPUT=/absolute/output \
  sh scripts/check-node-native-performance.sh
```

App использует настоящие Store, исходный durable reconciler, exclusive gate,
установленный controller inode и `NewNodeHistoryAdmission`. Контролируемое
ожидание admission — 25 мс до первого вызова dispatcher; дальнейшие вызовы
dispatcher используют настоящий `time.Now()` и polling 10 мс без сдвига
часов. Это управляемый такт стенда, не измерение штатного scheduler cadence.
HTTP delivery измеряется реальным TCP HTTP client к App handler; это не
браузерный event loop/paint. Enqueue/admission/server completion и HTTP
получение разделены; интервалы не складываются.
