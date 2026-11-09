# Исследовательская интеграция 09.11.2026

База: `0e2db5ab2120b20e249e3da7a8e861b558506550`, после четырёх локальных
коммитов поверх опубликованного draft PR #23 (`a2d1c3c7`). Исходная рабочая папка
`C:/Projects/RAZVILKA/bypass-integration` сохранена. Bundle refs, raw WIP и
временные каталоги: `C:/RAZVILKA-research-20261109/preserved-local/`.
Авторство истории, опубликованные теги, production и роутер не изменялись.

## Проверенная дельта

- Exact checker ограничивает ожидание SOCKS приватным context с бюджетом 8с;
  уже начатый обмен тоже прерывается. Поздняя готовность не принимается.
- `runtime_start`, `runtime_ready`, `route_identity` разделены. API/UI выводят
  только разрешённые ID/status/duration; они не повышают доступность сервиса.
- `nodeeval` сохраняет стадии, wall check, подготовку и ожидание кандидата.
  Последнее — последовательное ожидание внутри CLI, не durable App queue.
  Финальный summary учитывает recovery; failure/cleanup semantics сохранены.
- Mihomo probe API сохраняет подготовку, adapter check, closing guard и
  финализацию, в том числе в JSON отказах. Это время handler до сериализации,
  а не HTTP round trip; middleware queue не измеряется. Подробный контракт,
  подтверждённые исторические затраты и ссылки: [Mihomo](mihomo-context.md).
- Код чужих реализаций не копировался. Источники, SHA/лицензии, цена и решения:
  [лабораторный журнал](../../../RESEARCH_LAB_20261109.md).

## Windows/amd64, Go 1.26.5

Одинаковый loopback SOCKS fixture выпускает правильный greeting на 8100мс
после запуска моделируемого ProcessController. TCP/SOCKS настоящий; сам движок,
WAN и маршруты здесь не участвуют. N=1, это регрессия корректности, не benchmark
типичного ускорения VLESS.

| Версия | Время | Результат |
| --- | ---: | --- |
| 0e2db5ab | 8100мс | Greeting ошибочно принят после предела; regression FAIL |
| Исправление | 8000мс | DeadlineExceeded, поздняя готовность отвергнута; PASS |

Сырые [до](readiness-before-final.txt), [после](readiness-after-final.txt),
[описание опыта](readiness-measurement.json).

```powershell
& C:/Projects/RAZVILKA/tools/go/bin/go.exe test ./internal/dataplane -run '^TestExactNodeReadinessRejectsLateSOCKSGreeting$' -count=1 -v
& C:/Projects/RAZVILKA/tools/go/bin/go.exe test ./cmd/nodeeval -count=1
node scripts/test-node-job-timing-ui.mjs
node scripts/test-node-measurements-ui.mjs
node scripts/test-node-browser-ui.mjs
```

Интеграционный focused набор ExactNode/SOCKS/Dispatcher/cancellation/egress/
scope/WG/AUTO/capabilities/DTO: dataplane PASS16.807с, app PASS13.801с,
nodestore PASS1.029с. UI measurement26 cases и job timing PASS; независимый
reviewer дополнительно выполнил node-browser cases. Эти значения — время тестов,
не время сетевого маршрута. Отдельный полный nodeeval PASS1.148с; Mihomo/DTO
focused App PASS0.369с. `go vet ./cmd/nodeeval ./internal/dataplane ./internal/app`
PASS. Один vet во время незавершённой параллельной записи timing-файла отказал
на отсутствующем типе; после заморозки и интеграции полный адресный vet пройден.

## Linux native и CI

Workflow `.github/workflows/research-probes.yml` запускает существующий
`scripts/check-node-native-performance.sh` на baseline и candidate в одном job,
с одним Xray26.3.27 (archive SHA256 закреплён), алгоритмом `current-reuse`,
стабильными TLS/DNS/egress endpoints и controlled40ms сервисом. Используются
частные network/mount namespaces; live router не участвует.

Ожидается 52 Check +39 queue строки на ревизию: first sample отдельно от12
повторов каждого сценария. p50/p95 считаются nearest-rank внутри сценария.
Fixed baseline-then-candidate order допускает влияние cache/load; first sample
не является холодным запуском всей ОС. Пустой child RSS не означает ноль.
Стадии перекрываются, их сумма не считается полным временем.

Новые CI/native результаты будут добавлены после завершения соответствующего
SHA. Исторический generic CI `a2d1c3c7` SUCCESS не относится автоматически к этой
интеграции; его отдельные DNS/Mihomo failures остаются открытыми.

## Границы приёмки

Реальные Windows Xray/Toxiproxy опыты — отдельное HTTP-body доказательство,
не TLS/ExactNodeChecker/Telegram/MTProto/LAN. Native Linux проверяет полный
checker/очередь/cleanup в модели WAN; физический NC-1812 и LAN не проверены.
Программные DNS/Mihomo/NFQWS lifecycle задачи остаются в
[едином roadmap](../../../ROADMAP.md), не объявлены внешними блокерами.
Для аппаратного этапа нужны выделенный роутер/LAN-клиент и явная авторизация;
[сценарий подготовлен](../../../ROUTER_ACCEPTANCE_RU.md).
