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

Первый [native run42557481299](https://github.com/ArtixSx/RAZVILKA/actions/runs/42557481299)
на `71b6f969579833e3ba217b331dc3c1a24bb150f7` завершён SUCCESS. Сырые CSV,
environment, проверяющий анализатор и машинный отчёт сохранены в
[ci-71b6f969](ci-71b6f969/paired-analysis.json): обе ревизии содержат ожидаемые
52 Check и39 queue samples, exact verdicts/cleanup/идентичности проверены.

| Сценарий, N=12 повторов | Baseline p50/p95, мс | 71b6f969 p50/p95, мс |
| --- | ---: | ---: |
| Полный live Check | 407.049 /411.030 | 406.042 /407.920 |
| Single enqueue→server completion | 756 /769 | 752 /767 |
| Selected batch enqueue→server completion | 2622 /2639 | 2617 /2630 |
| All VLESS enqueue→server completion | 2637 /2656 | 2613 /2638 |

Ускорение на этом этапе не доказано. Первый live sample: 409.803→407.337мс,
не входит в N12. Dead-service p95 вырос414.192→487.176мс: sample2 configuration
занял100мс; этот выброс сохранён. В all-vless sample1 есть один RSS read error;
RAM gain не заявлен. На контролируемом стенде минутная задержка VLESS не
воспроизведена. На71b p50 runtime_start=1мс, runtime_ready=101мс,
route_identity=0мс: ожидание следующего readiness poll стало отдельной гипотезой
для следующего парного измерения, а не поводом ослабить service gate.

В том же run настоящий Mihomo handler и service/common cleanup PASS без SKIP.
Handler3641мс: подготовка631мс, adapter3009мс, sub-ms closing/finalize;
клиентский wall3642.777мс. N=1, не общий benchmark: [подробности](mihomo-context.md).
Generic CI оценивается отдельно. Исторический `a2d1c3c7` SUCCESS не относится
автоматически к этой интеграции; отдельные DNS/Mihomo failures остаются открытыми.

## Вторая интеграция по результатам первого измерения

Контролируемый [readiness опыт](cadence/README.md) сравнивает71b с ранними
проверками: готовность через25мс наблюдается≈101→31.6мс, через80мс≈101→102.9мс.
Это modeled process/native SOCKS, а не полный Xray. Паузы10/20/40/30мс дают
только три дополнительных ранних наблюдения; затем остаётся100мс cadence и
тот же8с deadline. Поздний greeting, cancel и cleanup регрессии проходят.

Из UTC timestamps восстановлен inter-check gap≈1322мс:
[данные](ci-71b6f969/queue-gap-analysis.json). Исходник подтверждает1с обязательного
NotBefore после успешного непоследнего шага. Новая continuation не обходит
планировщик: один bounded step, joined cleanup и свободная lease, успешный
durable checkpoint, unlock, затем wake. Приоритет Stop/recovery, burst3,
ошибочные WAN30с/busy5с, CAS/writer failure и restart подтверждены адресными
проверками. Остальные≈322мс не объявляются лишними: history и source guards
сохранены. Подтверждение выигрыша — отдельный итоговый native прогон ниже.

Исправлено и происхождение стадий nodeeval: результат с чужим node/service/
engine/profile или неверными start/end/expiry больше не отдаёт стадии текущего
кандидата. Семь регрессий воспроизводили ошибку до исправления; после PASS.
Самостоятельно измеренные wrapper wait/preparation/check wall сохраняются.

## Итоговый native результат 8c869c76

[Run42559470862](https://github.com/ArtixSx/RAZVILKA/actions/runs/42559470862)
завершён SUCCESS для `8c869c76caf36eb6194675b66cc9bb0d4cef7c69`.
Новый baseline0e и candidate8c выполнены на одном runner с одинаковыми Xray,
fixture, алгоритмом и выборками. Это самостоятельное парное сравнение;
не сравнивать8c с71b другого runner как эксперимент до/после.

Сырые файлы, хеши, проверка identities/verdict/cleanup и воспроизводимый
анализатор: [ci-8c869c76](ci-8c869c76/paired-analysis.json). В каждой ревизии
52 Check и39 queue строки; N12 повторов каждого сценария плюс отдельный first.
У каждого live Check один физический service request; отрицательные и
отменённые результаты не стали PASS. Queue evidence соответствует точному
node/service/network/probe и expected/observed route.

| Сценарий, повторные N12 | Baseline p50 / p95, мс | 8c p50 / p95, мс |
| --- | ---: | ---: |
| Full live Check, включая cleanup | 404.777 /435.624 | 314.996 /322.977 |
| Недоступный сервис, тот же полный Check | 405.286 /412.541 | 316.138 /320.015 |
| Отмена с joined cleanup | 365.044 /368.164 | 275.422 /278.369 |
| Недоступный endpoint до запуска движка | 8.404 /8.955 | 8.515 /9.400 |
| Single enqueue→server completion | 752 /765 | 657 /671 |
| Selected2 enqueue→server completion | 2615 /2635 | 1444 /1462 |
| All2 enqueue→server completion | 2633 /2645 | 1451 /1469 |
| Selected2 POST→HTTP readback, monotonic | 2617.319 /2637.652 | 1447.440 /1464.198 |

На этом стенде live p50 сократился на22.18%, selected2 completion на44.78%.
Первый live sample:408.708→313.659мс (отдельно от N12, не cold OS cache).
Runtime_ready p50=11мс, start=1мс; cleanup≈101мс сохраняется.
Реконструкция из UTC timestamps даёт inter-check selected p50
1324.399→333.257мс, all1330.692→335.211мс:
[данные](ci-8c869c76/queue-gap-analysis.json). Оставшиеся admission/history
затраты не удалены и не выдаются за измеренный отдельный компонент.

CPU self+joined child считается для каждой строки, затем quantile. Live
p50/p95:100.149/107.552→92.403/106.322мс; selected2:
1197.035/1223.895→1042.360/1067.217мс. Это CPU затраты тестового процесса вместе
с fixture, не показатель загрузки роутера. Существенного снижения RSS нет.
RSS read errors сохранены: baseline single sample1; candidate single1/3/5.
Пустое наблюдение памяти не считается нулём.

Mihomo actual service/common cleanup и HTTP handler также PASS без SKIP на8c:
handler3331мс, preparation577мс, adapter2754мс, postcheck/finalize<1мс,
HTTP wall3332.960мс. N1, самостоятельный сценарий. Отличие от71b не называется
ускорением: эти Mihomo прогоны не являются парным опытом. [Журнал](mihomo-context.md).

Минутные задержки на контролируемых VLESS fixtures не воспроизведены.
Фиксированный порядок baseline→candidate, N12, общий OS cache и modeled WAN
ограничивают перенос результатов на медленную flash/CPU, публичные узлы и
физический роутер. Это не измерение browser paint, Apply→LAN-ready или MTProto.

## Границы приёмки

Реальные Windows Xray/Toxiproxy опыты — отдельное HTTP-body доказательство,
не TLS/ExactNodeChecker/Telegram/MTProto/LAN. Native Linux проверяет полный
checker/очередь/cleanup в модели WAN; физический NC-1812 и LAN не проверены.
Программные DNS/Mihomo/NFQWS lifecycle задачи остаются в
[едином roadmap](../../../ROADMAP.md), не объявлены внешними блокерами.
Для аппаратного этапа нужны выделенный роутер/LAN-клиент и явная авторизация;
[сценарий подготовлен](../../../ROUTER_ACCEPTANCE_RU.md).

## Завершённый общий CI для кода 8c869c76

Push [42559470926](https://github.com/ArtixSx/RAZVILKA/actions/runs/42559470926) и PR [42559473824](https://github.com/ArtixSx/RAZVILKA/actions/runs/42559473824) завершились SUCCESS. Normal/race, vet, UI, сборки и проверки Entware прошли. Native [42559470862](https://github.com/ArtixSx/RAZVILKA/actions/runs/42559470862) также SUCCESS. [Ответы API с SHA и jobs](ci-8c869c76/completed-runs.json). Это проверки указанного кода, не аппаратная приёмка и не автоматическое доказательство для будущих изменений.
