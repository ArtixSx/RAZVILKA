# Сохранённое состояние после завершения текущих проверок

Новые реализации и прогоны остановлены по просьбе пользователя из-за остатка
недельного лимита. Уже запущенные CI дождались завершения. Это контрольная точка,
не завершение исходного задания и не готовность выпуска. Merge/release/deploy
и физический роутер не затрагивались.

## Код

- Опубликованный draft PR23: `a2d1c3c77edd194741e5c46610de09ebb2570601`,
  ветка `work/bypass-integration-20261031`.
- В `bypass-integration` дополнительно сохранён интегрированный код до `ab0f10e7`:
  исходные raw benchmark данные, Stop diagnostics и exact stopped-plan wire
  images. Последний исправляет подтверждённые ошибки первого сравнения и retry,
  но следующий native Stop отказ ещё остаётся. Эти дополнительные commits
  **не опубликованы**, чтобы не запускать новый CI после ограничения лимита.
  На интеграции targeted Windows DP/App PASS1.104/0.993с и tagged Linux vet PASS.
- `work/c-current-validation-20261102`, `098abc69`: reviewed readonly batch
  без двух дублирующих metadata обходов. Сохраняет обе проверки каждого child
  и полный внешний SHA. Отдельная ветка; не перенесена в основной checkout.
- `work/domain-detachment-validation-20261102`, `f71db55f` (включает `0b6b3ceb`):
  reviewed failed-preparation cleanup и точный cancel witness. Отдельная ветка,
  целевой native сценарий пока не подтверждён.
- `tools/mihomo-workflow-validation-20261102`, локальный `2a8bbf09`: reviewed
  фиксированные подшаги диагностики stopped-plan; без push и нового CI.
- `tools/mihomo-same-boot-validation-20261102`, HEAD `76c67f32`: 22 сохранённых
  WIP paths — metadata resume/restart и отдельные незавершённые prior-history
  изменения. **Не переносить весь WIP одним пакетом.** Reviewed metadata/restart
  нужно перенести на reader9 и использовать исходный `checkHistory()`.
  `tools/mihomo-same-boot-resume-20261102` чистый, HEAD `a2d1c3c7`; порт не начат.

Пользовательские правки `console-autonomy.js` и прежние временные каталоги
сохранены. Владельцы направлений и общий список — [ROADMAP](../../../ROADMAP.md).

## Завершённые проверки

| Код | Полный CI | Отдельная native приёмка |
| --- | --- | --- |
| Published main `a2d1c3c7` | [push41452796557](https://github.com/ArtixSx/RAZVILKA/actions/runs/41452796557) и [PR41452807579](https://github.com/ArtixSx/RAZVILKA/actions/runs/41452807579) SUCCESS | Backup/StrategyLab pair, VLESS, WG, cold recovery, health PASS. B/C/warm FAIL. Same-boot normal PASS91.50с; race не дошёл до consumer: producer `route-process-unavailable`, rollback/verify PASS. ACK cuts SKIP. |
| C `098abc69` | [41453271652](https://github.com/ArtixSx/RAZVILKA/actions/runs/41453271652) SUCCESS | Actual two-child batch×12, четыре metadata проверки, normal/race PASS. Full LAN Apply FAIL. Новый completed-workflow speedup не заявлен. |
| Warm `4bdb6764` | [41454454397](https://github.com/ArtixSx/RAZVILKA/actions/runs/41454454397) SUCCESS | [41454454580](https://github.com/ArtixSx/RAZVILKA/actions/runs/41454454580): actual post-CAS503 rollback PASS; lifecycle/settlement FAIL на stopped-plan-ack после Apply/Check/native cleanup. |
| B `f71db55f` | [41455450394](https://github.com/ArtixSx/RAZVILKA/actions/runs/41455450394) SUCCESS | [41455450260](https://github.com/ArtixSx/RAZVILKA/actions/runs/41455450260) FAIL. Baseline и focused Linux race DP PASS15.119с; все три новых preparation cases остановились на GEN1 DNS30s, новая cleanup lane не упражнялась. |
| Offline `76c67f32` | [41452124888](https://github.com/ArtixSx/RAZVILKA/actions/runs/41452124888) SUCCESS | Normal108.20с PASS; race120с FAIL после двух terminal ACK. Private-set normal/race PASS; cuts SKIP. |

Полный CI этих разных commits нельзя выдавать за полный CI локального
интегрированного `ab0f10e7` или за завершение перечисленных native-сценариев.

## Измерения и оставшаяся работа

- VLESS N12: wall p50/p95 **509.784/512.177 → 405.332/408.381мс**;
  [условия и данные](../../../measurements/2026-11-01/native-vless-resources-570b/README.md).
- Два полных SHA файлов, N12: normal p50/p95
  **115.502/121.091 → 62.771/79.557мс**; race
  **147.100/156.299 → 82.038/86.057мс**.
  [Данные и границы library измерения](../../../measurements/2026-11-02/parallel-artifact-816/README.md).
- Разные runner/mode длительности recovery выше не являются парным ускорением.

Программные блокеры: точный DNS/multi-generation cleanup в штатных бюджетах;
managed NFQWS2 полный Apply/Stop/recovery; оставшийся Mihomo stopped-plan ACK
и fresh Apply; same-boot race/ACK cuts, late metadata restart, prior stopped
history и раннее восстановление до archive move. Early restart пока не написан.
Они не объявляются внешними препятствиями: работа прервана ограничением лимита.

Внешний этап — физический роутер/LAN-клиент и явное разрешение на испытания.
[Сценарий подготовлен](../../../ROUTER_ACCEPTANCE_RU.md); аппаратная готовность
и публичная live readiness не подтверждены.
