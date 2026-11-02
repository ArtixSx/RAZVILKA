# Native Mihomo: диагностика повторных чтений исходного владельца

Это одиночные **неуспешные** запуски полного сценария в изолированных Linux network/mount namespaces. Это диагностические CPU-профили родительского тестового процесса, не доказательство ускорения работающего маршрута и не проверка роутера.

| Попытка | Commit | Actions run | Wall, s | Sampled parent CPU, s | SHA256 block, s |
|---|---|---|---:|---:|---:|
| Исходная | `6b3f9ba2f11a125dade89594ebc40041fc28f4de` | [41394900026](https://github.com/ArtixSx/RAZVILKA/actions/runs/41394900026) | 60.50 | 59.95 | 47.79 |
| С ограниченной областью повторных forward-чтений | `d20fd0f0abfe021787c09078a6881c70bf880c08` | [41396057916](https://github.com/ArtixSx/RAZVILKA/actions/runs/41396057916) | 57.42 | 56.63 | 44.06 |
| Дополнительно отдельная область cleanup-чтений | `bcd1723d1115062473f369538e4636f028408221` | [41396941945](https://github.com/ArtixSx/RAZVILKA/actions/runs/41396941945) | 49.92 | 48.83 | 40.09 |

Оба запуска дошли до настоящих validation, loopback/SOCKS canary и Activate HEV/TUN. Оба остановились в Health при регистрации временного ресурса, на `register-closing-guard`: исходный десятисекундный бюджет истёк. Во второй попытке точное место отказа — `backend-process-initial`. Mandatory HTTPS через TUN, Commit, Stop и повторный Apply **этими попытками не подтверждены**. Rollback удалил исходный Mihomo ресурс, но временная строка `node-transit prepared` осталась ограждена как незавершённая.

Третий запуск bcd прошёл регистрацию и отказал до effects на `apply-early-preflight/preflight-owner`. Временный ресурс действительно settled как `unused`, вся транзакция — `rolled-back`. Публичный phase diagnostic намеренно не печатает исходную причину: по нему нельзя отдельно утверждать тип ошибки deadline. Исходный бюджет не менялся. Этот запуск также не подтверждает TUN service/Commit/Stop/repeat. Полный SHA256 по-прежнему занимает 82.10% sampled CPU; cumulative `nativeCleanupCurrent` — 6.38 s, `backendDisjoint` — 9.45 s (это не независимые суммируемые длительности).

Исходный профиль: SHA256 занимает 79.72% sampled CPU; `MihomoLiveSource.currentLocked` cumulative 47.57 s, включая вложенные чтения `ArtifactFileTarget.Read` и проверку фактического образа контроллера. Cumulative значения перекрываются, складывать их нельзя. Изменение d20 ограничивает только повторные source-чтения внутри одного синхронного forward-наблюдения: полное `child.Current` выполняется при входе и выходе, включая ошибку и panic callback. Каждый вложенный native Current сохраняет полную проверку held executable/config, control и процесса; обычные Current, Start и Cleanup не используют наблюдение как кэш.

В d20 отдельно реально выполнен `TestMihomoLiveOriginalChildSurvivesApplyAndNeedsFreshCleanup`: normal PASS 5.58 s, race PASS 14.10 s при исходном внутреннем бюджете 30 s. Он проверяет настоящие полные opening/closing source reads, ошибки/panic callback, отзыв позднего/скопированного представления, отмену, регистрацию ребёнка/профиля и изменение receipt. Этот тест не проверяет маршрут или TUN service health.

В bcd тот же настоящий тест дополнен отдельным cleanup-наблюдением после durable Stop: normal PASS 7.63 s, race PASS 14.96 s, исходные 30 s сохранены. Forward-наблюдение после Stop отказывает; свежий исходный cleanup owner допускает только чтение, foreign/released reviews, поздняя/скопированная ссылка и изменившийся receipt отказывают. Ни Start, ни signal, ни packet authority это представление не выдаёт.

## Воспроизведение и границы

Workflow: `.github/workflows/mihomo-workflow-validation.yml` в указанных commits, ветка `work/mihomo-workflow-validation-20261102`. Он устанавливает официальные проверенные по SHA256 assets: Mihomo 1.19.33, HEV 2.17.1 и отдельный Xray 26.3.27 для настоящего TLS/VLESS peer. Публичные интернет-сервисы не используются как успешный ответ; peer работает в отдельной изолированной топологии. TLS-проверка включена.

Среда d20 по журналу job: GitHub-hosted Azure runner, Ubuntu 24.04.5 image `20261025.353.1`; все workflow фиксируют Go 1.26.5 и `GOMAXPROCS=2`. Физический CPU/kernel по этим сохранённым profile/status отдельно не аттестованы. Бюджеты во всех запусках: NodeTransit 10 s, Apply 110 s. Выборка N=1 на вариант: p50/p95, стабильное ускорение, child CPU и RSS по этим артефактам не вычисляются.

Основной запуск (после установки фиксированных assets и namespace dependencies из workflow):

```sh
sudo env PATH="$PATH" GOTOOLCHAIN=local \
  GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" \
  RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT="$PWD/artifacts/mihomo-live-profile" \
  RAZVILKA_XRAY_NATIVE=/usr/local/lib/razvilka-fixtures/xray-node26.3.27/xray \
  RAZVILKA_MIHOMO_ARCHIVE=/usr/local/lib/razvilka-fixtures/mihomo.gz \
  RAZVILKA_HEV_NATIVE=/usr/local/lib/razvilka-fixtures/hev-socks5-tunnel \
  sh scripts/test-mihomo-live-native.sh
```

Каталог вывода должен быть создан заранее с mode 0700 по точному пути workflow. Скрипт проверяет его происхождение и сохраняет исходный exit status native test независимо от анализа. Профиль собирается встроенным Go `-test.cpuprofile` на всём исходном тестовом процессе: setup/установка/fixture/контроллер входят в него, CPU дочерних Mihomo/HEV/Xray не входит. `cpu-top.txt` получен ограниченным `timeout 50s go tool pprof -top -nodecount=35 -unit=ms`; raw `.pprof` оставлен для повторного анализа, `status.txt` содержит параметры и статусы. Эти файлы скопированы из Actions artifacts без переписывания исторических результатов.
