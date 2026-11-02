# Native Mihomo: диагностика повторных чтений исходного владельца

Это одиночные **неуспешные** запуски полного сценария в изолированных Linux network/mount namespaces. Это диагностические CPU-профили родительского тестового процесса, не доказательство ускорения работающего маршрута и не проверка роутера.

| Попытка | Commit | Actions run | Wall, s | Sampled parent CPU, s | SHA256 block, s |
|---|---|---|---:|---:|---:|
| Исходная | `6b3f9ba2f11a125dade89594ebc40041fc28f4de` | [41394900026](https://github.com/ArtixSx/RAZVILKA/actions/runs/41394900026) | 60.50 | 59.95 | 47.79 |
| С ограниченной областью повторных forward-чтений | `d20fd0f0abfe021787c09078a6881c70bf880c08` | [41396057916](https://github.com/ArtixSx/RAZVILKA/actions/runs/41396057916) | 57.42 | 56.63 | 44.06 |
| Дополнительно отдельная область cleanup-чтений | `bcd1723d1115062473f369538e4636f028408221` | [41396941945](https://github.com/ArtixSx/RAZVILKA/actions/runs/41396941945) | 49.92 | 48.83 | 40.09 |
| Только диагностические typed error flags поверх bcd | `a5c3dcf2a0313d93c411679186f6304f50597315` | [41398052602](https://github.com/ArtixSx/RAZVILKA/actions/runs/41398052602) | 37.45 | 36.79 | 29.50 |
| Чистое native-наблюдение внутри provider bookends | `462ac42857005f610e3a9d01cd04740d1eb51eec` | [41400836820](https://github.com/ArtixSx/RAZVILKA/actions/runs/41400836820) | 42.52 | 41.48 | 33.65 |
| Одна область чтения для backend socket inventory | `71edb546113975d05d3f9caba6d7cd89916630b9` | [41402833543](https://github.com/ArtixSx/RAZVILKA/actions/runs/41402833543) | 39.92 | 38.93 | 30.02 |
| Сопоставление с фактически хешированным pool FD | `e33e84af4afa87cf9950df5534f6483ebe0c20c4` | [41407786965](https://github.com/ArtixSx/RAZVILKA/actions/runs/41407786965) | 35.59 | 34.56 | 27.87 |

Оба запуска дошли до настоящих validation, loopback/SOCKS canary и Activate HEV/TUN. Оба остановились в Health при регистрации временного ресурса, на `register-closing-guard`: исходный десятисекундный бюджет истёк. Во второй попытке точное место отказа — `backend-process-initial`. Mandatory HTTPS через TUN, Commit, Stop и повторный Apply **этими попытками не подтверждены**. Rollback удалил исходный Mihomo ресурс, но временная строка `node-transit prepared` осталась ограждена как незавершённая.

Третий запуск bcd прошёл регистрацию и отказал до effects на `apply-early-preflight/preflight-owner`. Временный ресурс действительно settled как `unused`, вся транзакция — `rolled-back`. Публичный phase diagnostic намеренно не печатает исходную причину: по нему нельзя отдельно утверждать тип ошибки deadline. Исходный бюджет не менялся. Этот запуск также не подтверждает TUN service/Commit/Stop/repeat. Полный SHA256 по-прежнему занимает 82.10% sampled CPU; cumulative `nativeCleanupCurrent` — 6.38 s, `backendDisjoint` — 9.45 s (это не независимые суммируемые длительности).

Исходный профиль: SHA256 занимает 79.72% sampled CPU; `MihomoLiveSource.currentLocked` cumulative 47.57 s, включая вложенные чтения `ArtifactFileTarget.Read` и проверку фактического образа контроллера. Cumulative значения перекрываются, складывать их нельзя. Изменение d20 ограничивает только повторные source-чтения внутри одного синхронного forward-наблюдения: полное `child.Current` выполняется при входе и выходе, включая ошибку и panic callback. Каждый вложенный native Current сохраняет полную проверку held executable/config, control и процесса; обычные Current, Start и Cleanup не используют наблюдение как кэш.

В d20 отдельно реально выполнен `TestMihomoLiveOriginalChildSurvivesApplyAndNeedsFreshCleanup`: normal PASS 5.58 s, race PASS 14.10 s при исходном внутреннем бюджете 30 s. Он проверяет настоящие полные opening/closing source reads, ошибки/panic callback, отзыв позднего/скопированного представления, отмену, регистрацию ребёнка/профиля и изменение receipt. Этот тест не проверяет маршрут или TUN service health.

В bcd тот же настоящий тест дополнен отдельным cleanup-наблюдением после durable Stop: normal PASS 7.63 s, race PASS 14.96 s, исходные 30 s сохранены. Forward-наблюдение после Stop отказывает; свежий исходный cleanup owner допускает только чтение, foreign/released reviews, поздняя/скопированная ссылка и изменившийся receipt отказывают. Ни Start, ни signal, ни packet authority это представление не выдаёт.

## Следующие диагностические попытки

Изменение a5c3 добавляет только печать фиксированных typed error flags в тесте. Оно подтвердило `deadline_exceeded=true`, `canceled=false`; результат остался `unused`/`rolled-back`. Разброс wall 49.92→37.45 s при практически одинаковом сценарии отказа и том же production-коде показывает, почему эти одиночные замеры нельзя выдавать за процент ускорения.

462: реальный original-child/fingerprint/helper normal/race PASS, включая запись в исполняемый образ (реальный ETXTBSY), изменение mode/CTIM и same-byte foreign descriptor. App всё ещё отказал на `preflight-presence/backend-process-closing` с deadline; ресурс действительно `unused`, транзакция `rolled-back`.

71ed: real-held child/kernel/view helper normal PASS 6.80 s и race PASS 14.92 s; mutation/helper component tests также PASS. Полный App отказал после входа в общий policy backend на `preflight-closing-guard`. Состояние `prepared`/`rollback-failed` осталось ограждено; его нельзя интерпретировать как удалённый или неиспользованный ресурс. Чистая backend-область исключает DNS, Runner и Start; оригинальный provider исполняется до и после неё.

e33: все component/DP/library normal/race проверки выполнены без SKIP. Original child 5.33/13.64 s, actual FD mutation 3.11/10.45 s, kernel/view helper 4.92/12.97 s, library same-file/revocation .01/.02 s, все шесть actual changed-file случаев .06/.13 s суммарно. Library действительно хеширует исходный pool FD и проверяет тот же inode/CTIM; default Read/CAS и ordinary Current/Start не изменены. App снова истёк при policy add/presence; `prepared`/`rollback-failed` остаётся blocker. Его отдельный полный CI [41407786805](https://github.com/ArtixSx/RAZVILKA/actions/runs/41407786805) завершился SUCCESS, что не заменяет неуспешный native App workflow.

Во всех дополнительных попытках mandatory TUN service/Commit/Stop/repeat по-прежнему не подтверждены. Новые raw профили сохранены отдельно; исходные файлы не переписывались.

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
