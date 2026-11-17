# Очередь node-check: продолжение после успешного шага

Дата: 2026-11-09. Реализация: lab_sources; интеграция: Root;
независимое ревью: independent_review. Изменение опубликовано в
`8c869c76caf36eb6194675b66cc9bb0d4cef7c69` в составе draft PR #25.

## Подтверждённая причина

В [предыдущем native сравнении](ci-71b6f969/queue-gap-analysis.json), кандидат
`71b6f969579833e3ba217b331dc3c1a24bb150f7`, интервал между двумя полными Check
для selected-batch имел p50 **1321.741 мс**, p95 **1331.495 мс** (12 повторов).
У baseline соответствующий p50 — 1325.577 мс. Это реконструкция из UTC событий
`NodeCheckResult`, **не новая monotonic stage measurement**. Общий цикл batch
занимал около 2620 мс, сами Check — около 413 мс каждый.

Исходный `runDurableServiceJob` после успешного непоследнего `node-check` явно
назначал `NotBefore = time.Now().Add(time.Second)` и `AfterFunc(time.Second,
nudgeReconciler)`. Это намеренная уступка очереди, действовавшая даже при
отсутствии готового recovery/maintenance. В native fixture capacity равен1,
maintenance отложен, а обычный dispatcher опрашивается с шагом10мс. Поэтому
секундный floor возникает между двумя шагами без исполнения recovery.

Около **322 мс сверх установленной секунды остаются нераспределёнными**.
Между Check действительно находятся history admission с хешированием и проверкой
retained image inventory, запись результата, durable persistence, повторный
screening, engine/network/resource admission. Это перечень кода на пути,
**не измерение вклада каждой операции**. Данных для отключения/кеширования
history, ownership или актуальности нет; эти проверки сохранены.

## Ограниченный механизм изменения

[Production diff](https://github.com/ArtixSx/RAZVILKA/commit/8c869c76caf36eb6194675b66cc9bb0d4cef7c69)
в `internal/app/durable_service_jobs.go`: **14 добавленных, 4 удалённых строки**.
Только успешный непоследний `node-check` получает `NotBefore = time.Now()`.
Два локальных флага разделяют намерение продолжения и разрешение wake:

1. Выполнить один существующий bounded step и дождаться его cleanup/release.
2. Обновить cursor/очередь и сохранить следующий bounded retry budget.
3. Выполнить существующую durable запись. `wakeContinuation` остаётся false до
   её успеха; ошибка записи, blocked scheduler или отменённый context не будят очередь.
4. Освободить `reconciler.mu`, затем вызвать существующий `nudgeReconciler`.
5. Следующий обычный scheduler turn заново выбирает задачу и проходит admission.

Рекурсивного вызова worker, новой очереди, goroutine или таймера продолжения нет.
Первый checkpoint перед dispatch также сохранён. Успех service check по-прежнему
не применяет маршрут. В других ветках остались прежние интервалы: busy5с,
WAN30с с существующим backoff, а также задержки остальных типов задач.

Сохраняются Stop/recovery/select priority, aging, уступка после `durableBurst=3`,
fresh network/config/resource checks, ownership, история, отмена и restart fences.
Исключение секундного idle не означает удержание lease между узлами.

## Адресные доказательства

Тесты находятся в `internal/app/durable_node_continuation_test.go`:

| Проверка | Наблюдаемый результат |
|---|---|
| PersistsAndReleasesBeforeNextTurn | После wake в файле есть cursor1/queued/joined; старая lease свободна; новый вызов без sleep/advance выполняет только следующий узел. |
| FailedCheckpointDoesNotWake | Реальная занятая writer lease отклоняет checkpoint: in-memory cursor сохранён, scheduler fenced, продолжения нет. |
| CASConflictDoesNotWakeOrOverwrite | Чужой образ файла, записанный во время worker, не перезаписан; CAS conflict не будит очередь и не разрешает продолжение. |
| PreservesRecoveryAndBurstYield | Due recovery удерживает готовый batch; каждый turn делает один шаг; после третьего требуется прежняя уступка. |
| RechecksCancelWANAndBusy | Между шагами отмена останавливает job, другой WAN не запускает следующий Check и сохраняет30с backoff, новая lease другого владельца сохраняет5с busy delay. |
| RestartDiscardsPriorProofAndCursor | Загрузка реального checkpoint обнуляет старый cursor/network proof и результаты; после моделируемого завершения startup recovery выполняется свежая проверка первого узла. |
| YieldsToOriginalStop | Настоящий durable Stop через существующий Manager/fixture adapter выполняется раньше продолжения; второй Check не запускается. |

```sh
go test ./internal/app -run '^TestDurableNodeContinuation' -count=1 -timeout=90s
```

Авторский прогон — PASS, 2.307с; независимый повтор reviewer — PASS, 2.310с.
Комбинированный прогон этих и существующих адресных регрессий admission,
restart, cancel/join, failed cleanup, window capacity, priority/aging и Stop —
PASS, 5.163с. Root отдельно сообщил PASS объединённого integration selection
`internal/app`, 9.118с. Это разные наборы тестов, **не before/after benchmark**.
`git diff --check` — PASS. Независимое ревью подтвердило порядок
persist → unlock → wake и отсутствие ослабления guards.

## Итоговое native сравнение

[Research probe comparison run 42559470862](https://github.com/ArtixSx/RAZVILKA/actions/runs/42559470862)
относится к SHA `8c869c76caf36eb6194675b66cc9bb0d4cef7c69` и завершён SUCCESS.
Артефакт в этом run:
`research-probes-8c869c76caf36eb6194675b66cc9bb0d4cef7c69`.

Workflow сравнивает исходный `0e2db5ab` и итоговый кандидат с одинаковым pinned
Xray26.3.27, endpoints, сценариями и числом повторов. Итоговый кандидат включает
также изменение readiness polling, поэтому общее ускорение нельзя целиком
приписать только scheduler continuation. Нужны raw CSV и разделение полного
Check, App queue, cold/repeated и cleanup. [Полные данные](ci-8c869c76/paired-analysis.json)
проверены: selected2 server completion p50/p95 2615/2635→1444/1462мс,
N12 повторов. [UTC-реконструкция](ci-8c869c76/queue-gap-analysis.json) inter-check:
1324.399/1335.605→333.257/343.080мс; оставшиеся guards сохранены.
Предыдущие результаты71b не являются
измерением новой правки. Native Linux CI отдельно от физического router/LAN;
этот документ не подтверждает release или аппаратный профиль.
