# З9: следующий шаг изоляции сервисов

Дата: 2026-10-16. Основание анализа: `7f0b9bcf`. Это план следующего ограниченного изменения, а не свидетельство native-приёмки или закрытия З9. Production пока не меняем; к Manager delta возвращаемся после native-приёмки текущего NFQ-пути.

## Что сейчас связано общей транзакцией

- `internal/app/autonomy_worker.go`, `applyAutonomyRoute`: строит полный желаемый план через `buildPlanReprovingRetained`. `internal/app/retained_node_proof.go` может потребовать новую проверку неизменённого узла Telegram. Отказ здесь происходит **до Apply**: работающие маршруты ещё не изменены. Это не общий rollback.
- `internal/app/app.go`, `buildDataplanePlanWithDNSContext`: перебирает все включённые сервисы; план описывает весь runtime. `changeScope` не является выбранным `service_id` для исполнения.
- `internal/dataplane/manager.go`, `Apply`: Snapshot/Stage/Validate/Canary/Activate/Health/Commit охватывают всех участников плана. После начала live-изменений ошибка ведёт к обратному rollback всех подготовленных участников и независимой проверке восстановления.
- `internal/dataplane/proxy.go`, `ProxyTunnelAdapter.Activate`: заменяет общий runtime/config/policy адаптера. Выделить строку Telegram из общего sing-box и считать остальной адаптер неизменным нельзя.

Нельзя просто отфильтровать routes, снять reproof или удалить sing-box из `plan.Adapters`: это теряет часть полного плана, может вызвать retirement либо оставить работающие selectors, которых новый план уже не описывает. HTTP 429/pause и существующий полный Apply не переделываем.

## Первая допустимая вертикаль

Изменяется **уже применённый NFQ-сервис**, а полный sing-box participant остаётся прежним. Без добавления/удаления адаптеров, общего LAN/DNS/domain/synthetic изменения, engine drafts или retirement. Остальные сервисы внутри NFQ по-прежнему разделяют один NFQ runtime; их независимость этим шагом не обещается.

1. После успешного собственного Commit Manager удерживает закрытый original-retained review для фактического зарегистрированного `*ProxyTunnelAdapter`. Привязка: исходный Manager/adapter, registry generation, полный sing projection и committed baseline, boot/process identities, runtime bytes, policy generation/receipt. Копия, stale handle, другой Store/Manager/adapter и handle после закрытия отказывают. Первый вариант — в пределах одного процесса; journal сам не восстанавливает эту capability после restart.
2. App сравнивает полный sing projection с исходным, включая настройки всех его сервисов и определения каталога. Неизменённые routes берутся из связанного оригинального baseline, а не из произвольного JSON. Для целевого NFQ остаются обычные проверки, consent, WAN, admission и точный CAS/undo.
3. Manager сохраняет **полный composite plan**, но только частный execution binding определяет мутационные фазы NFQ. Для удержанного sing выполняются readonly-проверки неизменности до/после эффектов и перед публикацией; Stage/Canary/Activate/service Health/Commit/Rollback sing не вызываются. Публичного поля `skip` в Plan/HTTP нет.
4. При ошибке восстанавливается затронутый NFQ, затем отдельно подтверждается неизменность sing. Неизвестные эффекты или провал наблюдения сохраняют recovery fence; они не разрешают перезапуск/удаление sing. Прежний service proof не становится новым PASS или `adapter-health`: текущая сохранность runtime и доступность сервиса — разные утверждения.

`internal/dataplane/runtime_presence.go`, `ObserveOwnedRuntime`, недостаточен как единственная проверка: он не сравнивает полный runtime config с исходным projection и не обеспечивает всю привязку committed receipt. Использовать readonly-проверки из `proxy.go`/`proxy_policy_generation.go`, не общий Health/Reconcile и не новый запуск узла.

## Минимальные файлы и порядок

1. Новые `internal/dataplane/retained_sing.go` и тесты: закрытая исходная привязка, bounded readonly observation, отзыв/повторное использование только при сохранённом оригинальном owner. Узкий hook в `manager.go` после подтверждённого Commit.
2. Новый `internal/app/nfq_service_delta.go` и тесты: строгая проверка поддерживаемой формы и полного неизменного sing projection; узкий вызов из соответствующего Apply pipeline. Существующий `internal/config/autonomy_route.go` уже предоставляет одно-сервисный CAS с точным undo; нового обходного Store writer не требуется.
3. В одном функциональном изменении — `manager.go`, `execution_journal.go`, `rollback_retry.go`: исполнение затронутого участника, честная доказательность, запись границы исполнения и crash/refusal поведение. Сейчас `reviewFailedRollbackImages` требует Snapshot каждого `plan.Adapter`; нельзя выпустить delta, забыв этот контракт. Записанная граница — provenance, а не разрешение очищать незатронутый sing после restart. Полный Stop/recovery не теряет retained routes; прежний путь, включая старые установки, сохраняется.

Это не общий framework для произвольного множества сервисов/адаптеров. Сначала реализуется и проверяется одна форма; неподдерживаемые случаи отказывают без автоматического снятия защит.

## Почему это ещё не NFQ ↔ sing и не общий LAN

- Если целевой сервис сейчас идёт через sing-box node и возвращается в NFQ, удаление его маршрута меняет общий sing projection. Старый sing selector нельзя оставить под видом «неизменённого Telegram». Обратное переключение также меняет sing. Нужен отдельный доказанный механизм изменения общего consumer; whole-adapter retention этого не решает.
- Текущий Home NFQ issuer в `internal/dataplane/nfqws_managed_packet_plan.go` требует один enabled service и только NFQ/network-policy participants. `Manager.Apply` отдельно отказывает при уже удержанном managed owner. Разрешение mixed Home NFQ + sing потребует собственного coexistence договора исходных owners, полного inventory и общего LAN gate. Эти отказы не снимать ради delta.
- Legacy NFQ restart затрагивает общую package/init область. Само различие имён адаптеров не доказывает независимость kernel effects. Перед функциональным допуском нужны точная граница NFQ effects и проверка сохранности sing; unknown/непроверенная общая область отказывает.

## Регрессии перед функциональным коммитом

- Настоящие Manager + Proxy + Config Store с моделируемыми процессами/runner: создать рабочий baseline; затем истёкший или неуспешный Telegram service proof при неизменном runtime. Разрешённое NFQ-изменение проходит без sing probe/restart/config write и без повышения доказательности Telegram.
- NFQ health failure: rollback только NFQ, точный Store undo и прежний composite journal; sing bytes/process identities/selectors неизменны. Unknown rollback или drift удержанного sing сохраняет fence.
- До эффектов отказывают изменённые WAN, boot, PID/start identity, config, policy receipt, каталог, Store, registry, copied/closed/stale handles. Изменение целевого route через общий sing, общий LAN/DNS и managed mixed scope также отказывают.
- Process-cut на границах CAS/plan/execution публикаций; новый Manager не получает retained capability из записанных данных, не очищает sing и не снимает unfinished fence. Существующие retry/close и полный Apply продолжают требовать свой прежний набор доказательств.
- Негативные controls должны падать при возврате прежнего full-adapter исполнения или при отключении соответствующей retained-проверки. Native NFQ Apply/Check/Stop и затем отдельный смешанный gate остаются самостоятельными этапами приёмки.
