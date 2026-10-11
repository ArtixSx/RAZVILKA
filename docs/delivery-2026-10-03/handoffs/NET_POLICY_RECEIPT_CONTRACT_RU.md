# NET → VLESS/CORE: durable successful-addition receipt

> 08.10.2026: продуктовый контракт уточнён — [активный список и обязательные исключения](../LIST_MODE_CORRECTION_RU.md). Прежний full-tunnel охват не является текущей задачей или разрешением на применение. Ниже сохранена история реализации и проверок; затронутые сценарии требуют повторной проверки.

> 11.10.2026: исходный контракт ниже уже реализован для WG в `334a62ad` и дополнен restoration/publication recovery в `ef2d7b5a`. Текущие Manager receipt regressions проходят. Оставшиеся App admission/source wiring и native ограничения описаны в [актуальном аудите WG и AWG](NET_WG_AWG_PREREQUISITE_AUDIT_20261011_RU.md); исторический staged-intent blocker ниже больше не описывает текущий `Rollback`.

Прочитан актуальный read-only `delivery-review/.../handoffs/CORE_RU.md`, раздел policy default admission (`b3bc486`, сообщён координатором). NET подтверждает проблему своего `WARPWireGuardAdapter.Rollback`: текущий `removePolicy(desired)` получает **полный staged intent**, а не список успешно добавленных ресурсов. `wg-interface-created` доказывает создание интерфейса, но не default route или всех selectors. Эти факты нельзя заменять совпадением kernel tuple.

Это **контракт/блокер, а не реализованное исправление**. Координатор подтвердил новый owner `policy_addition_receipt*.go`: VLESS, по опубликованному CORE контракту; existing policy_mutation/kernel/manager/app остаются CORE. NET ждёт конкретный общий API, не создаёт свою параллельную реализацию. Независимый D05 native-wg-08 PASS не моделирует этот concurrent EEXIST → subsequent Manager.Rollback сценарий. До закрытия риска нельзя объявлять полную rollback concurrency safety или начинать D07/HIL на этом основании.

## Запрашиваемый общий API

VLESS/CORE предоставляют конкретный API; запрашиваемые свойства WG consumer:

1. `applyRecordedPolicy` принимает recorder, связанный с transaction ID и digest канонического PolicyState. Recorder **durably** сохраняет prepared/pending action до mutating command и ack только после известного успеха + точного readback. Успешные additions доступны адаптеру после process restart, не только в локальном slice.
2. Receipt перечисляет точные added rules и defaults по family/table/dev/protocol/metric, включая использованную generation/layout. Уже существующий tuple и EEXIST никогда не получают ack или право удаления. Ошибка чтения/timeout/cancellation после отправленного command оставляют действие unknown; последующий совпадающий tuple его не подтверждает.
3. Receipt связан с private staged policy digest, transaction ID, adapter/interface, boot/network authority и immutable action IDs. Corrupt/missing/mismatched/historical receipt не превращается в full-intent authority. Pending crash window остаётся fenced.
4. Общий `removeRecordedAdditions` принимает только этот receipt/subset и повторно проверяет точные observed tuples. Whole staged PolicyState не должен служить fallback. Если primitive компенсировал известные additions внутри своего вызова, durable receipt это отмечает, чтобы adapter не удалял их второй раз после конкурентного создания чужого ресурса.
5. Для свежего Activate preflight failure recorder хранит prepared/no-issued-action: последующий Rollback не должен удалять policy или останавливать не изменённый предыдущий runtime. После неизвестного исхода — preserve + typed recovery fence; replay/попытка присвоить похожий default запрещены.
6. Commit переносит authority из transaction receipt в runtime ownership, а rollback/Stop/recovery используют соответствующую retained authority. Внешние владельцы сетевых ресурсов должны быть сериализованы; receipt не доказывает, что другой владелец не удалил/re-created ресурс после ack.

## NET после предоставления API

NET заменит staged-intent cleanup в `warpwg.go.Rollback` на successful-addition receipt, подключит prepared/pending/ack/compensated состояния к Activate и recovery, а unknown оставит fenced. Отдельные owned endpoint/interface receipts сохранятся; они не станут правом удалить общий default. Reconcile/RefreshPolicy также должны использовать согласованный общий mutation protocol; новый параллельный исполнитель NET не создаётся.

## Обязательные end-to-end regressions

- Конкурентный идентичный IPv6 default после preflight → EEXIST → partial primitive cleanup → настоящий Manager.Rollback: чужой default остаётся.
- Чужой selector занимает второй slot, первый был добавлен/компенсирован нами; subsequent adapter Rollback не удаляет новый чужой selector/default.
- Crash после issued command и до ack/write failure: subprocess recovery не удаляет совпадающий observed tuple и не replay Apply.
- Crash после ack и после primitive compensation: recovery использует только оставшиеся successful additions.
- Preflight AWG CLI/module/ABI rejection сохраняет старый runtime и policy **в полном Manager.Apply flow**, включая вызываемый менеджером Rollback. Direct adapter admission tests этого не доказывают.
- Старый отличающийся LKG, health failure, verified rollback и Stop с чужими host routes; ownership/hardware acceptance проверяются отдельно.

Linux durability требует file sync + parent directory sync и bounded owned reads. Текущий общий ownedfs.WriteAtomic синхронизирует файл, а самостоятельно добавлять общий durability API/phase machine в NET scope нельзя. Следующий контракт следует согласовать и интегрировать с CORE до HIL, без удаления recovery fence.
