# OPS: полный офлайн-возврат парного состояния

Это отдельная законченная порция restore + реальный CLI caller. Она ещё не
доказывает первый bootstrap 0.19.3 → 0.20 и не включает изменения Main/App.
Root выполняет Linux/VM/router и публикацию; порядок пользователя сохраняется:
полный план → час на роутере → GitHub 0.20.0 → чистая установка и проверки.

## Production caller и одна точка подключения CORE

Новый файл `cmd/razvilka/paired_restore_command.go` содержит
`runPairedRestoreCommand(args, journalRoots) (handled, code)`.
В начале существующего `runCommandWithSelfUpdateJournalRoots` CORE добавляет:

```go
if handled, code := runPairedRestoreCommand(args, journalRoots); handled {
    return true, code
}
```

Команда: `self-update-paired-restore <matching-id>`.
Директории фиксированы: `/opt` и существующие production journals. Публичных
override путей/manifest/checksum/revision нет. Необходимо уже существующее
состояние Stop именно этой транзакции. Команда не создаёт/сбрасывает Stop.

Caller получает настоящую исходную `Gate.ExclusiveContext`, удерживает её до
завершения всей синхронной операции и открывает существующий защищённый control
root/permanent `.control.lock`. Закрытый handle хранит inode корня/маркера и
физически прочитанный текущий Stop. Перед каждой заменой повторяются проверки
того же оригинального owner, контекста, control incarnation и Stop. Короткий
`WithSelfUpdateStoppedEffectAdmission` разрешает только точный effect из
фиксированного плана. Gate snapshot, observed DTO и fake App не используются.

`SelfUpdateFileAdapter.RestorePairedPriorState` дополнительно требует, чтобы
физически выполняющийся writer был проверенным candidate из release/asset map.
Прежний бинарник не становится restore writer и не получает reader ABI.
Независимые runtime/helper/panel/command проверки должны доказать отсутствие
активных владельцев; отсутствие PID-файла не заменяет process birth evidence.

## Файлы и сохранение текущих защит

Существующий selfupdatejournal writer удерживается всю операцию. Квитанция,
current pointer, frozen images и retirement metadata не изменяются. Обычный
шестифайловый Restore по-прежнему отвечает ErrRetired для paired состояния.

Manifest и все blobs читаются/проверяются до эффектов. Данные копируются
потоками по 64 KiB с прежними лимитами архива (64 MiB/file, 2 GiB total,
bounded directory entries). Все целевые образы готовятся в закрытых siblings,
проверяются повторно и меняются через pinned fd/renameat2. В коротком control
lock нет копирования, hash, fsync, ожидания процесса или открытия Store.
Вытесненные файлы/деревья сохраняются; удаления/prune/reuse артефактов нет.

Сначала публикуются guards для S99razvilka, S99artem-flow и сохранённого
S99artem-flow.razvilka-disabled (последний mode0600). Прежние init bytes остаются
в неизменном offline archive. Прежний executable публикуется последним; старый
PID никогда не возвращается как живой владелец.

Возвращаются app/config, mutable private data, component release bytes, cache
и logs. Control/helper/file journals, private-restore generations (включая
неизвестные будущие), native/provider state, runtime ownership, LKG и component
operation/update evidence остаются текущими в своих исходных корнях/inodes.
Полные прежние bytes этих областей сохранены в исходном archive как артефакты.
Это не утверждение совместимости текущих journals со старым app/config.

Config берёт прежние app fields и текущие exclusions/policies/consent/Stop
intent, получает новую revision и SafeMode + Stopped. Неизвестный config
schema/field, потеря owner, третье состояние target, подмена archive root/blob
или staged tree отвергаются. Незавершённые staging siblings сохраняются и
вызывают typed ErrPairedOfflineOrphan при повторе; они не усыновляются.

Успех сообщает только `{"state":"offline-requires-review"}`. Команда ничего
не запускает и не принимает ACTIVE/health/retirement. Для дальнейшего Start
нужен современный owner с новым review всех независимых доказательств; старый
init нельзя включать поверх новых исключений или Stop.

## Проверки OPS и граница Linux acceptance

Windows focused `TestPairedOffline*|TestPairedRestoreCommand*` PASS:
updatecheck4.691s, selfupdatejournal0.813s, cmd0.981s.
Полные Windows updatecheck46.855s и selfupdatejournal13.370s PASS.
Windows vet трёх пакетов PASS. Полный cmd содержит известное старое ожидание
reader3 в `TestSelfUpdateImmutableReaderCLIBypassesStopAndScanner`: фактически
reader4, code0, stderr empty. Reader4 введён a8c4281 / Root b751b22; Main/test
companion принадлежит CORE/Root (предыдущий Root1a860cd), OPS его не изменял.

Модели используют настоящие архивы, крупные файлы, stream/hash/CAS/staging,
Stop journal и исходный Gate. Их обмен на Windows не является доказательством
Linux renameat2. Linux-only тест
`TestNativePairedOfflineRestorePublishesGuardsBeforeOldExecutable` использует
настоящий fd-pinned exchange и файлы крупнее 4 MiB; runtime owner в этой
файловой фикстуре моделируется. Root должен отдельно проверить production
caller, source/candidate identity, процессную quiescence, mode/rename и power
cuts на том же pin после tiny Main hook. OPS ELF не запускает.

Bootstrap candidate/source identity WIP не входит в эту порцию. Legacy UI
helper 0.19.3 не усыновляется, raw shell snapshot не добавляется, первое
применение paired bootstrap пока не подключено.
