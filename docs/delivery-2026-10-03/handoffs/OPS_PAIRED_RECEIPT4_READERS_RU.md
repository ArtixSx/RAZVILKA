# OPS: парная копия и единое решение читателей, 2026-10-08

Этот этап продолжает capture-only pin `afd7894fa505071d33abccdea35ccb77a8e0bd0b`.
Изменения ограничены собственной веткой OPS. App/main и native-операции не
изменялись; исполнение Linux и router acceptance принадлежат Root.

## Завершённая часть

- Обычная запись файла остаётся schema2; stopped settlement остаётся schema3.
  Новый активный парный receipt имеет schema4; объявленная способность чтения
  теперь 4. Старый proof3 сохраняет исходную семантику. Proof4 создаётся только
  при фактическом чтении 4 каждым образом, без переобозначения proof3.
- Под исходным writer lease полная проверенная копия привязывается к точному
  prepared receipt до замены файлов: `prepared2 -> paired-prepared4`.
  Поля связывают manifest, исходный receipt, review, installation/sequence и
  revision (включая 0). Сам digest не даёт права вывести образ из списка.
- После обычной установки, принятия кандидата и сохранения matching completed
  helper доступен один переход `accepted4 -> archived4`. Он требует исходного
  finite context, authority, подтверждённых terminal process receipts, отсутствия
  старых процессов и доверенного наблюдения текущего владельца App/runtime.
  Единственная guarded rename меняет receipt; все сохранённые байты остаются.
- `binary_images`, общий controller fleet и helper reader используют одну
  проверку фиксированного private archive. Только validated archived4 исключает
  одновременно оба journal-образа, helper control.bin и его candidate. Текущий
  установленный контроллер продолжает участвовать в проверках.
- Неизвестные/повреждённые копии, helper/file orphans, незавершённые процессы,
  чужие папки и pending job сохраняют fences. Метаданные известного следующего
  ready job можно читать без создания file transaction; полный fleet всё ещё
  блокируется, а будущий candidate reader3 отвергается над retained4.
- Сохранённый helper.identity проверяется против matching retained-helper,
  даже когда current.json уже принадлежит следующему заданию. Для текущих
  native действий identity по-прежнему привязана к свежему current record.
- Raw rollback сначала отказывает при любом retained file/helper protocol,
  до target probe и Stop. Даже прочитанный archived4 не разрешает частичный
  возврат старых шести файлов поверх нового состояния.

## Проверки OPS

Windows: полные `internal/selfupdatejournal` (12.124 s) и
`internal/updatecheck` (39.426 s) PASS; vet обоих пакетов PASS.
Linux amd64/arm64: vet и test-build обоих пакетов PASS, без запуска ELF.
Shell: syntax PASS; bounded inert metadata fixtures rollback и upgrade PASS.
Git Bash не поддерживает успешный RLIMIT в этой среде: успех лимита в fixtures
моделируется, фактическая недоступность лимита отдельно проверена как отказ.

Новые проверки покрывают publication cuts, retirement cuts, отказы authority/
terminal/archive/admission, сохранность frozen bytes, отсутствие полномочий
у bare Store и всех трёх readers при повреждениях/сиротах. Проверка следующего
задания покрывает format-only floor4, pending fleet fence и reader3 refusal.
Windows process receipts в этих fixtures моделируются; это не native acceptance.
Root должен исполнить те же полные пакеты на Linux с race.

## Следующий конечный этап

`SealPairedPriorState` и `RetirePairedPriorState` намеренно не подключены к
обычному Apply. Протокол текущего этапа предполагает старый helper с современным
review2. Реальный 0.19.3 не знает этих CLI/форматов и не может быть назначен
такому helper. Для 0.19.3 нужен проверенный candidate bootstrap с отдельной
привязкой собственного executable и исходного старого executable, а затем
полный offline restore пары application/state с явными ролями Stop/native
монотонных записей. Полного restore API или shell entry point здесь нет.

До такого подключения paired rollback через старый six-file Restore явно
отказывает. Этот этап нельзя считать завершённым upgrade/rollback 0.19.3.
В paired bootstrap нельзя создавать дополнительный raw shell snapshot старого
контроллера без matching disposition: это оставило бы ещё один активный reader.
Существующие неизвестные legacy snapshots не получают задним числом retirement.

Root подключает два companion в App/main: stopped settlement сравнивает
required/binding именно с `selfupdatejournal.StoppedSchema` (3), а CLI ожидание
общей способности чтения `"3\n"` в
`cmd/razvilka/self_update_read_state_test.go` на общую константу способности
чтения обновляется до 4. Schema3 stopped ожидания сохраняются. OPS не меняет
чужие App/main файлы. Обычный upgrade installer также принимает reader4 только
вместе с успешным strict check-state; будущий reader5 отвергается, raw retained
fence остаётся прежним. Полный paired bootstrap этим не подключается.
