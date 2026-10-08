# OPS → Root/CORE: архив старого приложения и ordinary upgrade

08.10.2026. **OPEN release gate:** первая managed NFQWS установка после обычного
upgrade `0.19.3 → 0.20.0` не подтверждена. Совместимость нового установленного
контроллера не отменяет несовместимость сохранённых rollback controllers.
Root отложил новый retirement lifecycle/read format до отдельного этапа после
actual caller и list executor. Этот handoff содержит анализ; production patch,
новый DTO, schema4, архивирование и очистка истории здесь отсутствуют.

Проверенный OPS source: `0fa9d407e56d46d40a709435bf1461836acb8ade`.
Названные ниже audit files совпадают с finished Root
`74d27e6f224f5d4975af83e7fb362a3f127dd09d`. CORE согласен начать отдельный
этап с future freshly-known legacy upgrade; journaled retirement требует
отдельного согласованного контракта. Текущий caller может честно возвращать
`RETAINED_CONTROLLER_BLOCKED`; handoff не меняет его admission.

## Два разных пути

**Будущий known terminal upgrade.** Новый upgrade producer должен сохранить
полную согласованную прежнюю application/state copy, пока прежние writers
quiescent, и доказать terminal success нового matching update. Только затем
возможна явная операция пользователя: проверить durable offline copy и снять
ровно связанные controllers с active rollback eligibility. Сегодня shell
snapshot содержит allowlisted файлы и private directories, а не полную копию
всего приложения/состояния: `scripts/upgrade-entware.sh:483–571`. Manifest
публикуется **до** replacement (`:573–597`), а `current-backup` также пишется
при readiness exit75 (`:602–608`); они не доказывают successful terminal update.
Нельзя задним числом приписать существующему snapshot такую полноту/terminality.

**Фактическая 0.19.3 и unknown history.** Local tag `v0.19.3` указывает на
`817783493f0c2784ccc70aa73868cd64e9437634`; его `cmd/razvilka/main.go` не
объявляет `-component-update-schema` и `-self-update-read-version`. Root также
подтвердил отсутствие flag у actual router binary. Это unknown capability,
а не доказанный reader2. Older snapshot без paired SHA дополнительно unknown.
Номер версии, вычисленный впоследствии hash, копирование или изменение pointer
не дают retirement authority. Existing unknown/pending history сохраняется и
продолжает блокировать write3. Known reader2 также остаётся eligible до настоящего
проверенного перехода; terminal state сам по себе не исключает его из fleet.

## Три consumer seams

1. Общий concrete inventory: `internal/updatecheck/controller_images.go:19–113`
   (`retainedControllerImages`) включает journal old/new через
   `selfupdatejournal.Store.RetainedBinaryImages` и каждый legacy backup с binary
   и paired SHA. `component_history_admission.go:62–129` проверяет весь fleet
   для `max(actual floor, wanted)` и повторяет identity/inventory/state seal.
2. Self-update file-reader inventory:
   `internal/updatecheck/file_reader_admission.go:78–237`
   (`journalReaderImagesWithCurrent`) отдельно включает все helper `control.bin`,
   reviewed candidates, retained file images и legacy backups. Archive transition
   обязан иметь тот же смысл здесь, а не только в component scanner.
3. Rollback selection/settlement: `scripts/rollback-entware.sh:40–50` разрешает
   pointer/explicit snapshot только внутри `update-backups`; checks повторяются
   до effects (`:335–397`). Journaled matching/replace/settlement потребляют
   `internal/selfupdatejournal/journal.go:284–332,692–746` и helper/file binding
   `internal/updatecheck/file_reader_admission.go:524–550`. Retired update должен
   быть недоступен этим consumers до Stop/replacement/start, а manual restore
   полного offline archive не должен возвращать его в active eligibility.

## Обязательные invariants отдельного изменения

- Complete matching copy проверена и durable **раньше** eligibility transition;
  исходные immutable review/images/hashes не подменяются. Полноту прежнего state
  нельзя восстановить предположением из поздней, уже изменённой установки.
- Только точный fully-known terminal helper/file/private/process recovery set;
  все связанные old/new/helper/candidate images учитываются вместе. Unknown,
  pending, Stop и retained native evidence нельзя стереть, обойти или признать
  завершёнными. Полная копия не предоставляет runtime/inactivity authority.
- Переход принадлежит existing update owner под original finite operation,
  writer/control authority. Copy/fsync/readback не помещаются в короткий control
  leaf. Crash/restart сохраняют fence или завершают только тот же matching
  переход; marker от пользователя, простой move/filter или version waiver
  недостаточны. Все три seams должны видеть одинаковое durable disposition.
- Manual restore возвращает целиком согласованные прежние application/state
  bytes offline. Один старый binary поверх оставленной schema3 недопустим.
  Binary/private configs остаются private; они не входят в release/handoff.

Existing API не предоставляет такой переход: `Receipt.Pending/valid/Current`
(`internal/selfupdatejournal/journal.go:75,194,284`) допускают лишь нынешние
phases; schema3 предназначена для stopped rollback. `binary_images.go:65–140`
включает old/new всех retained receipts, а Store прямо не имеет prune/delete
API (`journal.go:79–81`). `archiveHelperRecord` сохраняет retained evidence,
не снимает eligibility (`internal/updatecheck/file_adapter.go:197–221`).
Новая semantics требует отдельного read-format/lifecycle решения; в текущем
packet она не добавляется.

## Необходимые unit/cut проверки, ещё не выполненные

- Partial copy, missing paired image, digest/mode/path/inode mismatch, cancel
  и copy/fsync failure: исходная история остаётся eligible, write3 блокируется.
- Cut после verified copy до disposition и после каждого durable publication:
  fresh-process recovery не выдаёт grant из незавершённого перехода и не
  повторяет native effects; только exact matching resume либо fence.
- Missing/corrupt/substituted archive после disposition: каждый seam отказывает,
  даже если другой consumer видит terminal metadata; forged manifest/pointer
  и arbitrary external directory не принимаются.
- Все связанные controllers исключаются только после завершения перехода;
  соседние unknown/pending/unretired reader2, orphan helper и Stop сохраняются
  и по-прежнему блокируют. После restart результат fleet scan тот же.
- Retired rollback selection/settlement отказывает до effects. Partial manual
  restore старого binary поверх нового state не допускается; полный matching
  offline restore проверяется отдельно.
- Legacy fresh-known path и actual flag-absent 0.19.3 проверяются раздельно.
  Изолированный firstInstall не доказывает ordinary upgrade и не разрешает
  удалить историю установленного приложения ради успешного hardware test.

В этом этапе production source/state не менялись; тесты и Linux/VM/hardware не запускались.
Native acceptance остаётся только у Root. Ordinary-upgrade gate остаётся OPEN.
