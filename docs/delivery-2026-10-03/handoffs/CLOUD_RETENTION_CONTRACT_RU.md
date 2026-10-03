# CLOUD → CORE/OPS: retained enrollment вне mutable self-update restore

Дата: 04.10.2026. Основание: `8821fd1d2e814f6e1a330e4d88f05509a096e2f3`, worktree `sol-cloud`.
Статус: **контракт для совместной реализации; отдельный root/capability ещё не подключены**. Ниже не заявляется, что новый self-update mutable restore уже безопасен для enrollment. Код CORE/OPS/nativeenrollment/privaterestore и их ownership не менялись.

## Доказанное текущее поведение

- `warp/native_enrollment.go`: canonical image и legacy migration inputs сейчас находятся под `Manager.Root`. `Generate` сохраняет pending до единственного POST; restart с unknown не разрешает новый POST. Recovery/backup/restore используют тот же root и lease.
- `nativeenrollment/state.go`: `MergeImage` не даёт архиву убрать/заменить существующий pending и не заменяет существующие attempt bytes. Но `CompareAndSwap` — общий доверенный file primitive, а не защита от внешнего directory restore или любого старого binary. `ReadEffective` при отсутствии image/legacy inputs возвращает пустое состояние; после удаления root это может снова разрешить enrollment.
- `privaterestore` имеет typed `native_warp` slot и при ошибке общей транзакции восстанавливает before-image. `TestNativeRollbackWithOtherTargetsPreservesBeforeImage` специально проверяет исчезновение нового импортированного image при rollback. Эту семантику нельзя переносить на retained facts, появившиеся после удалённого side effect. Текущий unit PASS retention проверяет конкретный import/lease, не сохранность при новом mutable self-update restore.
- Старые upgrade/rollback scripts проверяют `-native-enrollment-schema` и файлы под `$STATEDIR/warp`; обычный rollback сейчас не восстанавливает весь warp directory. Новый OPS mutable restore обязан сохранить эту границу. Schema=1 доказывает формат reader, но не знание другого пути или retained-only семантики.

## Обязательные инварианты

Enrollment — факт внешнего side effect, поэтому executable/config rollback не может откатить его историю. Каждый отправленный или потенциально отправленный attempt сохраняет локальную identity, intent, исходный key/response/registration, unresolved fence и уже списанную квоту. Отсутствующий response, старый snapshot или успешный rollback приложения не являются доказательством «POST не был отправлен».

Unknown блокирует новые manual/automatic/fresh enrollment независимо от rollback policy, UI/login, Stop и возраста backup. Допустимы read/status, Stop и локальное восстановление того же attempt из сохранённых bytes без POST. При missing/corrupt/unsupported retained state результат blocked/requires-review, не fallback на пустую регистрацию.

Снятие pending допустимо только существующим протоколом завершения того же attempt, с сохранённым результатом и локальным checkpoint. Завершение одной операции не снимает неизвестную другую. В этой порции нет API удаления/«сбросить регистрацию», истечения unknown по TTL или разрешения mint-again.

## Root и минимальный API-контракт

Предлагаемый trusted deployment root: `/opt/var/lib/razvilka/enrollment-retained/warp`. Он фиксируется установщиком/CLI, отдельно от `warp` mutable settings, stage/live profiles, directory snapshots и обоих self-update journal roots. Администратор может выбрать другой абсолютный private root до deployment; путь из импортируемого config/archive/HTTP недопустим.

CORE обязан отклонять overlap/alias с **любой** mutable restore целью или её предком/потомком, filesystem root, symlink/hardlink alias. Если OPS snapshot восстанавливает весь `/opt/var/lib/razvilka`, предложенный child root тоже попадает внутрь и запрещён: нужно сузить snapshot allowlist или выбрать отдельный private root вне него. Строковое сравнение путей без opened ownership/identity недостаточно.

Согласуемый минимальный wiring (не существующий API):

```go
// CLOUD: отдельное trusted поле, сконфигурированное до запуска workers.
warp.Manager.EnrollmentRoot string
// CORE: CLI -warp-enrollment-state <absolute-root>, deployment environment
// RAZVILKA_WARP_ENROLLMENT_STATE, одинаковые в daemon/check/restore/recovery.
// CORE: readonly capability -native-enrollment-retention-schema -> 1.
```

`EnrollmentRoot` применяется ко **всем** native status/read/Generate/recover/export/lease/binding путям, а не только POST writer. `Manager.Root` остаётся для legacy account и mutable WARP settings. Не реализовывать разные roots для автоматической и ручной регистрации. CORE обновляет typed private-restore layout/binding совместно с владельцем `nativeenrollment/privaterestore`; старые bindings из pending restore нельзя тихо переименовывать.

Retained root содержит canonical schema-1 enrollment image, migration provenance/fence и retained attempt accounting. В текущем `health-policy.json` смешаны policy и `HealthState.Attempts/Rotations`: mutable rollback этих данных не должен возвращать квоту неизвестной/выполненной регистрации. До отдельного accounting-контракта сохранить этот файл вне rewind либо держать recovery fence; новый duplicate enrollment provider/journal не вводить. Consent policy можно менять только через обычные CAS/Stop/SafeMode guards; восстановленный старый consent не снимает retained запреты.

## Миграция, backup и restore

1. Admission/Stop + доверенное отсутствие старых writers; lease обоих exact source/destination targets. При невозможности доказать quiescence миграция blocked, никакого сетевого действия.
   До смены root/layout нужно проверить старые private-restore journal generations и закончить их recovery с **прежним** binding, не переименовывая journal под новый scope. Если старый before-image способен убрать retained факт внешней операции, автоматическая recovery/migration остаётся requires-review; сначала обеспечить durable сохранение этого факта/fence. Одной сменой `WarpRoot` незавершённый журнал не исправляется.
2. Читать прежний canonical image и immutable legacy inputs. Новый destination получает validated copy/merge сохраняемых facts, pending, attempt identity и accounting; совпадение bytes обязательно. Конфликт двух pending — requires-review, не выбор самого нового timestamp.
3. Durable destination file **и directory entries**, затем readback, затем durable location/compatibility fence. Исходные image/legacy inputs не удалять и не перезаписывать. Crash между шагами не должен превращать новый root в «пустой»: незавершённый migration fence блокирует enrollment. Повтор миграции — тот же merge, без нового POST.
4. Self-update mutable restore исключает retained root, migration marker, compatibility record, accounting и retained restore journals из файлов/dir images и удаления. Он не вызывает raw CAS/restore before-image для enrollment. Old application snapshot меняет только разрешённые mutable цели.
5. Явный private backup экспортирует retained secrets только через существующий encrypted private механизм. Import — merge facts под тем же lease, без удаления/замены новейшего unresolved attempt. Его общий rollback может откатить mutable selection/drafts, но уже принятые retained unknown facts остаются либо держат отдельный durable fence; импортный before-image не становится authoritative enrollment state. Это требует изменения владельцем typed native slot: текущая его полная before-image rollback семантика этому контракту не соответствует.

## Upgrade/rollback к старому reader

OPS проверяет реальный target executable до stop/mutation и повторно после quiescence/recovery, а также retained paths, legacy inputs и migration/restore markers. Наличие terminal receipt тоже требует reader capability: terminal facts/квота не удаляются. Unsafe/corrupt/unsupported marker — blocked; отсутствие текущего pending не даёт права игнорировать retained protocol.

Требуются обе capabilities: существующий `-native-enrollment-schema` для формата фактического image и новый `-native-enrollment-retention-schema` для path/retention/fence семантики. Значение 1 нового флага CORE может возвращать только после wiring всех read/write/startup/restore режимов и guards, не как standalone print. Schema-1 binary, знающий только старый `$STATEDIR/warp`, **несовместим** с новым retained root даже при одинаковом JSON schema.

Нет флага/поддержки нужной схемы/root contract → downgrade/rollback target не устанавливается и не запускается поверх retained state. Совместимый LKG executable можно вернуть, сохранив тот же root/fence; вернуть старый config или старый health policy недостаточно. При новых schema writers обновлять объявленные read capabilities согласованно. Нельзя ради старого reader копировать «до регистрации» snapshot в старый root, стирать/переименовывать retained markers или отключать registration fence. Никакой обход через shell/wgcf при отказе capability.

Всем startup/CLI entrypoints нужен fence **до** API/workers: native unknown/migration unknown и неизвестный self-update command outcome сохраняются независимо. Self-update successful/rolled-back не означает native enrollment resolved и наоборот. Без совместимого recovery reader приложение остаётся в режиме чтения/Stop; новая регистрация и фоновые mutations запрещены.

## Ownership и приёмка

CLOUD после review реализует единый выбор native root в `internal/warp/**` и библиотечные регрессии. CORE реализует trusted paths/CLI/capabilities/startup admission, новый layout/binding и координирует владельца `nativeenrollment/privaterestore`. OPS исключает retained targets из mutable manifests/restore/cleanup и проверяет реальный reader upgrade/rollback. Общие файлы не переданы этому чату; эта порция меняет только handoff.

Нужные регрессии владельцам:

| Сценарий | Обязательный результат |
|---|---|
| Snapshot до POST → POST timeout → mutable app rollback → restart | исходный pending/key/квота сохранены, новый POST=0 |
| Response сохранён → crash до stage/current → rollback | локальная recovery того же attempt, новый POST=0 |
| Mutable snapshot без enrollment image либо с прежним current | retained bytes/fence не заменены, active LKG сохранён |
| Crash на каждой границе root migration | старое/новое состояние или requires-review, никогда unfenced empty enrollment |
| Private import pending → сбой другой mutable цели | retained pending/fence сохранён; новый POST=0 |
| Новый reader → target schema=1 без retention capability | до stop/replace отказ, receipt bytes сохранены |
| Retained unknown/corrupt/terminal плюс попытка старого rollback | unsupported/corrupt блокируются; terminal не удалён |
| Compatible LKG reader + смена policy/config root | retained path/identity неизменны, unknown не разрешён |

Это список приёмки, **не выполненные тесты**. В данном docs-only уточнении выполнен `git diff --check`; production код и live среда не менялись. Адресные unit/cross-build результаты предыдущего `8821fd1` остаются только его областью; новый retention протокол ими не покрыт.
