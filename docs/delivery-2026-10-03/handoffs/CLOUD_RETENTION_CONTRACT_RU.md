# CLOUD → CORE/OPS: retention на действующем native enrollment root

Обновлено 04.10.2026 после review `8821fd1`/`c44ffee`. **Предложение отдельного root, миграции и новой retention capability снято с этой порции по уточнению координатора.** Сохраняются действующие `Warp.Root`, schema=1, CLI, private-restore layout/binding и существующий reader gate. Здесь не объявляется согласованным изменение namespace или CORE API.

## Точный список исключений из mutable self-update

`WARP_ROOT` — доверенный текущий `-warp-state`, обычно `$STATEDIR/warp`; `CONFIG_DIR` — каталог доверенного `-config`, обычно `$APPDIR`. Применять список к фактическим deployment paths, а не только hardcoded defaults.

| Retained цель | Содержимое / причина |
|---|---|
| `$WARP_ROOT/native-enrollment.private.json` | Весь canonical schema-1 image: current/pending, все attempt identities, key/response/registration bytes и provenance. Он authoritative после появления. |
| `$WARP_ROOT/native-enrollment/**` | Весь immutable legacy input, включая current.json/pending.json, attempt-*/private-key.bin, response.private.json, registration.private.json, provider/accounts.private.json. Не выбирать только известные leaf-файлы и не удалять прежние материалы после canonical copy. |
| `$WARP_ROOT/.state-c86235c481bd74a829bc0e0baa588ad179542900e006f8e442425ab1818150ed.lock` | Permanent exact-file writer lease marker/inode. Имя — SHA-256 **UTF-8 basename**, не содержимого и не полного пути. `native-enrollment.private.json` уже lowercase, поэтому этот exact marker одинаков на Windows/Linux. Не копировать поверх и не удалять при restore/cleanup. |
| `$WARP_ROOT/health-policy.json` | Policy и runtime accounting пока смешаны: registration_attempts, rotations, cooldown/последние решения. Installer оставляет весь файл текущим, иначе старый snapshot вернёт квоту или прежние разрешения. Обычная явная policy CAS остаётся разрешённой владельцем. |
| `$WARP_ROOT/wgcf-account.toml` | Существующий пользовательский legacy enrollment сохраняется. `wgcf generate` только экспортирует его; native свежая регистрация его не удаляет. |
| `$CONFIG_DIR/private-restore-native-v1/**` | Полный retained journal generation: restore.private.json, before/after-images и .restore.lock. По одному current marker исключение неполно. |
| `$CONFIG_DIR/private-restore-feeds-v1/**` | Текущий feeds-generation coordinator тоже содержит `native_warp`; его journal/lease/images сохраняются по той же причине. |

Все эти цели исключить одновременно из snapshot manifest, mutable restore, удаления отсутствовавших в старом snapshot целей, directory replacement и prune/cleanup. Не восстанавливать `$WARP_ROOT`, `$STATEDIR`, `$CONFIG_DIR` или их общий предок целиком: это обход file allowlist. Historical manifest с whole-dir/overlapping target отклонить до первого stop/write; нельзя молча исполнять его частично и объявлять rollback успешным. Проверки учитывать actual opened ownership/alias/symlink, не только строковый prefix.

Из production источников: canonical/legacy поведение — `nativeenrollment/state.go`; lease inode — `restorejournal/file_target.go`, `lease.go`; accounting до remote call — `warp/health.go`; два journal поколения — `cmd/razvilka/private_recovery.go`. Текущие scripts уже не копируют WARP tree в directory snapshots; задача OPS — сохранить эту границу при новом mutable lifecycle. Эти файлы этим чатом не менялись.

## Unknown и текущий reader

Durable intent до POST остаётся на прежнем canonical root. Missing response, timeout, успешный executable rollback или старый config не означают «POST не был отправлен». Pending/invalid image блокирует manual/automatic/fresh enrollment. Recovery допускает только восстановление того же attempt из сохранённых материалов, без нового POST.

OPS продолжает existing `-native-enrollment-schema` gate на real target executable до stop, после quiescence и после private recovery; schema=1 и root не меняются, новая capability не нужна. Gate проверяет canonical и legacy markers и retained private-restore generations, включая feeds-v1. Unknown/corrupt/unsafe/unsupported protocol остаётся fence; старый reader без schema=1 не запускается поверх этих данных. Native resolved не снимает self-update unknown и наоборот. Read/Stop сохраняются, login/GET не получают сетевых прав.

## Узкий private-import guard — реализован в CLOUD библиотеке

`Manager.BeginNativeRestore` берёт Manager mutex и существующую canonical lease, затем фиксирует initial effective Document. Новый `NativeRestore.CompareAndSwap` требует точного сохранения **каждого** initial file, включая current/pending/key/response/registration. Удаление/замена исходного локального enrollment возвращает `nativeenrollment.ErrConflict` до записи. Baseline secrets очищаются при Close.

Новые bytes, внесённые только copy-only import этой сессии, допускается убрать точным typed journal rollback: под Manager mutex/lease не мог быть выполнен remote enrollment. Поэтому `empty → imported → absent` и `old → merged → old` сохраняют прежнюю transactional семантику. Это не общий monotonic CAS и не требование навсегда сохранять незафиксированный архивный импорт. Предыдущая формулировка о запрете любого native before-image rollback заменена этим различием.

Raw target теперь private; публичные методы сессии — Read, Binding, MergeImage, CompareAndSwap, Close. `Target`/унаследованный Save больше не позволяют обходить guard. Существующий privaterestore использует этот методный контракт; source-level обращений к `.Target` не найдено, schema/layout/journal generation не менялись.

Offline startup recovery по retained journal по-прежнему использует `nativeenrollment.Target` до открытия runtime/writers. Его exact before/after CAS нужен для незавершённого copy-only импорта и не заменяется этим guard. CORE сохраняет startup fence: нельзя открыть enrollment API/workers до разрешённой recovery; после Blocked admission остаётся закрытым. Self-update **не** использует native import/CAS как способ вернуть old enrollment snapshot. Guard не защищает от installer/root, удаляющего файлы — manifest exclusions обязательны.

## Проверки и приёмка

Добавлены regression tests `warp/native_restore_guard_test.go`: удаление/замена всех preexisting local enrollment files отклоняется, bytes не изменяются; после restart unknown не повторяет POST; rollback новых inert imported bytes разрешён с пустым/существующим baseline. Полный адресный `go test ./internal/warp ./internal/usquediag ./internal/privaterestore` — RC 0. Existing privaterestore copy-only rollback/crash tests тоже прошли; это unit/fault fixtures, не installer/native/power-cut приёмка.

OPS/координатору осталось проверить:

| Сценарий | Обязательный результат |
|---|---|
| Snapshot до POST → timeout/pending → mutable update rollback → restart | image/key/accounting unchanged, новый POST=0 |
| Response сохранён → crash до stage/current → executable rollback | та же локальная recovery, новый POST=0 |
| Historical manifest содержит whole-dir/root-overlap | отказ до stop/write; retained bytes и active LKG сохранены |
| Retained native/feeds private journal unknown/corrupt | reader/recovery fence; никаких raw cp/rm или нового POST |
| Copy-only import → ошибка другой mutable цели | точный rollback новых импортированных bytes, preexisting local facts сохранены |
| Старый target reader без schema=1 | existing gate отвергает до replacement, root не перемещается |

Последняя таблица — план совместной приёмки, не выполненный installer gate. Нового root/capability/миграции не добавлено; код OPS/CORE/nativeenrollment/privaterestore не изменён.

## Передача OPS: bounded стенд на существующих API

На проверенных refs CLOUD `4d157889`, OPS `5ca485f7`, integration `59232dd8` файл `selfupdatejournal/journal.go` одинаков (blob `28e959b43071ffd2bf8e87b4905a94d225ca4333`). Публичного generic mutable-directory/overlap API пока нет. Поэтому новый `warp/native_retention_test.go` упражняет реальные `Open/Prepare/Install/Restore/Current`, точный production snapshot selector из `upgrade-entware.sh` и полный `rollback-entware.sh` с инертными binary/init fixtures. Fixture CLI подтверждает только доступность схемы для прохождения shell boundary; он не считается реальным CORE recovery или live acceptance.

Три сценария реализованы и переданы координатору для opt-in запуска:

1. Snapshot/file-journal до simulated POST → automatic timeout/pending с durable accounting → candidate executable install → снимок после POST → file restore + полный shell rollback старого снимка → production prune → restart. Проверяются точный состав деревьев/hash/mode/inode canonical/key/health/legacy account/обоих private journal generations, отсутствие их в snapshot, сохранение working profile и API-call count=1 за весь сценарий. Mutable config/три directory images реально изменяются и обязаны вернуть LKG.
2. Response сохраняется настоящим production callback, child немедленно завершает процесс `os.Exit(73)` до decode/stage/current. После тех же rollback шагов pending/current переход и key/response сохраняют исходный attempt; recovery не вызывает API. Это process-crash, не power-cut/fsync reliability тест устройства.
3. Полный shell reader получает historical manifest с `WARP_ROOT_PRESENT`, `STATEDIR_PRESENT` или `APPDIR_PRESENT`; unsupported key отклоняется до schema/recovery/stop effects и live writes. File API отдельно отклоняет root/directory/native target до authority/quiescence callbacks. `Prepare` может создать permanent writer-lock в **self-update journal**, поэтому нулевую запись вообще во все файлы не утверждаем.

Последний сценарий проверяет существующий fixed manifest reader и file allowlist. Он **не** подтверждает отсутствующий generic target-overlap validator. При введении mutable API OPS сохраняет exclusions выше и добавляет проверку opened roots/alias/ancestor до stop; подключить этот стенд к новому API можно только после появления реальных entry points. Default shell deployment paths проверяются здесь; произвольные `-warp-state`/`-config` должны отдельно согласовываться с фактическим installer manifest.

Запуск и текущие результаты — [CLOUD_RETENTION_HARNESS_RU.md](CLOUD_RETENTION_HARNESS_RU.md). Список exclusions и эта передача служат контрактом для OPS; файлы OPS не изменены и сообщения в другие чаты не отправлялись.
