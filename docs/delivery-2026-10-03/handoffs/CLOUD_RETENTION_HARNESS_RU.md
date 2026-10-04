# CLOUD: retention при отказе raw rollback

04.10.2026. Совместимость с принятым OPS `8f96be6`. Действующий WARP root/schema=1 сохранён; CLOUD не добавляет namespace, migration, production capability или provider recovery.

`TestNativeLocalCloudRetentionHarness` в `internal/warp/native_retention_test.go` и runner `scripts/test-cloud-retention.sh` по умолчанию отключены. Стенд использует приватные временные каталоги, subprocess и production файловые API; remote registration заменена in-process API-double. Сокетов, daemon, маршрутов, router/VM и фактического аккаунта нет. Private-restore generations в fixture содержат инертные bytes; корректность их recovery проверяется отдельно.

## Изменившаяся граница OPS

`rollback-entware.sh` из OPS `8f96be6` отказывает в raw replacement при сохранённых `self-update/current.json`, `self-update-files/current.json` или `self-update-stop`. Проверка выполняется до Stop, после Stop/recovery и перед файловыми эффектами. Такой отказ не восстанавливает mutable LKG и не завершает pending transaction. Удалять journals/control ради успешного rollback нельзя.

Стенд больше не ожидает raw success после low-level file-journal Restore. Он требует точного сообщения managed refusal, неизменного дерева `bin`, `etc`, `var/lib/razvilka`, отсутствия init status/Stop/private recovery/deactivate и прежнего pending file receipt. Вызовы `Prepare/Install/Restore` остаются модельной проверкой библиотеки с инертными callbacks; это не production `InstallAdmitted/RestoreAdmitted`, CORE authority или matching provider recovery.

Production native/reader preflight проверяется раньше managed refusal. Поэтому только managed subcases включают инертный marker `retention-target-reader2`: test binary отвечает `-self-update-schema=2`, чтобы дойти до настоящей shell-проверки присутствия protocol. Это CLI-double, не новая capability. Остальные reader fixtures сохраняют прежние schema ответы. Presence fixtures helper/file/control не являются валидными typed journals или accepted control seals.

Если production source не содержит ровно одну `require_legacy_file_protocol_free() {`, managed subcases явно SKIP; старый путь pending-journal raw success не исполняется. Без OPS node-history gate отдельно SKIP его negative subcase. Root принимает актуальный harness только на объединённом source с нужными owner gates и без относящихся к ним SKIP.

## Команда для координатора

В Linux source window после объединения этого CLOUD изменения с OPS `8f96be6` или более новым совместимым owner commit:

```sh
RAZVILKA_NATIVE_CLOUD_RETENTION=1 GO=/path/to/go sh scripts/test-cloud-retention.sh
```

Эквивалентный адресный запуск (POSIX shell доступен в PATH или задан абсолютным `RAZVILKA_CLOUD_RETENTION_SH`):

```text
RAZVILKA_NATIVE_CLOUD_RETENTION=1
go test ./internal/warp -run '^TestNativeLocalCloudRetentionHarness$' -count=1 -v -timeout=120s
```

Windows opt-in запускает координатор с native Go и Git Bash `sh.exe`, через `RAZVILKA_CLOUD_RETENTION_SH`. Harness переводит trusted fixture paths в POSIX absolute paths через shell `cd/pwd`; root всегда `t.TempDir`. Не переносить CR в последний argv Linux launcher.

## Обязательные результаты

| Subcase | Что должен проверить actual root run |
|---|---|
| timeout-pending | Automatic attempt charged до единственного simulated POST; model file Restore остаётся pending; raw rollback отказывает до эффектов, полное дерево и key/accounting/lease/legacy/journals неизменны; manual/fresh/automatic enrollment restart не повторяет API |
| response-crash | Child RC73 сразу после durable response callback, без registration/current/stage; тот же managed refusal сохраняет attempt/key/response и pending file receipt; отдельная enrollment recovery восстанавливает тот же attempt без API |
| retained-managed-protocol-refused-before-stop/file-current | Наличие file current вызывает точный managed refusal; всё captured дерево и LKG snapshots сохраняются, нет status/Stop/recovery/deactivate |
| retained-managed-protocol-refused-before-stop/helper-current | То же для helper current, без удаления retained marker |
| retained-managed-protocol-refused-before-stop/control-root | То же для control directory с retained `current-v1.json`; directory не снимается для прохождения gate |
| whole-directory-manifest-rejected-before-stop | Три unsupported whole-root manifest keys отвергаются полным shell parser до binary/schema/recovery/Stop; retained bytes/mode/inode и LKG не меняются; file-journal directory targets отклонены до callbacks |
| node-history-reader-refused-before-stop/{incompatible,unsupported} | Реальный production gate вызывает fixture `-check-node-history-state` ровно с пятью аргументами и trusted config/state roots; typed false/unsupported приводят к отказу до Stop/live writes |

Production backup selector и prune function извлекаются из точных границ `upgrade-entware.sh` и исполняются отдельно от daemon startup. Snapshot до регистрации и после неё не содержит retained enrollment/journal/accounting images. Prune удаляет три специально созданных obsolete snapshots и сохраняет исходные LKG snapshots. Это узкая legacy-function проверка, не приёмка managed provider prune или восстановления privateSnapshot schema2.

Перед raw refusal mutable config и три directory images изменяются: прежний файл получает новые bytes, второй удаляется, третий добавляется. Проверяется сохранение именно этого текущего состояния, а не возврат старого LKG. После отдельного prune дерево снова сравнивается. Retained/LKG trees проверяются повторным обходом по точному составу regular files/directories, hashes/modes/inodes; symlink aliases отвергаются. Read-only fixture CLI может писать только диагностические markers вне captured production tree.

Enrollment restart в этом стенде — адресный вызов CLOUD API в изолированном fixture. Он не является CORE startup admission при pending self-update: такой startup обязан сохранить независимый fence. Ни helper/file receipt, ни control root не удаляются и не объявляются settled.

## Статус проверки

Root сообщил native RC0 для OPS `8f96be6`; это owner provider checkpoint, не результат обновлённого CLOUD harness. Ранее сообщённые Linux результаты исходного retention harness на integration d010e13/source31 и typed-reader порции source32 относятся к прежнему shell lifecycle. Они не доказывают новый managed refusal и не разрешают raw rollback с retained protocol.

Actual запуск обновлённого harness на объединённом source — **UNVERIFIED**, выполняет координатор. CLOUD выполняет portable unit/vet и Linux cross-compilation без запуска fixture binaries; результаты новой порции записываются в [CLOUD_RU.md](CLOUD_RU.md). Выключенный opt-in — SKIP, не native PASS.

Matching provider recovery после CORE wiring, `InstallAdmitted/RestoreAdmitted` с actual authority/quiescence, six-file/private schema2 restoration, generic opened-root/alias/ancestor overlap, power-cut durability и live acceptance остаются отдельными root проверками. Этот стенд не подменяет их legacy raw shell или инертным schema ответом.

Точный список исключений: [CLOUD_RETENTION_CONTRACT_RU.md](CLOUD_RETENTION_CONTRACT_RU.md). Owner lifecycle: [OPS_SELFUPDATE_CONTRACT_RU.md](OPS_SELFUPDATE_CONTRACT_RU.md).
