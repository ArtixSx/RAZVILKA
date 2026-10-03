# CLOUD: три сценария self-update retention

04.10.2026. Действующий WARP root/schema=1 сохранён. Нового namespace, migration, capability или directory restore API нет.

`TestNativeLocalCloudRetentionHarness` в `internal/warp/native_retention_test.go` и runner `scripts/test-cloud-retention.sh` по умолчанию отключены. Они используют только приватные временные directories, subprocess и production файловые API; remote registration заменена in-process API-double. Сокеты, daemon, маршруты, namespace, router/VM, фактический аккаунт и root privilege не нужны. Retained private-restore generations здесь — byte fixtures; их recovery корректность проверяется отдельными privaterestore tests.

## Команда для координатора

В Linux source window с текущим CLOUD commit:

```sh
RAZVILKA_NATIVE_CLOUD_RETENTION=1 GO=/path/to/go sh scripts/test-cloud-retention.sh
```

Эквивалентный адресный запуск (POSIX shell доступен в PATH или задан абсолютным `RAZVILKA_CLOUD_RETENTION_SH`):

```text
RAZVILKA_NATIVE_CLOUD_RETENTION=1
go test ./internal/warp -run '^TestNativeLocalCloudRetentionHarness$' -count=1 -v -timeout=120s
```

Windows opt-in запускается координатором с native Go и Git Bash `sh.exe`, через `RAZVILKA_CLOUD_RETENTION_SH`. Go harness сам переводит trusted fixture paths в POSIX absolute paths через shell `cd/pwd`; root всегда `t.TempDir`, не live installation. Не переносить CR в последний argv при создании Linux launcher.

## Что считается PASS

| Subcase | Обязательная граница |
|---|---|
| timeout-pending | Automatic attempt charged до единственного simulated POST; pending/key/accounting/lease/legacy/journals hash+mode+inode неизменны после file restore и полного shell rollback; fresh/manual/automatic restart не повторяют API |
| response-crash | Child RC73 сразу после durable response callback, нет registration/current/stage; rollback сохраняет тот же attempt/key/response, restart восстанавливает его без API |
| whole-directory-manifest-rejected-before-stop | Три unsupported whole-root manifest keys отвергнуты полным shell parser; нет binary/schema/recovery/stop markers, LKG и retained bytes/mode/inode не меняются; file-journal target dirs тоже отклонены до callbacks |

Production backup selector и prune function извлекаются из точных границ исходного `upgrade-entware.sh` и исполняются без daemon startup. Prune реально удаляет три obsolete fixture snapshots и сохраняет retained tree. Полный rollback запускается на инертном executable/init fixture; native schema/readiness fixtures не доказывают реальный CORE startup recovery или работающий tunnel. File-journal `restored` оставлен pending; restored executable не снимает независимый self-update fence. Snapshot до регистрации и после неё не содержит retained enrollment tree/journals/accounting.

Mutable config и три directory images сначала содержат LKG fixtures, затем меняются: старый файл изменён, второй удалён, третий добавлен. Проверки требуют фактического восстановления прежних bytes/удалённого файла и удаления нового; отключённый restore не может пройти. Retained/LKG trees сравниваются повторным обходом по точному составу regular files/directories, hashes/modes/inodes; symlink aliases отвергаются. Legacy tree использует допустимое 32-hex имя attempt, current/pending markers и полный набор key/response/registration/provider paths. Его материалы остаются inert fixtures; canonical runtime account создаётся production enrollment кодом с API-double.

Whole-root rejection — текущие unsupported manifest keys + fixed file allowlist. Generic mutable overlap API в проверенных OPS/integration refs отсутствует; его admission, custom deployment paths и hardlink/symlink overlap этим стендом не объявлены пройденными. Power-cut durability и actual installer live readiness остаются отдельной root приёмкой.

## Проверки CLOUD до передачи

- Windows Go 1.26.5: `go test -count=1 ./internal/warp ./internal/usquediag ./internal/privaterestore` RC0; native retention opt-in выключен и test SKIP.
- `go vet ./internal/warp ./internal/usquediag` RC0.
- Linux amd64/arm64 cross-compile `go test -c ./internal/warp` RC0; test binaries не исполнялись.
- POSIX syntax runner RC0; выключенный runner actual RC2 до Go/native window. Адресный native test без opt-in — SKIP, не actual PASS.
- Native retention actual run: **unverified**, выполняет координатор после приёма коммита. H2/H3 actual результаты предыдущего `4d15788` к retention не относятся.

Точный список исключений OPS: [CLOUD_RETENTION_CONTRACT_RU.md](CLOUD_RETENTION_CONTRACT_RU.md).

## Совместимость с OPS 5ca485f / CORE b0a5093

Инертный fixture поддерживает новый `-check-node-history-state` ровно с trusted config/state root arguments и typed ответом `{"ok":true}`. Argument mismatch возвращает96, unsupported reader94, typed incompatibility — `{"ok":false}`. Production gate не менялся. Дополнительный subcase `node-history-reader-refused-before-stop` запускает полный production reader для incompatible/unsupported fixture и требует отказ до stop/live writes плюс фактический marker вызова typed gate. На CLOUD base без OPS gate этот subcase явно SKIP; он включается после owner merge, а не эмулирует gate вручную.

Координатор сообщил actual Linux трёх исходных retention scenarios RC0 на integration d010e13/source31 до OPS5ca. Это не результат нового negative subcase и не проверка после merge; новую комбинированную ветку прогоняет root отдельно.
