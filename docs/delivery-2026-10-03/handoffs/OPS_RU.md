# OPS: первая порция D11, 03.10.2026

## Дополнение: native IPK container (отдельная порция после 99ac304)

Следующий feedback `native-opkg-03`: extractor дошёл до postinst; explicit `./etc/` отсутствовал, а pinned opkg экспортирует `PKG_ROOT`, не `IPKG_INSTROOT`. Добавлена directory entry до data file; synthetic postinst требует абсолютный непустой PKG_ROOT != `/`, причём `${PKG_ROOT%/}` должен **точно** совпасть с independently supplied `RAZVILKA_EXPECTED_OFFLINE_ROOT` из fixture runner. Никакой fallback к system root и отключения проверки migration. Имя env проверено по [pkg_run_script указанной ревизии](https://github.com/openwrt/opkg-lede/blob/80503d94/libopkg/pkg.c). Адресный container test — RC0; native повторяет координатор.

Координатор сообщил native-opkg-02 FAIL до postinst: Malformed package file, opkg-lede `80503d94`. Проверен [официальный extractor этой ревизии](https://github.com/openwrt/opkg-lede/blob/80503d94/libbb/unarchive.c): он декодирует внешний gzip/USTAR и вложенные control.tar.gz/data.tar.gz. Fixture заменяет Debian ar на этот контейнер; внутренние записи также явный USTAR, порядок детерминированный. Исполняемый postinst и требование фактической migration остаются; зависимости от ar больше нет. Native запуск остаётся у координатора, здесь не выполнен. Адресный `go test ./internal/components -run '^TestNativeFixtureEntwareGzipTarContainer$' -count=1` и launcher contract — RC0. Этот коммит отделён от ещё незавершённых supervision/acceptance изменений.

Ветка `sol/ops-20261003`, worktree `C:/Projects/RAZVILKA/worktrees/sol-ops`.
Base: `52eee92c28af1b9ad3c789f2ee2c3ffc43a0e175` (проверенная кодовая база `367ef14` + документы).
Один исполнитель этого чата, без подагентов, чужих worktree, VM, роутера и публикаций.

Результат: завершённый ограниченный низкоуровневый протокол файлов self-update с fault tests, исправления durable intent существующего helper и retained receipt gates. **Это не закрытие всего D11: новый файловый протокол ещё не подключён к shell/CLI/app. Gates требуют совместной интеграции CORE, описанной ниже. Не устанавливать эту ветку на роутер как готовый релиз.** D13 не начат до review координатора.

## Изменения

- Новый `internal/selfupdatejournal/**`: отдельный журнал файлов приложения, не журнал компонентов/opkg. Два pre-existing root: установка и приватный journal (предлагаемый production путь `/opt/var/lib/razvilka/self-update-files`). Разрешены только бинарник, init, config и три каталога/источника. Не допускаются произвольные HTTP-пути, traversal и symbolic links. Root anchoring и постоянный inode kernel lock; lock не снимается по PID/возрасту.
- `Prepare` требует точный 32-hex transaction ID, manifest SHA256 каждого кандидата, текущие authority/quiescence callbacks. Потоково сохраняет immutable old/new images с fsync, затем receipt и current pointer. Максимум шесть файлов, максимум 256 MiB на файл; до вызова нужен существующий disk-space gate. Непубликованный orphan после crash не разрешает изменение live и не перезаписывается новым вызовом с тем же ID.
- `Install` и `Restore` сохраняют индекс до/после каждого file replacement. Temp находится рядом с destination; file fsync → atomic rename → parent directory fsync на Linux. После crash между rename и receipt допускается продолжение только при совпадении live SHA256 с old/new image. Чужие изменения и повреждённые LKG images запрещают продолжение. Restore восстанавливает первоначальные права и первоначальное отсутствие файла.
- `Execute` сохраняет command-started до trusted callback. Ошибка команды, crash и неизвестность записи command-finished оставляют fence. Повтор любого command при unknown запрещён; выполненные имена сохраняются, A→B→A не повторяет A. `ResolveUnknown` требует matching ID, новые authority, независимые quiescence и observation/repair callbacks; команду не запускает. `Restore` не используется как скрытое разрешение повторить unknown.
- `Accept` требует независимый live callback, authority до/после проверки, точные SHA256/mode файлов и нужное направление (candidate или rollback). Один работающий процесс/candidate probe не является live evidence. Images и per-transaction receipt остаются также после accepted/rolled-back и начала следующей транзакции. API удаления/retention отсутствует.
- `internal/updatecheck/updater.go`, `helper.go`: Linux directory fsync после durable handoff/restarting/terminal record и создания updater directory. Неизвестная persisted phase и unsafe updater root теперь дают requires-review даже в новом процессе без старой памяти. Добавлены regression tests в `self_update_test.go`.
- `scripts/upgrade-entware.sh`, `rollback-entware.sh`: readonly compatibility gates для retained `self-update/current.json` и `self-update-files/current.json`, включая terminal/corrupt receipts, до stop и после quiescence. Требуется `-self-update-schema` → `1`; unsafe directory/file отклоняется. Journal не восстанавливается из backup и не удаляется. `test-self-update-supervision.mjs` проверяет реальные shell gate-функции; сервисы не запускаются.
- `scripts/test-component-update-native.sh`: учитывает явно заданный `GO` (в том числе путь с пробелами), GOTOOLCHAIN=local, defaults GOMAXPROCS=2/GOFLAGS=-p=2, общий timeout 3m. `test-native-opkg-runner.mjs` проверяет launcher opt-in/env/аргументы на явно названных stubs; это не native opkg evidence.

## Аудит существующего shell пути: что остаётся блокером

| Граница | Текущий shell путь | Новый низкоуровневый примитив / оставшаяся интеграция |
|---|---|---|
| Снимок до replacement | cp/manifest rename без file+directory durability каждой записи | Prepare freezes old/new до current; заменить shell файловый блок через CLI |
| Binary/init/catalog replacements | atomic mv отдельного файла, нет persistent file index | Install с durable index и old/new readback после crash |
| migrate-config, deactivate, component install, start | Нет отдельного durable intent/result каждой команды | Trusted Execute с фиксированными разными именами; unknown не replay |
| current-backup | Прямой redirect может оставить обрезанный pointer | Файловый journal имеет atomic durable current; shell pointer ещё требует интеграции |
| rollback files/dirs | restore_or_remove и rm/cp directory images без phase ledger | Restore закрывает шесть allowlisted файлов; mutable/private directory images остаются существующим отдельным private-restore протоколом, не объявлены покрытыми этим модулем |
| live acceptance | Shell PID/healthcheck и helper confirmInstalledHealth | Использовать эти независимые доказательства в Accept, сохраняя startup recovery lease; сами gates/файловый digest не live proof |

Нельзя просто повторно запустить прежний upgrade/rollback после kill/power loss: новые journal primitives пока не заменили эти shell блоки. Запись/migration config **после** Prepare, меняющая целевой config в third image, намеренно приведёт к ErrMismatch. Интеграция должна заранее получить проверенный staged config и его digest либо разработать отдельную согласованную фазу migration; нельзя расширять old/new match до «любого существующего config».

## Проверки этого чата

Windows/amd64, Go 1.26.5: `C:/Projects/RAZVILKA/tools/go/bin/go.exe`.
Для Go: GOTOOLCHAIN=local, GOMAXPROCS=2, GOFLAGS=-p=2. Production go.mod/go.sum/VERSION не менялись.
Node: `C:/Users/Artix/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe`.
Shell: `C:/Program Files/Git/bin/sh.exe`.

| Команда | RC / граница |
|---|---|
| `go test ./internal/selfupdatejournal ./internal/updatecheck -count=1` | 0; конечные исходники |
| `go test ./internal/selfupdatejournal -count=1 -v` | 0; 64 ordinal fault boundaries: prepare 10, install 24, restore 20, Execute 6, accept 2, rollback accept 2; семь os.Exit subprocess crashes |
| `go test ./internal/app -run SelfUpdate -count=1` | 0; существующий startup/HTTP recovery contract, не новый CLI wiring |
| `go vet ./internal/selfupdatejournal ./internal/updatecheck` | 0 |
| `go test -race ./internal/selfupdatejournal ./internal/updatecheck -count=1` | **2**, Go отклонил запуск: `-race requires cgo`; compiler gcc в PATH отсутствует. Race не выполнен |
| `GOOS=linux GOARCH=amd64 go test -c ./internal/selfupdatejournal` | 0; только сборка |
| `GOOS=linux GOARCH=amd64 go test -c ./internal/components` | 0; только сборка native harness |
| `go test ./internal/components -run '^TestNativeOpkgManagedUpdateJournal$' -count=1 -v` | 0 со **SKIP**, opt-in выключен; не native результат |
| `node scripts/test-self-update-supervision.mjs <sh>` | 0; actual gate functions, stub binary capability |
| `node scripts/test-component-update-supervision.mjs <sh>` | 0; старый component gate сохранён |
| `node scripts/test-native-enrollment-supervision.mjs <sh>` | 0; native enrollment gate сохранён |
| `node scripts/test-native-opkg-runner.mjs <sh>` | 0; launcher stubs only. Первый запуск дал RC1 из-за Windows PATH fixture; исправлен shell-local PATH без изменения production gate |
| `sh scripts/test-installer-architecture.sh` | 0; architecture и mandatory checksum tests |
| `sh -n` для upgrade, rollback, native runner | 0 |
| `git diff --check` | 0 |

Symlink subtest требует Windows privilege и здесь SKIP. Проверки Stop/CAS callback revalidation, authority/quiescence nil, mismatched ID, чужой digest, invalid checksum/allowlist, failed live evidence и kernel writer lock выполняются обычными тестами. Windows проверяет process crash; directory power-loss durability не заявляется. Бинарники cross-compile находятся только в ignored `.hil/ops-d11`, не в коммите.

## Точные запросы CORE / координатору

1. **CORE, `cmd/razvilka/main.go` + `internal/app/self_update.go`/startup admission:** согласовать и реализовать readonly `-self-update-schema` → `1`. Нельзя объявлять capability одним print до подключения retained file-journal fence: эта capability означает чтение существующего helper receipt и схемы `selfupdatejournal.Schema`. Без флага новый gate намеренно отклоняет app updates/downgrades при существующем helper receipt. Эту порцию нельзя отдельно включать в installable сборку без сопряжённого CORE изменения.
2. **CORE, startup и matching repair:** `Store.Current()` только читает. Любая ошибка — fence, `present && receipt.Pending()` — fence до matching recovery; missing current без ошибки — отсутствие транзакции. Сохранять auth/CSRF/CAS/Stop/SafeMode. Разрешённый startup node recovery lease надо связать с точным helper job ID и file transaction ID и подтверждённым живым helper, а не открыть фоновые writes при любом pending. Никакой downshift requires-review → restarting по одному PID.
3. **CORE/OPS, отдельное назначение CLI wiring после review:** CORE владеет command dispatch в main; OPS — adapter/скрипт. Нужен trusted внутренний вызов `Open('/opt', '/opt/var/lib/razvilka/self-update-files')`, Prepare/Install/Execute/Restore/Accept; authority/quiescence/live/observe closures создаёт приложение, не JSON request. Directory creation, ownership и parent fsync — обязанность wiring. Transaction ID брать из reviewed helper job, SHA256 из проверенного manifest; фиксировать command names в коде. Не запускать старый shell поверх active new journal. Изменение приватных directory images остаётся у существующего private-restore owner; библиотека не разрешает их рекурсивное удаление.
4. **Координатор:** Linux tests/race/vet нового модуля, symlink subtest, полный Linux gate только после совместной CLI/fence интеграции. Физические power-cut/fsync/storage и ARM/MIPS — отдельная приёмка, не cross-build.

## Native opkg: воспроизводимость и передача запуска

Launcher и Linux test binary подготовлены; **реальный opkg не запускался**. Harness читает фиксированный локальный file:// feed, создаёт временные offline root/config/IPK, каждому вызову добавляет `--conf <fixture> --offline-root <fixture> --force-postinstall`. Synthetic postinst требует непустой IPKG_INSTROOT != `/` и пишет только в него; проверка требует реального исполнения migration, а не молчаливого skip postinst. Это ограниченный сценарий synthetic package, не обещание об изоляции произвольного стороннего postinst.

Оба сценария: обычный config-changing update должен проверенно откатиться; interrupt после реальной upgrade-command оставляет upgrade-started и запрещает повтор update в свежем Manager. Все внешние действия — только в единственном live-окне координатора. Проверить наличие native opkg с поддержкой этих опций, `ar`, Linux и предварительно доступных Go dependencies; записать opkg/Go версии. Неподдерживаемый postinst/offline-root — failure, не разрешение убрать опции.

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 GOTOOLCHAIN=local \
  GO=/absolute/path/go1.26.5 \
  RAZVILKA_TEST_OPKG=/absolute/path/opkg \
  sh scripts/test-component-update-native.sh
```

Native harness имеет две реальные package-сценария, но не physical power cut. Для нового self-update нужна отдельная матрица Linux storage: kill до/после Prepared/current, file copy/sync/rename/dirsync, command intent/run/result и terminal acceptance; затем реальное отключение питания на целевых устройствах. Пакетные unknown не повторять, LKG не удалять. Общий LAN/DNS executor и `NETWORK_POLICY_EXECUTOR_REQUIRED` эта порция не меняет.
# D11 COMPONENTS: отдельная завершённая порция 03.10.2026

04.10.2026: D13 передан координатором CLOUD. Скрытого/незакоммиченного D13 WIP нет; cloudflareprovider/warp/usquediag/sources не менялись OPS в текущей порции. Эти каталоги больше не принадлежат OPS. Self-update provider находится только в updatecheck/selfupdatejournal/scripts. По актуальному CLOUD retention contract независимые native/provider/runtime/LKG roots и private-restore generations исключены из нового mutable snapshot/restore; существующие журналы и final LKG сохраняются на прежних путях. Никаких live accounts/router операций.

Отдельный subreaper helper вместо обязательного PID namespace, durable boot/start/command identity + wait4 ECHILD receipt, matching Manager.Quiescence, исторический unknown fence; отдельное accept-installed-idle с exact candidate config/version и двумя trusted inactive/quiescence наблюдениями; автоматический rollback больше не переиспользует candidate probe и ждёт independent acceptance. Полный контракт main/HTTP: [OPS_COMPONENT_CONTRACT_RU.md](OPS_COMPONENT_CONTRACT_RU.md).

ComponentUpdateSchema=2, retained v1 читается; writer/shell target gate=2 исключает старый reader поверх новых полей/terminal phase. CORE подключает два private CLI dispatch и HTTP idle action. OPS не менял main/app. Windows components unit/fault/subprocess tests RC0, vet RC0, Linux ARM64 test cross-compile RC0, реальные shell schema gates + syntax RC0. Новые Linux detached-child/supervisor-death и обновлённый native opkg harness здесь unverified — переданы координатору. Native-opkg-04 на предыдущем 6523002 подтвердил только fixture/PKG_ROOT/старую baseline, не эту семантику. Production module/version, другие worktrees, стенды и публикации не менялись.

## D11 self-update provider checkpoint — 04.10.2026

Законченная neutral порция описана в OPS_SELFUPDATE_CONTRACT_RU.md: sealed InstallationID+Sequence review, actual worker/child/file/private rename admission через единый CORE Stop kernel lock, pre-files stop/snapshot/quiesce, sole Wait4 WALL/ECHILD custody, matching startup/live/Finish/terminal Inspect, отдельный known-CAS private repair. Production main/app не изменены; self-update capability0/unsupported остаётся до CORE wiring и Root native acceptance. Retained Warp/Cloudflare/runtime/LKG и private-restore native/feeds histories не входят в mutable snapshot schema2 или restore, historical whole-domain snapshot запрещён.

Готовы отдельные 5ca485f retained controller admission, 178798a private POSIX node fixture и 0168ba6 strict inventory consistency; последний проверен в git archive без provider WIP (updatecheck4.883s/selfjournal6.641s/vetRC0). CORE authority modules exact cherry-picked как ee2c267/25ec48e; Root сохраняет свои более новые docs при integration. NFQWS reuse A boundary f673fb6 прочитан владельцем; только новые его bridge files, existing components helpers не менялись.

Локальные Windows model tests updatecheck/selfupdatejournal/operationgate+vet RC0, Linux amd64/ARM64 cross-compiles, shell syntax и real extracted compatibility/legacy fences PASS. Coordinator launcher scripts/test-self-update-native.sh готов для isolated actual Linux worker/Stop/rename/unknown/fault matrix; его выполнение не заявляется. Legacy raw apply теперь отказывается при retained control/file protocol или installed schema2/future; соответствующий старый CLOUD raw-pending rollback fixture needs matching recovery integration, а не ослабление fence. Никаких live/VM/router/network/accounts действий OPS. Полный D11 и power-cut остаются открытыми.

## D11 immutable reader3: shell rollback consumer — 07.10.2026

CORE и Root согласовали exact read-only ABI: standalone `-self-update-read-version` печатает `3\n`; standalone `-check-self-update-state` печатает `{"ok":true}\n` только после existing retained scanner fixed `/opt` roots. Metadata доступны под Stop, не получают новый 3c Start grant, не принимают relocation и не означают разрешения установки. Production `-self-update-schema=0` сохраняется.

`rollback-entware.sh` теперь отказывает raw replacement при installed reader2/3 независимо от schema0. Legacy fallback требует явного unsupported Go flag ABI (exit2, empty stdout, exact stderr first line), отдельного known legacy schema/unsupported ABI и отсутствия всех protocol artifacts. Empty top-level self-update/file directories допустимы; retained/hidden entries, unsafe/unreadable directories и Stop сохраняют fence. Unknown/future/garbage/stderr/missing newline/timeout не превращаются в legacy. Probe ограничен `timeout -k 1 5`; если bounded probe недоступен, rollback отказывает, не устанавливает инструменты.

Target reader3 отдельно запускает fixed-root scanner до Stop, после quiescence и после private recovery. Его успех не ослабляет installed raw fence; selected shell backup, native/private/node-history проверки остаются самостоятельными. Пробы используют только временные private output files с очисткой, не меняют retained journal и application images. Upgrade sibling и production cmd/app этой порцией не менялись.

Адресные inert Windows POSIX fixtures: reader3+schema0 refusal, strict stdout/stderr/newline/exit/timeout, retained/hidden/late artifacts и failed directory inspection, exact standalone target scanner/repeated refusal — PASS. Existing raw legacy fence и четыре actual inert node-history rollback refusal cases — PASS; shell syntax/diff-check — RC0. Unix-only DNS/autonomy fixtures получили только явный old unsupported ABI; их native выполнение не заявляется. Go/native/router/release/broad suite не запускались. CORE finished reader/scanner/startup checkpoint остаётся отдельной зависимостью, full D11 не закрыт.

Root review добавил bounded capture: scoped child `ulimit -f 128` применяется до metadata Start; stdout/stderr каждый строго меньше 64 KiB после capture, saturated/oversized output не может стать unsupported fallback. Допуск normal old Go Usage внутри этого bound сохраняется. Отсутствие file limit отказывает до CLI. Git Bash/MSYS фактически возвращает EINVAL для RLIMIT_FSIZE: actual unsupported-limit refusal проверен, положительные ABI/capture случаи и oversize fixtures здесь используют явно объявленную limit model. Linux/BusyBox kernel enforcement и post-cap actual full rollback остаются за Root; Windows PASS до добавления limit не выдаётся за эту native семантику. CORE ABI dependency теперь finished `5b90f42f8fd0f35aee44b25428ac2528ef550ce1` (doc-only follow-up `4135c7e`).

## D11 тот же raw fence в upgrade/install — 07.10.2026

Root отдельно включил `upgrade-entware.sh` в ту же границу. Повторён согласованный strict/bounded metadata contract; installed reader2/3/schema0 не разрешает apply. Target fixed scanner проходит перед preflight/Stop, после quiescence, после private recovery и непосредственно перед atomic replacement. Before-snapshot error trap заново проверяет raw fence до restart: late protocol/reader change не получает новый Start через восстановление неизменённых files. Read-only dry-run не открывает apply capability. Metadata scratch для upgrade находится в существующем TMPDIR, поэтому fresh preflight не создаёт installation state.

Install wrapper ровно делегирует `upgrade-entware.sh --apply`; bootstrap после проверки release выбирает `install-entware.sh` или `rollback-entware.sh`, без собственного пути live binary replacement. Эти wrappers не изменялись. ELF/architecture fixture получил только explicit old unsupported metadata ABI.

Адресный reader fixture исполняет реальные functions каждого script: strict output/time bounds, oversize stdout/stderr, normal old Usage, missing RLIMIT refusal, installed reader3/schema0, retained/hidden/late artifacts, target scanner и fresh-state no-create — PASS. Upgrade restart trap отдельно отказал Start при reader3/schema0. Existing legacy fixture обоих scripts — PASS, shell syntax/diff — RC0. На MSYS успешный RLIMIT моделируется явно; production gate на actual unsupported RLIMIT отказывает. [BusyBox implementation](https://raw.githubusercontent.com/mirror/busybox/master/shell/shell_common.c) подтверждает factor_shift=9 для RLIMIT_FSIZE и setrlimit для soft/hard limits; выполнение Linux/BusyBox/Entware и широкие installer/bootstrap suites здесь не заявлены. CORE fixed-root ABI `5b90f42` — отдельный finished prerequisite; capability0, native acceptance и полный D11 остаются за Root.

## D11 native transaction fixture после immutable reader3 — 07.10.2026

Root принял upgrade checkpoint `35795ea` через merge `9ff8832`; integration74/installer75 подтвердили production metadata capture в Linux `/bin/sh` и actual BusyBox без RLIMIT model. В старом `test-entware-transaction.sh` current binary install → same-version raw upgrade → raw rollback → повторный install больше не является допустимым lifecycle: installed reader3/schema0 должен отказать независимо от успешного чтения. Fixture теперь использует реальный native binary без metadata shim/downshift: fresh preflight/install и отдельный fresh uninstall, canonical reader3/schema0/fixed-root scanner, dry-run, обязательные raw upgrade/rollback/auto refusal с точным diagnostic. Running refusal сохраняет exact supervised PID и critical live hashes; stopped-process refusal и readonly checks сохраняют полное test installation tree: regular-file SHA256, inode, mode, UID/GID, entries и link targets. Timestamps не включены из-за допустимого создания/удаления probe scratch в parent directory. Процесс quiescent здесь не означает durable D11 Stop или settlement.

Fresh install с занятым портом остаётся ошибкой readiness. После copy текущего reader3 automatic raw rollback тоже обязан отказать: fixture требует nonzero, manual-intervention diagnostic и сохранённые candidate/snapshot, затем отдельно удаляет test-owned panel через uninstall. Это проверка failed installation/preservation, не accepted recovery. Успешный uninstall сохраняет settings/token/catalog, current-backup и байты/метаданные snapshots; повторяется только uninstall, без второго raw install. Unknown manifest key/missing staging/path traversal проверяются по своим конкретным сообщениям до reader admission, поэтому общий reader refusal не может выдать ложное покрытие этих validators.

Readiness/prior-route/pruning tests остаются только isolated shell-function contracts; их recording commands не доказывают historical binary transaction или managed lifecycle. Старые native assertions восстановления adapter/private/source snapshots через current raw rollback и failed-stop/private-recovery reachability удалены как недостижимые под reader3. Pinned legacy binary в этом checkpoint не добавлен, скачивание/toolchain/production ABI не изменялись; historical legacy transaction acceptance не заявляется. Истинные journaled update, durable Stop settlement B и Resume остаются отдельной D11 приёмкой.

`test-installer-architecture.sh` фиксирует exact legacy recording candidate sequence: standalone read-version (explicit Go unsupported ABI), retained node history, version, config. Invalid architecture/checksum требуют полного отсутствия binary/metadata execution. Это intentional четыре entrypoints, а не снятие старой count assertion; reader3 scanner настоящего native binary проверяется в transaction fixture отдельно. OPS здесь запускает только syntax/diff и inert Windows shell helper/architecture model checks; actual Linux native transaction gate остаётся за Root.

Адресная OPS verification: inert readiness/prior-route fragments, complete-image detection of changed bytes/inode/entries и exact refusal diagnostic/exit validation — PASS. Architecture selection + mandatory checksum matrix — PASS в временной inert копии с явно объявленной MSYS RLIMIT model; production capture не изменён. Symlink/mode/UID semantics, actual native metadata/install/uninstall/conflict и полный transaction fixture не запускались здесь. Shell syntax/diff-check — RC0.
