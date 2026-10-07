# D11: matching persistent file/helper crash recovery — 07.10.2026

Пакет продолжает существующий callable consumer `app.SelfUpdateFiles.Action`, не добавляет production acceptance framework. Linux external test `internal/updatecheck/file_persistent_native_linux_test.go` импортирует actual App consumer; небольшой `file_native_acceptance_export_linux_test.go` предоставляет только test-build доступ к существующему relocated `nativeFileFixture`. Production files/API не менялись. Принятые journal primitive crash tests и stopped84 fixture не переписаны.

## Точный native запуск, только Root

```sh
sh scripts/test-self-update-persistent-native.sh
```

Эквивалент: `GOMAXPROCS=2 GOFLAGS=-p=2 GOTOOLCHAIN=local go test -race ./internal/updatecheck -run '^TestNativeSelfUpdatePersistentCrashRecovery$' -v -count=1 -timeout=14m`. Один original fixture ctx12m после setup; child ctx3m и launcher child timeout4m. Это конечный envelope девяти реальных subprocess crash cuts, многократного hashing, четырёх supervised commands и их actual ECHILD/sole Wait, а не новый production effect timeout. Отрицательные проверки сверяют исходный ctx; его expiry не считается refusal proof. Broad native launcher исключает этот case из старого общего3m запуска и вызывает отдельный launcher последовательно.

OPS запускает только Windows Go tests, Linux cross-compilation/vet и inert shell syntax check. Native/race execution и actual VM/router effects выполняет Root. Ignoredbinaries `.review-local/selfupdate-persistent-linux-{amd64,arm64}.test` собраны без race и являются вспомогательными артефактами, не native PASS.

## Что исполняется и сохраняется

Один immutable review и один persistent transaction: actual old panel process с sealed boot/birth/executable/device/inode, actual stop worker и parent Wait, actual private-snapshot worker, actual delayed detached quiescer descendant и ECHILD. Installed binary и candidate ELF имеют разные SHA256 (candidate overlay сохраняет runnable ELF), init images тоже различаются. Candidate manifest переписан согласованно внутри TempDir; рабочие VERSION/release assets не изменяются.

Девять cut points: quiesce worker успешно завершён, но `Execute` ещё не записал command checkpoint; install-file-0 до actual rename; install-file-0/2/5 после actual rename внутри реального protected-control admission; rollback-file-0/2/5 после actual rename/unlink; restore-private-state worker завершён, но `Execute` ещё не checkpoint. Child завершает actual процесс с86. Оба resolve-unknown и завершающие install/restore выполняются отдельными новыми actual subprocess с exit0, а не прежним adapter object. Каждый новый matching consumer открывает прежние roots/journal; отсутствуют reset, повторный Prepare, изменение Stop/installation/epoch и raw Store Install/Restore.

Unknown command retry обязан вернуть `ErrUnknown` и сохранить receipt/process/lease inode и bytes. `resolve-unknown` вызывает actual adapter Quiescence/Observe, без повторного worker Start. File recovery использует actual `InstallAdmitted`/`RestoreAdmitted` через App Action, проверяет durable phase/index и фактический target digest/absence на каждом cut. Третий config image запрещает recovery до effects и сохраняет всё наблюдаемое; намеренную правку исправляет только test setup. После завершённого Restore повторный known data retry не заменяет inode.

Retained old/new images, immutable file review/helper identity/controller, writer/command/control permanent locks сохраняют bytes/mode/UID/GID/inode. Восстановленные шесть destinations возвращают original bytes/mode/UID/GID и original absence; rollback не обязан возвращать прежний target inode. Private token восстанавливается actual private worker. Worker logs сообщают фактические boot/birth/device/inode, reaped count и ECHILD без private payload.

Live acceptance без реального start/runtime отказывается. В конце actual durable Stop увеличивает control epoch, forward install/start/live отказываются, Stop current/request и file/LKG images сохраняются, `Pending` остаётся true. Итог этого case: **data recovery, live_accepted=false, recovery_required=true**.

## Границы и следующая конкретная интеграция

Fixture использует принятый private relocated adapter с explicit owned/layout/capability overrides; network quiescer остаётся synthetic delayed-write owner, не registered production Manager. Guard consumer проверяет original ctx; exact config/review/control проверяют actual adapter/consumer. Здесь нет HTTP original-exclusive issuance, production constructor, production `/opt` startup, реальных network owners, live candidate/rollback health или live final LKG. Процессные cuts не доказывают физическое power-loss/flash durability. Не называть даже native PASS этого case полным D11.

Следующее расширение того же consumer после concrete issuer: actual production `RunHelper` → candidate startup/independent Live → failed candidate → owned cleanup → restored private/files → actual rollback startup/independent Live → retained terminal LKG и повторный запуск. Production `-self-update-schema` остаётся0 до готовых capability/admission/runtime owners. CORE5be control review — epoch primitive, не произвольный payload grant.

Конкретный OPS wiring gap старого `confirmInstalledHealth` закрыт следующим owner slice: [exact admitted live probes](OPS_SELFUPDATE_LIVE_PROBES_RU.md). Только held installed version/healthcheck recipes через existing FileEffectAdmission и actual matched runtime endpoint; init pid/lan-ip/PATH tool probes удалены. CORE подтвердил отдельные exact bounded recipes, sealed installation/transaction/controller; protected epoch lock только actual Cmd.Start. Generic label/default policy consent или reader-probe effect не расширяются произвольными argv. Native probe Start/join и полный production main/live LKG всё ещё требуют Root execution/concrete issuer.

Root human version decision: будущий real candidate **0.20.0** как обычный upgrade с0.19.3; предыдущая просьба0.2.0 отменена. VERSION/release bump и GitHub writes принадлежат Root после полного тестирования; этот packet их не делает.

## Локальная проверка

Windows full updatecheck24.044s/selfupdatejournal10.321s PASS. Linux amd64/arm64 test cross-compilation и vet updatecheck RC0; shell syntax и diff check RC0. Root accepted c190c79 как87be33d и выполнил actual Linux141 race: **case PASS23.98s / package25.114s, RC0 LINUX_SELFUPDATE141_OK**. Все девять cuts, четыре fresh recovery subprocess, actual quiescer ECHILD2 и final Stop/Pending прошли. Это actual matching persistent data recovery; полный production main/live LKG не заявлен.
