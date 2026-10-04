# OPS stopped settlement: независимый source review — 04.10.2026

Проверен только finished commit `b1f34a9d99eeb959dd90daebd20b5351cd362aa1` из общего Git object store. Чтение через git show, без checkout/cherry-pick и без правок production/WIP. OPS optional-reader compatibility WIP не анализировался; известное ограничение ordinary Prepare здесь не оформляется повторно. VM/router/native tests не запускались, runtime PASS не заявляется.

**Результат: один P2 в private-state readback, P1 не подтверждён.** Пробел унаследован от существующего verifier/restore image; новый stopped terminal опирается на него. Остальные перечисленные ниже механизмы статически согласованы, но требуют ROOT integrated acceptance.

## P2: stopped terminal не проверяет права секретных файлов

Новый [file_stopped.go:198](C:/Projects/RAZVILKA/worktrees/sol-ops/internal/updatecheck/file_stopped.go:198) принимает `verifyPrivateRestore` как доказательство восстановленного private-state. У [file_private.go:381](C:/Projects/RAZVILKA/worktrees/sol-ops/internal/updatecheck/file_private.go:381) fixed private files сравниваются по Exists/Data. [restorejournal.Image](C:/Projects/RAZVILKA/worktrees/sol-ops/internal/restorejournal/journal.go:46) не содержит permissions, а [ReadFileImage/readTarget](C:/Projects/RAZVILKA/worktrees/sol-ops/internal/restorejournal/file_target.go:208) проверяет regular file, bounded bytes, inode continuity и cancellation, но не private mode.

Конкретный counterexample для Linux: snapshot содержит `admin.token` с mode0600; bytes остаются теми же, но к моменту restore/settlement mode становится0644. Все Stop, original process identities, ECHILD, six-file digests и runtime-inactive proofs могут оставаться корректными. Private image equality не видит изменения mode. Более того, generic restore journal не создаёт record для equal Before/After image; [replacePrivateFile:193](C:/Projects/RAZVILKA/worktrees/sol-ops/internal/updatecheck/file_private_linux.go:193) также возвращает nil для равных bytes/Exists до rename. Даже наличие staged file0600 не доказывает, что unsafe target был заменён. Поэтому новый terminal может объявить private rollback завершённым, оставив секретный файл readable другим пользователям. Возможность прочитать его зависит от parent-directory access; сам settlement этого ограничения не доказывает.

Это не утверждение, что нормальная запись создаёт0644: replacement создаётся0600. Это **отсутствие rejection/repair при metadata drift с unchanged content**. `checkRootOwnedPath` проверяет uid0, symlinks и запрет group/world write, не запрет group/world read; здесь он к тому же проверяет helper/review roots, а не каждый restored secret. `ownedfs.check` защищает пути от symlink, не проверяет mode. Обычный запуск token gate отдельно делает chmod0600; запускать panel для исправления после Stop нельзя, и новый data-only path его правильно не вызывает.

Bounded fix: перед terminal проверять metadata fixed secret files (как минимум token/credentials) через owned descriptor: regular/no symlink, expected ownership и запрет group/other access; при недостатке доказательства сохранить pending/fence. Если требуется восстановление mode, оно проходит отдельно через matching data-rollback admission, а не через panel Start или read-only reader check. Не менять глобальный restorejournal.Image schema ради этого narrow consumer без отдельного contract review.

ROOT regression: (1) unchanged token bytes + chmod0644 до restore; restore либо подтверждённо возвращает private permissions, либо отказывает; (2) chmod0644 после успешного restore до SettleStoppedRollback; settlement отказывает до публикации terminal; (3) normal0600 и unchanged bytes проходят; (4) такой же case для credentials, если файл присутствует. Проверить actual Linux permissions и unchanged Stop receipts/noStart. Это подготовленные проверочные сценарии, здесь они **не исполнялись**.

Локальные `sol-ops` file_stopped.go, file_private.go, file_private_linux.go, restorejournal/file_target.go и restorejournal/journal.go на момент аудита имели те же Git blob IDs, что b1f34a9; ссылки на moving files необходимо повторно проверить перед применением. WIP file_adapter/reader_admission не читался как доказательство этого commit.

## Что подтверждено чтением

| Контракт | Source evidence | Практическая граница |
|---|---|---|
| Matching Stop | file_stopped.go:40–59: installation/preStop+1/review revision; stopCheck + AuthorityAction(replace-to-rollback) + mandatory trusted Check | Сам producer не реализует CORE callback; nil/error отказывает. Matching TransactionID/current Stop проверяет CORE, не HTTP DTO |
| Six-file old image | file_stopped.go:127 и selfupdatejournal/journal.go:366–444 | Frozen new hashes + sealed old executable/init/config; actual installed bytes/modes/prior absence для всех шести. Config exact во время settlement, terminal inspection позже допускает typed config revisions |
| Private/control separation | file_private_formats.go fixed4 mutable directories +6 files; control/runtime/LKG histories не restore targets | private bytes/readable formats проверяются; P2 metadata gap для отдельных файлов описан выше |
| ECHILD, не PID absence | file_stopped.go:147–197 | Для каждого записанного command mandatory canonical reaped/not-started + WaitECHILD, exact original helper Parent, old-controller Supervisor; successful prepare/restore обязательны. Даже иной boot не заменяет отсутствующий ECHILD |
| Actual inactivity | file_stopped.go:138,166,183,201–209; file_commands_linux.go:124 | Boot/birth old panel, supervisors и captured Runtime; pidfile absence и mandatory runtimeInactive. Running same-birth process не принимается даже при исчезнувшем pidfile |
| Reader fleet | file_reader_admission.go:71–230,330–357; binary_images.go | Installed old/candidate/control, retained helpers/file images и hash-bound legacy backups; missing/future/unknown/drift отказывают. Matching transaction snapshots допускаются лишь как точно совпадающие уже probed old/candidate bytes |
| No probe/Start после Stop в settlement | file_stopped.go + CheckRetainedJournalReaders | Settlement только читает frozen proof/inventory; executable CLI probes находятся в pre-Stop seal и actual Start проходит existing admission. В stopped body нет Run/Live/command execution |
| Не live acceptance | stopped schema3 terminal distinct; journal.replace/Execute/Accept и file_adapter.Finish | Нельзя повторить command/file replacement либо использовать stopped receipt как accepted/rolled-back live Finish. Helper возвращает non-success code3 |

Windows writer observation в stopped.go передаёт only same active kernel-lock inode через private context key; применяется лишь при failed second-descriptor marker read на Windows и matching os.SameFile. Это не переносится из public config и не отменяет fresh receipt/image checks. Для Linux marker читается обычным descriptor.

## Publication, retained reader и race proof

Store держит прежний writer lease, повторяет authority/readers/inactive/image checks, пишет receipt3, затем current3. Current допускает только exact known receipt3/current2 cut для matching stopped terminal. Binding включает exact stopped epoch/revision/reader3. Retry не replay effects и повторяет fresh proofs. Existing accepted/rolled-back не преобразуются в stopped.

Adapter после Store снова проверяет evidence, публикует retained-helper, затем helper current. Cut с retained terminal archive при ещё pending helper current распознаётся в journalReaderImages: exact reviewed payload, retained receipt, process/private formats и sealed old image hashes. Изменённый/copy/orphan архив не принимается как другой current. Сам terminal не удаляет snapshots или Stop.

`TestStoppedSettlementPublicationCuts` покрывает четыре boundary только **file journal receipt/current** и повтор fresh callbacks после reopen. Это model fault injection, не physical power-cut. `TestJournalReaderProofIncludesEveryRetainedController` специально моделирует reader2 в retained old file image и missing control; он не запускает настоящий старый controller. Native fixture использует real copied fixture CLI/workers/ECHILD, не production old-version binary.

`TestNativeStoppedSettlementActualECHILDAndPreservedStop` действительно содержит real panel identity, workers/sole wait4, detached writer, private token restore, exact control/current Stop byte comparison, missing-ECHILD refusal, retry и afterStopStarts=0. Но RestoreAdmitted/restore-private-state завершены **до** RequestSelfUpdateStop (lines136–162). Поэтому этот fixture доказывает механизм terminal consumer при ROOT execution; он не является integrated mid-rollback Stop proof. Это ограничение OPS handoff уже обозначает — не новый bug/P2.

Существующий отдельный `TestNativeSelfUpdateCommandStopBeforeActualChild` ставит Stop перед actual child admission и проверяет durable not-started+ECHILD/отсутствие late-write. Он полезен, но не заменяет combined candidate/rollback/private-write/terminal sequence под CORE callbacks и ROOT barriers. ROOT acceptance нужен для Stop около actual Start, во время rollback rename/private restore, после receipt3 до pointer3 и между retained-helper/current публикациями; reader2 retained fleet, changed Stop binding, cancelled worker, delayed descendant и failed final readback сохраняют fence, не получают live success/Resume автоматически.

## Итог для интеграции

P2 выше требует отдельного OPS исправления или доказанного private-metadata gate в конечном consumer. Новый P1 в read-only review не установлен. Сам finished provider не подключает production CORE/main/HTTP stopped settlement callbacks; это owner integration boundary, не доказанная работоспособность. Production readiness не повышать на основании этого source audit. Новую optional-reader3 порцию необходимо проверять отдельным pinned diff, без автоматического переноса вывода с b1f34a9.
