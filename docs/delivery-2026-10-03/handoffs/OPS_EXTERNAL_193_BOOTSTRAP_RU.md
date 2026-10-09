# Настоящий внешний producer old0.19.3 → 0.20.0

## Caller и provenance

Standalone consumer `runExternalBootstrapCommand` принимает только:

```
self-update-bootstrap-old193 ID ABSOLUTE_ARCHIVE SHA256
```

ID — новый lowercase32hex, SHA — lowercase64hex. Roots строго production /opt;
environment/root override или готовый review/receipt не принимаются. CORE должен
добавить tiny dispatch этого consumer до ordinary startup. Внешний caller —
реально исполняемый кандидат0.20.0 из проверенного пакета, а не old UI helper.

Архив предварительно скачивается/проверяется внешним установщиком. Физический
candidate и архив должны находиться в root-owned tree без symlink/group/world
write ancestors, например в закрытой /opt/var/cache/razvilka bootstrap directory.
Переданному SHA не выдаётся process/effect authority: producer самостоятельно
проверяет source, свой original owner, реальные процессы и весь пакет.

Local release provenance явно `verified-external-archive-sha256`, Release.ID=0;
нет выдуманного GitHub ID, URL, attestation или заявления об API authentication.
Target0.20.0 и binary architecture/name берутся из закрытого first-bootstrap
контракта. Extracted binary SHA/size должны совпасть с физически выполняемым
candidate, который обязан реально сообщить version0.20.0 при preflight.

## Производство и применение

Успех CLI удерживает оригинальный конечный20min ExclusiveContext до синхронного
завершения/реального join всех command supervisors (три offline, четыре live). Start candidate
runtime-ready не считается Wait: после Finish producer ждёт настоящий retained
exec-created Wait и runtime-handed-off receipt. Живой new App передан owner,
не остановлен ради ECHILD. При failed cleanup/утере join возвращается только
ErrFileCommandUnsettled, CLI fences свой Gate, pending evidence сохраняется;
это не утверждение quiescence или завершения потерянного процесса.
Существующий ControlEpochReview держит
protected root/permanent marker; producer получает reference только после
Current этого реального handle. Epoch инициализируется только после read-only
проверок старого source и до первого metadata/header effect. Stop не очищается.
Metadata probes получают дочерний deadline, который не продлевает original.
Короткий admission содержит только bounded Start/rename, без Store/hash/fsync/Wait.

Producer требует live old panel из фиксированного PID-файла: actual /proc
boot/start/SHA/dev/ino, физический /opt/bin/razvilka и точное old-version0.19.3.
Единственный old-program probe — read-only -version; современный ABI не
приписывается. Свой actual candidate SHA/birth и exact CLI argv проверяет kernel
observer. Cold old panel, чужой caller и changed source/config отвергаются.

Helper/file/prior archive namespaces перед началом должны быть пусты/отсутствовать.
Unknown legacy helper/history сохраняется и блокирует. Retained raw backup с
прежним executable также блокирует: first-bootstrap не может выдать ему ABI или
retirement через whole-copy checksum. Fresh raw install artifacts без prior
executable остаются opaque и не удаляются. Typed managed/native/private history
и текущие exclusions продолжают проверяться существующими независимыми readers.

Первый current header — O_EXCL claim. Original archive открывается no-follow и
nonblocking, inode/size/mode/mtime и parent namespace удерживаются/проверяются
вокруг streaming copy/hash. Private copy создаётся O_EXCL, fsync + readback digest
до ExtractInstallFiles. Неудачные partial copies/headers сохраняются, не prune
и не reuse. После immutable review внешний original archive не нужен роли.

Genuine shared staging выполняет VerifyExtracted, candidate capabilities,
private migration, config CAS/intent, authority/history bookends. Review4 хранит
explicit external-old193-installer и candidate helper SHA, control.bin копируется
из кандидата. Old source SHA остаётся отдельным rollback evidence. JournalReaders
nil; fake stopped proof3 и old reader2 не выдаются. До Stop sealed helper identity
сравнивается с реальными original candidate и old panel identities.

Если реальный source config SafeMode/Stopped, review явно связывает mode=offline.
Сохраняются SafeMode, весь ServiceControl, policies/consent/exclusions и revision.
Prepare, три реальные joined stop/quiesce commands, полный paired Seal и шесть
file replacements выполняются под закрытым action `bootstrap-offline`. Кандидат
не запускается, Live/Accept/Finish и retirement не вызываются. Результат только
`installed-offline-requires-review`; paired receipt остаётся installed/pending,
helper — requires-review. Следующий обычный запуск/update требует отдельного
реального review. Существующий современный durable Stop блокирует этот forward
action: producer не очищает и не обходит Stop/unknown history. Cold panel всё ещё
отвергается; Root может подлинно запустить old UI с остановленной маршрутизацией,
если это поддерживает old constructor, без выдуманного PID или смены intent.

Source `ServiceControl.Stopped`/`SafeMode` — сохранённое состояние маршрутизации
в config. Durable self-update Stop — отдельный защищённый control epoch, который
отзывает право forward effects. Offline bootstrap поддерживает первое только
при UNSTOPPED текущем epoch; он не получает stopped effect admission.

В live mode используются existing neutral file primitives: Prepare, реальные joined
stop-old-panel / prepare-private-state / quiesce-old-runtime, SealPairedPriorState,
InstallAdmitted, start-candidate-panel, fresh Live/Accept и Finish. Seal с полной
paired prior copy обязателен до первой замены. Прерывание не replay/auto rollback,
не fake ECHILD/retirement/Start: все доказательства остаются для review и отдельного
matching Stop + offline restore. Success только completed-awaiting-owner-retirement.

## Shared integration и native acceptance

Role API4665+465ce0 уже принят Root. Scanner обязан положительно проверить
original helper независимо от отличающегося имени/inode и сохранить полный
process/socket/kernel inventory. CORE владеет этим tiny wiring и Main dispatch.
Global `selfUpdateEffectAdmission` должен принимать `bootstrap-offline` через
обычный `WithSelfUpdateEffectAdmission` при текущем UNSTOPPED durable epoch.
`WithSelfUpdateStoppedEffectAdmission` не используется для forward installation.
Adapter разрешает этому action только seal/install и три early commands.

Для actual candidate boot/следующего обычного update нужен adapter OpenFileJournal
в SelfUpdateFiles.Current/Action, paired-prepared phase и retirement из реального
App owner после completed/helper gone. Fake App или CLI acceptance для retirement
не добавляется. Эти shared Main/App hooks не входят в OPS source packet.

Windows faults проверяют archive mutation/SHA, unknown/existing copy, namespace,
exclusive claim, unsupported owner/root и закрытый CLI. Linux-only
TestNativeStageExternalBootstrapReviewUsesCandidateOnly запускает настоящий ELF
probe/migration/staging, но old source/migration version в этом узком тесте
моделируются: он не доказывает real0.19.3 compatibility.

Root alone opt-in TestNativeExternalBootstrapPublicExecutableProducer:
RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ID, _CANDIDATE, _ARCHIVE, _ARCHIVE_SHA.
Полные имена начинаются с RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP. Setup должен
содержать настоящий isolated fixed-/opt live old0.19.3 и built0.20.0 package.
Тест не создаёт review/receipt/helper identity/Stop/runtime facts; вызывает
actual executable с очищенными RAZVILKA_* env и проверяет genuine pair/Review/
installedSHA/control и сохранение intent. Offline branch проверяет installed
receipt/VerifyInstallation и отсутствие PID, live branch — Inspect. Candidate
остаётся offline либо live согласно реальному source config. Actual App retirement,
реальный Stop и ba55 public offline restore остаются отдельными Root проверками.

Windows full updatecheck PASS49.248s, focusedCLI0.942s, Windowsvet PASS.
После финальных Wait/closing checks повторены focused bootstrap/restore и vet;
Linuxamd64/arm64 vet+test-build проходят без ELF execution. Native opt-in
execution не запускался OPS.

OPS только Windows + Linux cross-vet/test-build; ELF, VM/router и публикация
остаются Root. До tiny hooks и genuine native execution bootstrap acceptance
ещё не закрыт. Hour router test → GitHub0.20.0 → clean install порядок сохраняется.
