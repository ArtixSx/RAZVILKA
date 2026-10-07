# D11: exact admitted live probes — 07.10.2026

Закрыт конкретный OPS gap перед production live acceptance. Старый `confirmInstalledHealth` создавал новый Background ctx, запускал raw `/opt` version, init pid/lan-ip и healthcheck. Теперь `liveFileRuntime` вызывает private `confirmFileLiveHealth` с исходным ctx, immutable file review и actual уже совпавшим runtime boot/birth/hash/device/inode. Public App/main/CORE APIs и production schema0 не меняются.

Только две recipe: `live-probe-version` → held installed executable `-version`; `live-probe-healthcheck` → тот же executable `-healthcheck http://<actual-listen>:8787/api/v1/status -healthcheck-pid <actual-runtimePID> -healthcheck-require-dataplane`. Они допускают исключительно `start/live` через existing `SelfUpdateFileAdapter.EffectAdmission`, seal installation/transaction/reviewed epoch и CORE callback. Generic health label, reader-probe family, read/observe или cleanup не дают Start.

PID уже проверен `ownedFileRuntime` по executable inode/hash и exact supervised job/helper argv. Endpoint читается из `/proc/<matchedPID>/cmdline`: ровно один explicit canonical `-listen IPv4:8787`, без alternate syntax, default/wildcard/multicast/IPv6/customport/hostname/URL injection. Ни caller URL, ни новое discovery через S99 `lan-ip` не используются. Таким образом нет init/shell/PATH ip/awk probes или их неучтённых child trees.

Installed executable удерживается descriptor через ownedfs installation root и исполняется `/proc/self/fd/3` с `ExtraFiles` и fixed commandEnvironment. До и после каждого probe свежие Authority/Stop, birth/inode, held/current/proc SameFile, regular/executable/protected/current-UID metadata и SHA256. Path replacement не выбирает другой executable в Start window. Hashing/FD reads и sole Wait не находятся внутри CORE control lock; callback содержит только actual Cmd.Start.

Один20s child ctx сохраняет cancellation, values и более короткий deadline исходного Live ctx. Admission error после actual Start вызывает cancel/group cleanup и sole direct-child Wait; no-begin/refusal/cancel не считаются выполненным probe. Уже запущенный probe проверяет actual durable Stop каждые250ms, при revocation отменяется и join-ится; final Stop read не позволяет completed-before-read probe принять live после новой epoch. stdout ограничен128, stderr1024; success требует exact canonical version newline / actual main ABI `healthy: <version>\n` и empty stderr. Timeout/error/diagnostic не downgrade и не fallback.

Portable tests проверяют wide/missing/ambiguous listener, URI/query/userinfo, arbitrary effect/recipe/PID, запрет Start под read/cleanup labels. Native case `TestNativeSelfUpdateLiveProbeActualAdmissionAndJoin` исполняет actual held copied fixture CLI и actual control admission: оба exact recipes, allowed/pre-Stop/cancel/no-begin/post-Start-error/post-Start-Stop, плюс actual hanging version child при Stop во время выполнения. Проверяются original context value/deadline, zero/one actual Starts и final actual wait4 ECHILD. Fixture CLI выдаёт synthetic version/health text; **это Start/join/admission acceptance, не production HTTP/live LKG**.

Root native запуск:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 GOTOOLCHAIN=local go test -race ./internal/updatecheck \
  -run '^TestNativeSelfUpdateLiveProbeActualAdmissionAndJoin$' -v -count=1 -timeout=4m
```

Тест входит в существующий native launcher через NativeSelfUpdate pattern. OPS native не запускал. Windows targeted FileLive/effect/review1.493s, full updatecheck24.384s/selfupdatejournal10.384s и Win vet PASS; Linux amd64/arm64 cross-compilation/vet RC0. Root accepted94f4bc3 как16430cd и выполнил **actual Linux145 race: все13 cases PASS7.37s / package8.485s, RC0 LINUX_TARGETED145_OK**, включая running Stop, original context values/deadline, post-Start error/Stop и join. Scope остаётся actual probe admission/Start/join с synthetic fixture CLI response; production HTTP/live LKG не заявлен. Production end-to-end с concrete issuer/registered live owners ещё обязателен. `-self-update-schema` остаётся0, VERSION0.19.3; будущий candidate0.20.0 меняет только Root.

Отдельно Root подтвердил **Linux141 source87be33d actual race persistent recovery PASS23.98s, package25.114s, RC0 LINUX_SELFUPDATE141_OK**: девять cuts, четыре fresh recovery subprocess, actual quiescer ECHILD2 и final Stop/Pending. Этот уже принятый data-only факт не становится полным production main/live LKG.
