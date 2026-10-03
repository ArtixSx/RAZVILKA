# NFQWS — D09: bounded библиотека и quiescence fence

04.10.2026. Worktree `C:/Projects/RAZVILKA/worktrees/sol-nfqws`, ветка `sol/nfqws-20261004`, base `fe7d0ab9baaec1151c92593f308e080274903a93`. Владение этой порции: только `internal/strategylab/**`, новый собственный launcher и этот handoff. VERSION 0.19.3, go.mod/go.sum сохранены. Код в app/worker, policy/ownership/journal и NET AWG/WG/DNS не менялся.

## Аудит и конкретные пробелы

- `strategylab.ExecValidator` вызывал `--dry-run`; этот режим не запускает Lua. Библиотека не могла отличить проверку CLI/наличия файлов от реально загруженных функций/assets.
- `Manager.Probe` уже имеет resource gate, ограничение 15 секунд и временный точный OUTPUT/NFQUEUE путь. `SystemProbeExecutor` сериализовал пробы обычным mutex: ожидающий вызов не мог сразу выполнить Stop.
- `Manager.Record`/`summarize`/`consecutiveFailures` считали любой отрицательный результат отказом стратегии: отсутствующие утилиты, DNS, занятую очередь, локальный запуск/firewall/cleanup. Будущие timestamp раньше получали возраст 0; высокий уровень сценария не имел собственной свежести.
- Существующий выбор Strategy Lab — только перенос в draft после трёх проходов; `Frozen` сохраняет ручной выбор. В текущем `runAutonomyService` отдельный starter branch при `ExpectedRoute=nfqws2` вызывает `runNFQWS2Starter`, который явно NFQWS2-only. `PreferredRoutes` в общем worker — порядок кандидатов. Нельзя выводить only из одного предпочтения или подключать preferred через starter-only branch.
- `engineconfig.NFQWSMode` (`user-list/auto/all/custom`) описывает hostlist discovery. Это другая ось, чем D09 `preferred/only/manual`; новая библиотека её не переписывает.
- `NFQWS2Adapter.Stage` сохраняет полный config, изменяя только owned list blocks. Новых LAN policy additions библиотека не делает. Общий D07 executor/guard и VLESS addition receipt остаются отдельными зависимостями.

## Проверенный первичный upstream

Повторно проверены и закреплены 04.10.2026 на полном SHA `ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b`: [manual.md](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/docs/manual.md), [nfq2/nfqws.c](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/nfq2/nfqws.c), [nfq2/lua.c](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/nfq2/lua.c), [zapret-antidpi.lua](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/lua/zapret-antidpi.lua), [zapret-auto.lua](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/lua/zapret-auto.lua). Первое чтение 04.10 ссылалось на изменяемую ветку без snapshot/hash manifest; идентичность первоначально прочитанных bytes не доказана. Утверждения ниже проверены заново на этом pin. Дополнительно сверена существующая baseline [конфигурация Keenetic c77226b](https://github.com/nfqws/nfqws2-keenetic/blob/c77226bd384e047a3d97e3ab6f0ad8b46fc3c967/etc/nfqws2/nfqws2.conf), уже используемая BuiltinPack.

Upstream разделяет `--dry-run` и `--intercept=0`: первый проверяет CLI/файлы без Lua-init, второй инициализирует Lua без NFQUEUE. Blobs загружаются как Lua global strings; `fake/circular` существуют в соответствующих библиотеках. При неизвестной опции после уже разобранного `--dry-run` upstream выходит с ошибкой. [Linux startup L473–495](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/nfq2/nfqws.c#L473) открывает raw sockets до Lua-init даже при intercept=0; [NoInterceptLoop L243–273](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/nfq2/nfqws.c#L243) и [manual L1778–1779](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/docs/manual.md#L1778) подтверждают выполнение таймеров до опустошения их списка. Следовательно, intercept=0 не гарантирует ни быстрое завершение, ни отсутствие raw sending.

[SIGINT/SIGTERM L114–150](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/nfq2/nfqws.c#L114) запрашивают quit/Lua interrupt; [Lua hook L4651–4660](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/nfq2/lua.c#L4651) прерывает Lua bytecode. [Lua hardening L4204–4249](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/nfq2/lua.c#L4204) убирает execute/popen/loadlib/debug до init scripts, но это не process-tree proof: [Linux sec_harden L154–170](https://github.com/bol-van/zapret2/blob/ca950d838a0ee7dc32bb6ae5e65e54488c1bfe3b/nfq2/sec.c#L154) может вернуть false, а startup не проверяет этот результат. Native требует доверенных assets, отдельного контроля lifecycle и appropriate прав; произвольный Lua не разрешён. Это чтение исходников, **не запуск реального nfqws2 и не подтверждение версии установленного пакета**.

## Первая порция d64ac97 — исторические изменения

Коммит `d64ac97ee9fd4787db86220b590e2fce8a239344` принят координатором в integration `549308b`. Описания и результаты этого раздела относятся только к первой порции; текущие ограничения provider/quiescence перечислены во втором checkpoint ниже.

- `internal/strategylab/adaptive.go`: `AdaptiveSelector.Evaluate`, явные режимы и typed recommendation. По умолчанию до 4 кандидатов, до 12 probes (3 на кандидата), общий budget 60 секунд, attempt 15 секунд, cooldown 5 минут. Жёсткие пределы параметров, 512 входных кандидатов, 128 cooldown scopes. Одна активная batch на selector между всеми сервисами; параллельный вызов возвращает busy/cooldown. Duplicate IDs не дают повторного теста.
- `internal/strategylab/compatible.go`: первая версия `CompatibleValidator` требовала owner-granted `TrustedAssets`, reviewed data-only candidate grammar и абсолютные стандартные Lua/blob файлы. После dry-run выполняла Lua initialization с intercept=0 и generated assertions функций/blobs; обе успешные фазы давали `Validation.LuaChecked`. Это историческое поведение первой порции: прямой process exit не доказывал quiescence, и второй checkpoint ниже закрывает такой путь принятия. Inline/custom Lua и runtime options не допускаются; `InstalledBaseArguments()` читает конфигурацию без shell execution и не выдаёт trust.
- `internal/strategylab/evidence.go`, `strategylab.go`: `Outcome=pass/service-fail/local-error/inconclusive`, `Level=packet/http/media/voice/game`, независимые `Summary.Coverage{Level,LastPassedAt,Fresh}`. HTTP не подтверждает media/voice/game. Локальные результаты сохраняются для видимости, исключаются из confidence/failure reputation и не вызывают rollback. Без подтверждённого route отрицательный результат inconclusive. Неопределённость разрывает consecutive failure quorum. Старые local/route failure records классифицируются консервативно при чтении; будущие/невалидные/stale timestamps не делают evidence свежим и не запускают rollback.
- `internal/strategylab/probe.go`: context-aware очередь вместо неотменяемого mutex; один immutable reviewed base можно передать и в validator, и в probe. Реальная HTTPS/H3 проба обозначается только HTTP. `Manager.Probe` не записывает поздний успех после Stop.
- `adaptive_test.go`, `compatible_test.go`, `evidence_test.go`: 19 новых test-функций, включая одну opt-in native fixture. Границы: manual/only/preferred, согласие и свежий VLESS reserve, ровно 12 probes, duplicates/пользовательская стратегия, точный cooldown/restart NotBefore, low-memory/missing inspector, concurrency/Stop/deadline, wrong-service/future/stale evidence, dry-run без Lua, отсутствующая опция intercept, недоверенные/inline/custom assets, сохранение local diagnostics после restart, независимая свежесть сценариев и поздний успех после Stop.
- `strategylab_test.go`: прежние rollback/frozen/decay регрессии сохранены. Их отрицательные fixture теперь доказывают route и service rejection; неуспех route не притворяется service failure. Test clock действительно продвигается до новых успешных timestamps.
- `scripts/test-nfqws-compatibility.sh`: новый opt-in launcher только для coordinator fixture; shared check.sh не менялся.

AdaptiveSelector не записывает/не заменяет Candidates, Selections, пользовательский config или стратегию. `candidate-ready` — три свежие подтверждённые пробы запрошенного уровня, рекомендация для draft review; ни Apply, ни разрешение менять LKG. `FallbackEligible` — только preferred + явное VLESSAllowed + supplied fresh verified reserve. only/manual/frozen/Stop/busy/cooldown не получают автоматический fallback. Не добавлен AUTO default для неизвестного/пустого режима.

## Первая порция d64ac97 — фактические проверки

Среда первой порции: Go 1.26.5 windows/amd64, `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`. Production module без подмены/test-double модуля. Результаты финальной версии **первой порции**, не второго checkpoint:

| Команда | RC и граница |
|---|---|
| `go test -count=1 -json ./internal/strategylab` | 0; 46 top-level test-функций PASS, 1 native fixture SKIP; subtests отдельно в JSON, не суммируются как новые функции |
| `go vet ./internal/strategylab` | 0 |
| `go test -count=1 ./internal/dataplane -run NFQWS` | 0; существующий NFQWS lifecycle/ownership/rollback набор |
| `go test -count=1 ./internal/app -run 'Strategy\|NFQWS'` | 0; существующий draft/API/starter контракт; новый worker не реализован |
| `go test -race -count=1 ./internal/strategylab` | 1 до запуска тестов: `-race requires cgo`; CGO в Windows среде отключён. Race **not_run**, Linux race выполняет координатор |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ./internal/strategylab` | 0; только compile |
| `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/strategylab` | 0; только compile |
| `sh -n scripts/test-nfqws-compatibility.sh`, `git diff --check` | 0; синтаксис/whitespace |

Локальный test JSON и два cross-compiled test binaries: `.hil/nfqws/` в этом worktree; каталог игнорируется Git, артефакты не коммитятся. Существующий общий Linux PASS базы не переносится на этот diff. Все перечисленные unit/API/NFQWS regressions, vet/cross-build выполнены на финальном коде этой порции. Проверка `git diff --exit-code -- VERSION go.mod go.sum` имеет RC 0.

Независимая проверка координатора `cloud-nfqws-01`: race/app/vet имеют RC 0 для первой принятой порции `d64ac97` / integration `549308b`. Эти результаты **не распространяются** на второй checkpoint.

## Второй checkpoint — bounded provider и sticky unknown

Base `d64ac97ee9fd4787db86220b590e2fce8a239344`. Владение остаётся в `internal/strategylab/**`, собственных `scripts/test-nfqws-*` и этом handoff; CORE/app, общий ownership/policy/execution journal и NET не меняются.

- `CompatibleValidator` требует явно переданный trusted `CompatibilityProvider`. При nil возвращает `SUPERVISION_REQUIRED` до запуска; `TrustedAssets` само по себе не предоставляет lifecycle authority. Provider должен подтвердить quiescence конкретного invocation со всеми descendants; exit 0, отсутствие одного PID, пустой process scan или закрытые pipes такого доказательства не дают.
- Конкретный `CompatibilityProcessProvider` ограничивает direct-process/pipe wait через `WaitDelay` и cleanup grace 1 секунда. Он сохраняет `QUIESCENCE_UNKNOWN` **после любого начатого invocation, включая exit 0**; не выдаёт Native/LuaChecked/compatibility PASS и не допускает следующий запуск после unknown. Поздний ответ, ошибка или concurrent return не очищают fence.
- `Manager` сохраняет sticky unknown в существующем Strategy Lab state; unknown повышает schema до 2. Новый reader понимает schema 1/2, старый downgrade reader отвергает schema 2. Успешная повторная validation, удаление/переимпорт кандидата, error/concurrent return не могут снять fence. Validate/Probe имеют единый admission/busy gate под lock до завершения и сохранения результата. Selector останавливает batch до следующего кандидата/пробы/fallback, включая unknown из concurrent Evaluate; перед публикацией проверяет общий latch. Record не может занести свежий успешный evidence поверх unknown.
- Существующий package supervisor связан с opkg, точным operation ownership и durable transaction journal. Его authority нельзя перенести на standalone Lua-init запуск. Второй общий журнал и новый CORE контракт не создаются.

Unknown записывается только после результата: crash между spawn и сохранением fence **остаётся недоказанной границей**. Direct provider не готов для production worker; wiring app/worker в этой порции отсутствует. Проверяемая bounded выдача unknown не является proof завершения дерева процессов или crash-safe cleanup.

Проверки второго checkpoint на Go 1.26.5 windows/amd64, production module, GOTOOLCHAIN=local/GOMAXPROCS=2/GOFLAGS=-p=2: `go test -count=1 -json ./internal/strategylab` — RC 0, 59 top-level PASS и 3 opt-in SKIP; `go vet ./internal/strategylab`, app `-run 'Strategy|NFQWS'`, dataplane `-run NFQWS` — RC 0. Linux amd64/arm64 test binaries успешно cross-compiled; это только compile, не Linux/native execution. `sh -n` обоих собственных launchers, `git diff --check`, protected VERSION/go.mod/go.sum — RC 0. JSON и binaries в ignored `.hil/nfqws/strategylab-quiescence-*`. Native/process fixtures и race второй порции здесь not_run; исторический cloud race PASS не переносится на этот commit.

## Конкретный контракт CORE

1. Сохранить отдельное explicit per-service NFQWS adaptive mode с CAS/consent; не трактовать `PreferredRoutes`/hostlist MODE_AUTO как only/manual. Manual/frozen и starter-only должны сохраняться. Preferred не должен входить в существующий unconditional starter-only branch и очищать явно разрешённые `r.Reserves`.
2. Создать **один** долгоживущий `AdaptiveSelector` для worker. Перед Evaluate проверить consent/SafeMode/Stop/recovery fence/definition/draft/revision/network/scope. Передать `NetworkID`, trusted catalog target, immutable Candidates snapshot, нужный scenario level, ограничения. Executor/validator/provider — явные зависимости, resource inspector обязателен. До запуска утилит компонентный owner подтверждает provenance/ownership assets; browser не устанавливает TrustedAssets. `QuiescenceUnknown` блокирует следующую работу; concrete direct provider не даёт production разрешения на worker.
3. Получить `InstalledBaseArguments()` один раз для batch; передать одинаковую immutable копию в `CompatibleValidator.BaseArguments` и `SystemProbeExecutor.BaseArguments`. Изменение config/package/assets/network между проверкой и Apply требует нового review/validation. Факт Lua-init PASS не проверяет всю packet-time семантику Lua и не разрешает сетевые мутации.
4. Сохранять `RetryAt` через существующий worker/runtime store; после restart передавать его как `AdaptiveRequest.NotBefore`. Внутренние cooldown/active state process-local; библиотека не создаёт второй persistent journal. Workers должны ограниченно ротировать candidate order между batch, если хотят обследовать больше первых четырёх: новый cursor в этой порции не добавлен.
5. На `candidate-ready` выполнить новый CAS/Stop/ownership/network readback, перенести только выбранный reviewed аргумент через существующий draft/Apply transaction с сохранением пользовательского raw config и LKG. Read/UI не вызывает Evaluate/Validate/Apply. `FallbackEligible` даёт рекомендацию: перед настоящим VLESS Apply повторить exact-engine/source/node/fresh route proof, budgets и shared transaction. Ошибки local/inconclusive не передавать в NodeStore/source reputation и не вызывать `Observe(...,"FAIL")`.
6. `Summary.Eligible` остаётся лабораторной готовностью к draft, не runtime/media health. `Coverage.LastPassedAt/Fresh` — свежесть последнего успешного **собственного** сценария, не green status после более нового отказа; для текущего health CORE/UI используют также typed последние Evidence. SystemProbeExecutor имеет HTTPS/H3, а voice/game protocol executor отсутствует: UDP unsupported не становится отрицательной оценкой узла.
7. `NETWORK_POLICY_EXECUTOR_REQUIRED` сохраняется. NFQWS Activate этой порцией не менялся и новых ip route/rule additions нет, поэтому `policy_addition_receipt` не подключён здесь. Перед будущим NFQWS/LAN executor CORE должен использовать общий VLESS-owned receipt/API для exact additions и unknown cleanup fence. Existing temporary OUTPUT probe имеет defer cleanup, но durable crash recovery firewall-пробы **не доказан**; автоматический фон нельзя объявлять crash-safe на основании unit. Нужен согласованный общий ownership/cleanup контракт и native fault acceptance, не второй журнал NFQWS и не отдельный route replace.

## UI контракт

Показывать отдельно режим и действие: «предпочтителен NFQWS2», «только NFQWS2», «ручной». Выводить code, candidate attempts, RetryAt и причина local-unavailable/incompatible/inconclusive. Показывать собственные packet/HTTP/media/voice/game отметки времени и Fresh; отсутствие отметки означает «не проверено». HTTP/H3/bytes read не подписывать «видео/голос/игра работают». Compatible/LuaChecked отдельно от сервисной/применённой проверки. FallbackEligible не означает applied и не открывает Apply без серверных gates.

## Opt-in native fixture — один case, затем unknown

Подготовить в отдельном **reviewed disposable** каталоге плоские файлы `zapret-lib.lua`, `zapret-antidpi.lua`, `zapret-auto.lua`, `tls_clienthello.bin` из доверенной установленной версии; каталог/родители читаемы для nfqws2 после privilege drop. Не копировать приватные профили. Доверенный настоящий binary дать абсолютным путём. Launcher ничего не скачивает и не создаёт live NFQUEUE/firewall rules. Native Lua-init всё ещё открывает raw sockets; соответствующие права и live окно принадлежат только координатору.

Обязательно выбрать ровно один `RAZVILKA_NFQWS_NATIVE_CASE`: `dry-run`, `lua-init`, `lua-syntax`, `missing-function` или `missing-blob`. Каждый запуск выполняет **одно** native invocation и после него сохраняет unknown, независимо от ожидаемого exit status. Следующий case допустим только после отдельного cleanup review координатора; новый provider/process не снимает fence. Fixture проверяет настоящий CLI/Lua exit и консервативный unknown, **не выдаёт compatibility PASS или production readiness**. Отрицательные cases используют фиксированные disposable изменения, а не произвольный Lua.

```sh
RAZVILKA_NFQWS_NATIVE_BINARY=/absolute/reviewed/nfqws2 \
RAZVILKA_NFQWS_NATIVE_ASSETS=/absolute/disposable/flat-assets \
RAZVILKA_NFQWS_NATIVE_CASE=dry-run \
GO_BIN=/absolute/go sh scripts/test-nfqws-compatibility.sh
```

Для router без Go использовать собственный cross-compiled test binary:

```sh
RAZVILKA_NFQWS_NATIVE_BINARY=/absolute/reviewed/nfqws2 \
RAZVILKA_NFQWS_NATIVE_ASSETS=/absolute/disposable/flat-assets \
RAZVILKA_NFQWS_NATIVE_CASE=dry-run \
/absolute/strategylab-linux-arm64.test -test.v -test.timeout=2m -test.run '^TestNFQWSNativeCompatibilityNoIntercept$'
```

## Opt-in process fixture — timer и inherited pipes

`scripts/test-nfqws-quiescence.sh` требует `RAZVILKA_NFQWS_PROCESS_FIXTURE=1`. Fixture запускает фиксированный Go child с timer и отдельный Linux child через setsid с inherited stdout/stderr. Lua, настоящего nfqws2, live сеть, NFQUEUE, firewall, package transaction, PID namespace или subreaper здесь не используются. Проверка должна подтвердить bounded return после Stop/сохранения pipes и unknown после exit 0 непосредственного parent при оставшемся child; это не имитация совместимости и не универсальная гарантия cleanup. Child имеет watchdog 20 секунд; detached cleanup пишет приватный release-marker и ждёт acknowledgement максимум 2 секунды, не сигналит numeric PID и не считает done-marker quiescence receipt. Birth/cmdline проверяются лишь для фиксации оставшегося fixture child.

```sh
RAZVILKA_NFQWS_PROCESS_FIXTURE=1 \
GO_BIN=/absolute/go sh scripts/test-nfqws-quiescence.sh
```

Для router без Go — reviewed cross-compiled test binary, запуск только координатором:

```sh
RAZVILKA_NFQWS_PROCESS_FIXTURE=1 \
/absolute/strategylab-linux-arm64.test -test.v -test.timeout=2m \
  -test.run '^(TestNFQWSNativeCompatibilityProcessCancellation|TestNFQWSNativeCompatibilityInheritedPipes)$'
```

Обе fixtures второго checkpoint локально **not_run**; предыдущий native SKIP относится к первой порции. Linux race новой порции, native CLI/assets, real LAN/IPv6/H3 selected/control, Stop cleanup fault/power cut, media/voice/game, router/HIL/soak остаются **unverified/not_run**. D09 целиком не закрыт; production worker wiring и crash между spawn/save fence не доказаны.
