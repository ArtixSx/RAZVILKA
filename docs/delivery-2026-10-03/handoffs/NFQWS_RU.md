# NFQWS — D09: bounded библиотека, первая порция

04.10.2026. Worktree `C:/Projects/RAZVILKA/worktrees/sol-nfqws`, ветка `sol/nfqws-20261004`, base `fe7d0ab9baaec1151c92593f308e080274903a93`. Владение этой порции: только `internal/strategylab/**`, новый собственный launcher и этот handoff. VERSION 0.19.3, go.mod/go.sum сохранены. Код в app/worker, policy/ownership/journal и NET AWG/WG/DNS не менялся.

## Аудит и конкретные пробелы

- `strategylab.ExecValidator` вызывал `--dry-run`; этот режим не запускает Lua. Библиотека не могла отличить проверку CLI/наличия файлов от реально загруженных функций/assets.
- `Manager.Probe` уже имеет resource gate, ограничение 15 секунд и временный точный OUTPUT/NFQUEUE путь. `SystemProbeExecutor` сериализовал пробы обычным mutex: ожидающий вызов не мог сразу выполнить Stop.
- `Manager.Record`/`summarize`/`consecutiveFailures` считали любой отрицательный результат отказом стратегии: отсутствующие утилиты, DNS, занятую очередь, локальный запуск/firewall/cleanup. Будущие timestamp раньше получали возраст 0; высокий уровень сценария не имел собственной свежести.
- Существующий выбор Strategy Lab — только перенос в draft после трёх проходов; `Frozen` сохраняет ручной выбор. В текущем `runAutonomyService` отдельный starter branch при `ExpectedRoute=nfqws2` вызывает `runNFQWS2Starter`, который явно NFQWS2-only. `PreferredRoutes` в общем worker — порядок кандидатов. Нельзя выводить only из одного предпочтения или подключать preferred через starter-only branch.
- `engineconfig.NFQWSMode` (`user-list/auto/all/custom`) описывает hostlist discovery. Это другая ось, чем D09 `preferred/only/manual`; новая библиотека её не переписывает.
- `NFQWS2Adapter.Stage` сохраняет полный config, изменяя только owned list blocks. Новых LAN policy additions библиотека не делает. Общий D07 executor/guard и VLESS addition receipt остаются отдельными зависимостями.

## Проверенный первичный upstream

Прочитаны 04.10.2026: [manual.md](https://github.com/bol-van/zapret2/blob/master/docs/manual.md), [nfq2/nfqws.c](https://github.com/bol-van/zapret2/blob/master/nfq2/nfqws.c), [nfq2/lua.c](https://github.com/bol-van/zapret2/blob/master/nfq2/lua.c), [zapret-antidpi.lua](https://github.com/bol-van/zapret2/blob/master/lua/zapret-antidpi.lua), [zapret-auto.lua](https://github.com/bol-van/zapret2/blob/master/lua/zapret-auto.lua). Дополнительно сверена существующая baseline [конфигурация Keenetic c77226b](https://github.com/nfqws/nfqws2-keenetic/blob/c77226bd384e047a3d97e3ab6f0ad8b46fc3c967/etc/nfqws2/nfqws2.conf), уже используемая BuiltinPack.

Upstream разделяет `--dry-run` и `--intercept=0`: первый проверяет CLI/файлы, второй инициализирует Lua без NFQUEUE. C-код подтверждает этот порядок и загрузку blobs как Lua global strings. Функции `fake/circular` существуют в соответствующих библиотеках. При неизвестной опции после `--dry-run` upstream выходит с ошибкой, поэтому проверка поддержки `--intercept=0` выполняется сначала в dry-run. Нативный режим всё ещё может создавать raw sockets и выполнять Lua-init/таймеры: он требует доверенных assets и прав, а не является sandbox произвольного пользовательского кода. Это чтение документации/исходников, **не запуск реального nfqws2 и не подтверждение версии установленного пакета**.

## Изменённые файлы и результат

- `internal/strategylab/adaptive.go`: `AdaptiveSelector.Evaluate`, явные режимы и typed recommendation. По умолчанию до 4 кандидатов, до 12 probes (3 на кандидата), общий budget 60 секунд, attempt 15 секунд, cooldown 5 минут. Жёсткие пределы параметров, 512 входных кандидатов, 128 cooldown scopes. Одна активная batch на selector между всеми сервисами; параллельный вызов возвращает busy/cooldown. Duplicate IDs не дают повторного теста.
- `internal/strategylab/compatible.go`: отдельный `CompatibleValidator`. Требует owner-granted `TrustedAssets`, reviewed data-only candidate grammar и абсолютные стандартные Lua/blob файлы. Сначала dry-run с intercept=0, затем реальная Lua initialization с intercept=0 и generated assertions наличия функций/blobs. `Validation.LuaChecked` выдаётся только после обеих успешных фаз. Inline/custom Lua и runtime options не допускаются; неизвестный binary/options/assets отклоняются до probe. `InstalledBaseArguments()` читает текущую конфигурацию без shell execution; trust не выдаёт.
- `internal/strategylab/evidence.go`, `strategylab.go`: `Outcome=pass/service-fail/local-error/inconclusive`, `Level=packet/http/media/voice/game`, независимые `Summary.Coverage{Level,LastPassedAt,Fresh}`. HTTP не подтверждает media/voice/game. Локальные результаты сохраняются для видимости, исключаются из confidence/failure reputation и не вызывают rollback. Без подтверждённого route отрицательный результат inconclusive. Неопределённость разрывает consecutive failure quorum. Старые local/route failure records классифицируются консервативно при чтении; будущие/невалидные/stale timestamps не делают evidence свежим и не запускают rollback.
- `internal/strategylab/probe.go`: context-aware очередь вместо неотменяемого mutex; один immutable reviewed base можно передать и в validator, и в probe. Реальная HTTPS/H3 проба обозначается только HTTP. `Manager.Probe` не записывает поздний успех после Stop.
- `adaptive_test.go`, `compatible_test.go`, `evidence_test.go`: 19 новых test-функций, включая одну opt-in native fixture. Границы: manual/only/preferred, согласие и свежий VLESS reserve, ровно 12 probes, duplicates/пользовательская стратегия, точный cooldown/restart NotBefore, low-memory/missing inspector, concurrency/Stop/deadline, wrong-service/future/stale evidence, dry-run без Lua, отсутствующая опция intercept, недоверенные/inline/custom assets, сохранение local diagnostics после restart, независимая свежесть сценариев и поздний успех после Stop.
- `strategylab_test.go`: прежние rollback/frozen/decay регрессии сохранены. Их отрицательные fixture теперь доказывают route и service rejection; неуспех route не притворяется service failure. Test clock действительно продвигается до новых успешных timestamps.
- `scripts/test-nfqws-compatibility.sh`: новый opt-in launcher только для coordinator fixture; shared check.sh не менялся.

Библиотека не записывает/не заменяет Candidates, Selections, пользовательский config или стратегию. `candidate-ready` — три свежие подтверждённые пробы запрошенного уровня, рекомендация для draft review; ни Apply, ни разрешение менять LKG. `FallbackEligible` — только preferred + явное VLESSAllowed + supplied fresh verified reserve. only/manual/frozen/Stop/busy/cooldown не получают автоматический fallback. Не добавлен AUTO default для неизвестного/пустого режима.

## Фактические проверки

Среда: Go 1.26.5 windows/amd64, `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`. Production module без подмены/test-double модуля. Результаты final библиотечной версии:

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

## Конкретный контракт CORE

1. Сохранить отдельное explicit per-service NFQWS adaptive mode с CAS/consent; не трактовать `PreferredRoutes`/hostlist MODE_AUTO как only/manual. Manual/frozen и starter-only должны сохраняться. Preferred не должен входить в существующий unconditional starter-only branch и очищать явно разрешённые `r.Reserves`.
2. Создать **один** долгоживущий `AdaptiveSelector` для worker. Перед Evaluate проверить consent/SafeMode/Stop/recovery fence/definition/draft/revision/network/scope. Передать `NetworkID`, trusted catalog target, immutable Candidates snapshot, нужный scenario level, ограничения. Executor/validator — явные зависимости, resource inspector обязателен. До запуска утилит компонентный owner подтверждает provenance/ownership assets; browser не устанавливает TrustedAssets.
3. Получить `InstalledBaseArguments()` один раз для batch; передать одинаковую immutable копию в `CompatibleValidator.BaseArguments` и `SystemProbeExecutor.BaseArguments`. Изменение config/package/assets/network между проверкой и Apply требует нового review/validation. Факт Lua-init PASS не проверяет всю packet-time семантику Lua и не разрешает сетевые мутации.
4. Сохранять `RetryAt` через существующий worker/runtime store; после restart передавать его как `AdaptiveRequest.NotBefore`. Внутренние cooldown/active state process-local; библиотека не создаёт второй persistent journal. Workers должны ограниченно ротировать candidate order между batch, если хотят обследовать больше первых четырёх: новый cursor в этой порции не добавлен.
5. На `candidate-ready` выполнить новый CAS/Stop/ownership/network readback, перенести только выбранный reviewed аргумент через существующий draft/Apply transaction с сохранением пользовательского raw config и LKG. Read/UI не вызывает Evaluate/Validate/Apply. `FallbackEligible` даёт рекомендацию: перед настоящим VLESS Apply повторить exact-engine/source/node/fresh route proof, budgets и shared transaction. Ошибки local/inconclusive не передавать в NodeStore/source reputation и не вызывать `Observe(...,"FAIL")`.
6. `Summary.Eligible` остаётся лабораторной готовностью к draft, не runtime/media health. `Coverage.LastPassedAt/Fresh` — свежесть последнего успешного **собственного** сценария, не green status после более нового отказа; для текущего health CORE/UI используют также typed последние Evidence. SystemProbeExecutor имеет HTTPS/H3, а voice/game protocol executor отсутствует: UDP unsupported не становится отрицательной оценкой узла.
7. `NETWORK_POLICY_EXECUTOR_REQUIRED` сохраняется. NFQWS Activate этой порцией не менялся и новых ip route/rule additions нет, поэтому `policy_addition_receipt` не подключён здесь. Перед будущим NFQWS/LAN executor CORE должен использовать общий VLESS-owned receipt/API для exact additions и unknown cleanup fence. Existing temporary OUTPUT probe имеет defer cleanup, но durable crash recovery firewall-пробы **не доказан**; автоматический фон нельзя объявлять crash-safe на основании unit. Нужен согласованный общий ownership/cleanup контракт и native fault acceptance, не второй журнал NFQWS и не отдельный route replace.

## UI контракт

Показывать отдельно режим и действие: «предпочтителен NFQWS2», «только NFQWS2», «ручной». Выводить code, candidate attempts, RetryAt и причина local-unavailable/incompatible/inconclusive. Показывать собственные packet/HTTP/media/voice/game отметки времени и Fresh; отсутствие отметки означает «не проверено». HTTP/H3/bytes read не подписывать «видео/голос/игра работают». Compatible/LuaChecked отдельно от сервисной/применённой проверки. FallbackEligible не означает applied и не открывает Apply без серверных gates.

## Opt-in native fixture координатору

Подготовить в отдельном **reviewed disposable** каталоге плоские файлы `zapret-lib.lua`, `zapret-antidpi.lua`, `zapret-auto.lua`, `tls_clienthello.bin` из доверенной установленной версии; каталог/родители читаемы для nfqws2 после privilege drop. Не копировать приватные профили. Доверенный настоящий binary дать абсолютным путём. Launcher ничего не скачивает и не создаёт live NFQUEUE/firewall rules; fixture создаёт/удаляет только свою temp directory и исполняет reviewed Lua-init без перехвата. Требуются appropriate native permissions/raw socket capability; запуск — только координатор.

```sh
RAZVILKA_NFQWS_NATIVE_BINARY=/absolute/reviewed/nfqws2 \
RAZVILKA_NFQWS_NATIVE_ASSETS=/absolute/disposable/flat-assets \
GO_BIN=/absolute/go sh scripts/test-nfqws-compatibility.sh
```

Для router без Go использовать собственный cross-compiled test binary:

```sh
RAZVILKA_NFQWS_NATIVE_BINARY=/absolute/reviewed/nfqws2 \
RAZVILKA_NFQWS_NATIVE_ASSETS=/absolute/disposable/flat-assets \
/absolute/strategylab-linux-arm64.test -test.v -test.timeout=2m -test.run '^TestNFQWSNativeCompatibilityNoIntercept$'
```

Fixture требует PASS хорошей версии и reject broken Lua syntax, отсутствующей функции fake и отсутствующего blob; NFQUEUE/live traffic не испытываются. Здесь fixture SKIP. Linux race, native CLI/assets, real LAN/IPv6/H3 selected/control, Stop cleanup fault/power cut, media/voice/game, router/HIL/soak — **unverified/not_run**. D09 целиком не закрыт; следующая крупная вертикаль после review координатора.
