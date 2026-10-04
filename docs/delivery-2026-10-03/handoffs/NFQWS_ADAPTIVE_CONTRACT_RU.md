# NFQWS → ROOT / CORE / OPS: adaptive worker boundary, 04.10.2026

Работа в `sol/nfqws-20261004`, `C:/Projects/RAZVILKA/worktrees/sol-nfqws`. Это owned library foundation для существующего worker, не production admission. Нет нового scheduler, journal, RuntimeActivate, установки managed payload или изменений CORE/OPS/LAN-owned файлов. Public managed-ready constructor пока отсутствует.

## Изменение owned library

`AdaptiveSelector` сохраняет существующие `preferred` / `only` / `manual`, максимум четыре кандидата и двенадцать probes, общий budget до минуты, attempt до 15 секунд, cooldown и входной persisted `NotBefore`. Selector только рекомендует; не вызывает `Manager.Select`, не применяет маршрут и не присваивает VLESS reputation.

Ошибка probe `ErrCompatibilityQuiescenceUnknown`, включая wrapped/joined error одновременно с отменой, должна стать sticky unknown до обычной обработки local error. Такой результат не разрешает candidate recommendation или preferred VLESS fallback. Новый tick, cooldown, network epoch и manual request не снимают fence того же selector. Обычная доказанно settled local error сохраняет прежнюю семантику рекомендации fallback по consent + fresh verified reserve.

Новая **private** `managerAdaptiveFoundation` хранит тот же Manager и выдаёт непрозрачный `adaptiveCandidateBinding`. `newManagerAdaptiveFoundation(*Manager)`, `bind(Candidate)` и `validateBound(context.Context,adaptiveCandidateBinding)` — internal plumbing. Binding сохраняет exact ID, pool, name, raw arguments, origin и created time с отделёнными slices. Args → ID lookup отсутствует: два кандидата могут иметь одинаковые argv. Validation использует общую реализацию существующего `Manager.Validate`; сравнение identity и установка `nativeRunning` происходят под одним Manager lock. Повторная проверка перед publication не позволяет воскресить удалённый draft или перезаписать новую provenance того же ID.

Если результат стал unknown одновременно с удалением/rebind кандидата, private helper сохраняет глобальный fence в existing State без воссоздания старого candidate: schema 2 сохраняется как unknown; schema 3 удерживает только existing session.Unknown/finalizing через exact FileTarget CAS и independent cleanup context. Исторические commands/ACK/receipts и новая validation не меняются. Uncertain CAS сохраняет sticky unknown/writeBlocked и не перезаписывает foreign image. Это не новый receipt и не новый ledger.

Foundation принимает только exact `CompatibleValidator` с конкретным `*SupervisedCompatibilityProvider` того же Manager, trusted assets и matching reviewed binary/base. Nil/default `ExecValidator`, direct provider и arbitrary custom provider отказывают до исполнения. Глобальный unknown, finalizing, write block и busy admission проверяются независимо от списка запрошенных кандидатов. Foundation не реализует `Validator` / `ProbeExecutor`, не вызывает `Manager.Probe`, `m.Executor`, `Record` или `Select` и не является readiness proof.

Automatic `pack:` binding закрыт: текущие Origin и общий PackReceipts не доказывают принадлежность именно этого candidate подписанному payload. Receipt не превращается в доказательство membership. Пользовательские manual/expert данные сохраняются; отсутствие auto admission не разрешает их переписать.

## Вход и выход существующего CORE worker

Consumer должен находиться в уже существующем `autonomyRound` / `runAutonomyService` под общим Operations owner. Новый бюджетный цикл не нужен. Candidate-aware validation hook должен вызывать bound Manager path, а owned probe — тот же Manager admission и общий policy owner. Bare `Validator.Validate(ctx,args)` обходит необходимый manager gate и не подходит этому consumer.

CORE предоставляет explicit per-service adaptive mode, consent, frozen/manual state, неизменную service definition и protocol/family/scope, текущий network epoch, recovery gate, context deadline и Stop authority. NFQWS hostlist `user-list` / `auto` / `all` / `custom` — другой параметр; из него adaptive mode не выводится. Существующая starter branch с `ExpectedRoute == nfqws2` не является готовой реализацией preferred fallback.

`AdaptiveResult.RetryAt` нужно хранить в existing autonomy runtime/store и возвращать как `AdaptiveRequest.NotBefore`, включая restart. Сбрасываемый при reload `Runtime.NextCheck` не сохраняет этот cooldown. До первого effect нужен confirmed CAS reservation retry time с учётом batch budget + cooldown; после результата — confirmed save итогового RetryAt. Eligibility учитывает оба срока. Ошибка persistence блокирует effect: текущий путь, игнорирующий ошибку save, для этого admission не подходит. Поле и wiring принадлежат CORE; второй ledger не создаётся.

Candidate-ready recommendation допускается только после genuine known compatibility и трёх fresh route-confirmed typed probes нужного уровня с подтверждённой cleanup/quiescence. Frozen snapshot связывает mode/consent revision, exact service/definition/draft, scope/protocol/family, WAN epoch, candidate args/digests, OPS generation и Stop InstallationID/Sequence. Перед каждым actual effect и guarded Apply CORE повторно проверяет эту связку и recovery. Изменение отзывает recommendation. `Manager.Select` остаётся draft operation; один `route=nfqws2` не передаёт strategy ID/args в существующий adapter. Preferred reserve требует отдельного explicit VLESS consent и fresh verified reserve; only/manual не переключаются в VLESS. Ошибка unknown блокирует любую рекомендацию.

## Зависимости, которые ещё закрывают live consumer

| Владелец | Необходимая законченная boundary |
| --- | --- |
| CORE | Actual atomic-rename admission для финальной StrategyLab publication: prepared/fsynced bytes + existing FileTarget lease; control ID/sequence под общим Stop lock вокруг bounded rename; preparation и post-fsync вне lock. `f7a46bf` закрывает live-return failure, но rename → crash → unknown repair остаётся. |
| OPS | Sealed managed descriptor с explicit expected binary/assets digests, canonical ordered base, generation/provenance и immutable lease на весь lifecycle обеих фаз, Lua/timers, ECHILD и durable ACK. App-only lease недостаточен после parent death; helper должен удержать проверенную capability. Retained intent/unknown продолжает fencing cooperating package mutation после смерти обоих владельцев. |
| CORE / NFQWS / policy owner | Реальный owned probe/helper contract с exact scoped plan, admission actual process/firewall effects, durable intent/terminal receipts, sole descendant reap owner и подтверждённой cleanup. Наличие любого `ProbeExecutor`, boolean или interface marker этого не доказывает. |
| LAN / CORE | Unified LAN exclusion из общего policy owner перед route/proxy/WG/NFQWS/DNS. Свои MAC/ingress selectors NFQWS не создаёт. No-intercept compatibility не требует live LAN selectors. |

Текущий `SystemProbeExecutor` выбирает stock binary, напрямую запускает NFQWS и очищает direct child/iptables. Он не предоставляет durable descendant quiescence и **не допускается** как managed adaptive backend. Custom executor также не получает admission только по отличающемуся Go type. До перечисленных контрактов production consumer закрыт; private binding tests и model evidence не выдают ему capability.

## Проверки и статус

Local correction финальной publication сохранена в `f7a46bf8ae40785c8083c91fa8fcf77982ca770b`, поверх held `9cdcbff`; подробнее `NFQWS_SUPERVISED_RU.md`. CORE подтвердил, что actual atomic-rename hook ещё не готов и будет передан отдельным reviewable SHA/API.

ROOT сообщил independent Linux `nfqws-kernel-39` на точном `9cdcbff`: 13 kernel cases и supervised controller cancel/crash/Stop/foreign epoch RC0, Go1.26.5. Это принятие subprocess mechanism, не final publication и не genuine NFQWS. Native запуск остаётся только у ROOT; main router OFF.

ROOT отдельно сообщил genuine `genuine-root42` на official AMD64 zapret2 v1.0.5.2 с ordered reviewed Lua/blobs: normal dry-run 0 / Lua-init 0, missing-circular Lua rejection exit 1, isolated netns и intercept=0 без NFQUEUE/rules. Это meaningful CLI/Lua evidence, не принятие pending publication/worker. Более ранний non-root lua-reject по setpcap EPERM meaningful rejection не подтверждал; отдельный fixture checkpoint будет проверять точную Lua diagnostic. Для штатного privilege drop assets должны быть доступны dropped UID при сохранённом root/euid ownership и запрете group/other write; private controls/helper paths остаются 0700.

Финальная local Windows проверка foundation: StrategyLab 125 top-level PASS / 5 SKIP / 0 FAIL; components 69 PASS / 1 SKIP / 0 FAIL. JSON: ignored `.hil/nfqws/adaptive-foundation-windows-unit.jsonl`. Scoped app `NFQWS|Strategy`, dataplane `NFQWS`, vet StrategyLab/components — RC0. StrategyLab test binaries Linux amd64/arm64 cross-compile и diff/scope checks — RC0. Go1.26.5, GOTOOLCHAIN=local, GOMAXPROCS=2, GOFLAGS=-p=2. Независимый owned code/test review существенных пробелов в этом scope не нашёл. Native/process/race здесь не запускались.

Не заявляются production worker wiring, owned live probe либо закрытие rename → crash interval. Native evidence ROOT выше не подменяет эти зависимости.
