# NFQWS → ROOT / CORE: D11 inactivity boundary, 04.10.2026

Read-only audit проведён в owned `sol/nfqws-20261004` на `473f8bd` и ROOT `delivery-review` на `a1eb4a9`. Этот отдельный checkpoint содержит только два ordinary regression tests и handoff; adaptive/Lua implementation не меняется. Inactivity observer не объявлен готовым, cleanup/runtime effects/new ledger не добавляются.

## Конкретный blocker

`nfqws2Lease` version 1 в `internal/dataplane/nfqws2_ownership.go` сохраняет StateRoot/owner/transaction, config/init hashes и два managed list block hashes. Это file/resource intent, а не process/kernel lifecycle receipt. В нём отсутствуют recorded boot/process birth/group/executable/argv identity, exact IPv4/IPv6 kernel attachments/queue owner и pending/settled process disposition. `prepareActivationLease` пишет этот intent до изменений файлов, затем `Activate` делегирует запуск пакетному init `restart`; owned daemon launch receipt не производится.

`Deactivate` при missing lease возвращает nil. При owned lease он удаляет managed blocks, выполняет package init **restart** и удаляет lease. Успешное завершение может оставить daemon работающим. Lease absence не отличает never-owned instance от retired list cleanup и не доказывает absence owned/foreign runtime. Старое Deactivate или отсутствие PID не подходят как `VerifyRuntimeInactive` proof.

`VerifyRollback` проверяет восстановление своего snapshot. Для stopped snapshot достаточно init `not running` и отсутствия queue rule в цепочке с префиксом `nfqws` в IPv4 `iptables-save`. Foreign chain с тем же NFQUEUE, IPv6 и точная process identity этим не исключаются. Такой rollback result не является global inactivity proof, даже при exact file lease.

`lockResources` также не является чистым read-only observation primitive: при missing marker он создаёт постоянный lock file. Само наличие такого marker не служит runtime authority. Новый compatibility supervisor receipt StrategyLab и accepted OPS `NFQWSRuntimeDescriptor` не описывают legacy package daemon адаптера и не заменяют отсутствующее launch/settlement evidence.

Поэтому honest `NFQWS2Adapter.VerifyRuntimeInactive(ctx) error` с successful branch нельзя завершить небольшим read-only дополнением к текущему producer. Нужен finished runtime ownership producer/lifecycle в **existing** lease/control boundary, который записывает exact authority перед actual process/kernel effects и сохраняет подтверждённое settlement для fresh observer. Его legacy/missing/pending/unknown/foreign cases должны оставаться refusal. Второй журнал не нужен. Общий Manager aggregator принадлежит CORE/DEFAULT; отсутствие NFQWS observer должно блокировать D11 inactivity admission, включая unused adapter или missing lease. Always-nil либо boolean-ready заглушка не добавляется.

## Meaningful ordinary regressions

`TestNFQWS2SuccessfulDeactivateDoesNotProveRuntimeInactive` выполняет настоящие adapter activation/deactivation paths с modeled package runner. Owned blocks удалены и lease retired, но отдельный fresh init status read по-прежнему running. Тест показывает конкретный несовместимый результат, не моделируя native proof как success.

`TestNFQWS2StoppedRollbackProofDoesNotExcludeForeignQueue` восстанавливает stopped snapshot с exact files/lease, получает confirmed existing rollback при fresh status/IPv4 readback и остающемся foreign-chain NFQUEUE на том же queue 300. VerifyRollback остаётся read-only; это доказательство границы его назначения, а не изменение rollback semantics.

Локально Windows Go1.26.5: targeted dataplane `NFQWS` 25 top-level PASS / 0 FAIL, включая обе новые boundary regressions; vet dataplane, Linux amd64/arm64 dataplane test cross-compile и diff check — RC0. JSON ignored `.hil/nfqws/inactivity-boundary-windows.jsonl`. GOTOOLCHAIN=local, GOMAXPROCS=2, GOFLAGS=-p=2. Native/race/router проверки здесь не запускались.

ROOT отдельно сообщил independent acceptance и merge `ef0b959` + strict Lua fixture `34eeea4` + incarnation correction `473f8bd` как library checkpoint; atomic rename/production consumer cap остаётся closed. Следующий обязательный checkpoint — actual managed NFQWS lifecycle/ownership producer и fresh process/kernel observer в existing lease/session с supervised ACK, exact attachments и real isolated native harness для ROOT. Эти два regression tests не завершают D11 dependency. Legacy ambiguous records остаются fenced; stock package daemon не трогаем. Actual managed probe продолжится по finished CORE launch/Stop/prepared-rename/scoped hooks без второго scheduler.
