# NET — COMMON synthetic baseline issuer dependency

Дата: 11.10.2026. Worktree `sol-net`, базовый pin `39dd4c1876ea037c8b1f2e669902495b809a0e29`.

Порядок Root на 11.10: сначала callable literalIP Xray в обычном App (CORE/VLESS), затем полная synthetic-доменная вертикаль. Миграция 0.19.3 и ниже не является задачей: чистая 0.20.0, затем будущие обновления с сохранением, rollback и расписанием. Этот документ описывает dependency portion, не готовый publisher и не аппаратную приёмку.

## Связанный путь

NET владеет новыми `synthetic_baseline_coordinator.go`, `synthetic_baseline_execution_resource.go` и их тестами. CORE владеет shared scope, регистрацией и existing journal hooks. Main/App/Manager/journal-файлы NET не меняет.

1. Исходный `Manager.BindSyntheticDNSExecution` сохраняет конечный operation context и зарегистрированный ScopedDNSAdapter. Закрытие scope отменяет и присоединяет исходную phase.
2. `Lease.SyntheticDNSCommandTools()` в `internal/startuptools/synthetic_dns_tools.go` возвращает descriptor с конкретным runner исходного удерживаемого Lease. Новый Acquire для DNS request не допустим.
3. `ProxyTunnelAdapter.RunDomainPolicyTCP → serveDomainPolicyTCPCapture → owner.WithCapture` передаёт исходный открытый `*DomainPolicyTCPCapture`. Он является входом; observation либо prepared mapping не заменяет listener.
4. `binding.bindBaselineCoordinator` удерживает конкретные binding/tools/backend/capture/control. `Current` проверяет исходную конечную операцию, исходный DNS session/control, реальный capture.Current/address и зарегистрированный Xray adapter, совпадение client/device/MAC/iif/name, provider/NI/tool review и frozen runner. CORE регистрирует только этот исходный aggregate.
5. `binding.issueBaseline` проверяет исходный mapping и frozen transport, получает инструменты из этой регистрации, создаёт original inspector и pre-issued retirement view именно SAME DNS source; через CORE `reserveSyntheticBaseline` записывает planned intent до открытия COMMON receipt и до эффекта. Конкурирующий issuer переиспользует только SAME original mapping/backend/capture; отказ persistence остаётся fenced.
6. `resource.prepareBaseline` выполняет четыре эффекта через existing COMMON. Конкретный sealed `SyntheticDNSCommandAdmission` сравнивает исходный per-RPC invocation и вызывает control.WithStart только вокруг actual Cmd.Start. Полные callbacks выполняются до входа в tool source lock; на Start только локальные сравнения. Wait и durable ACK остаются отдельными.
7. `currentBaseline` удерживает actual receipt document/permanent-lock descriptors и canonical image через complete one-image kernel readback и closing owner reads. Нужны все четыре ACK и все четыре эффекта в одном полном image. После этого CORE записывает `baseline-prepared`.
8. `prepareCapture` вызывает actual `capture.PrepareSyntheticMapping` только после baseline ACK/readback и проверяет prepared.Current до записи `capture-ready`.

Unknown Start/Wait/ACK/readback/persist оставляет fence; новая попытка не повторяет Add. У issuer нет удаления baseline, reuse адреса, обхода Stop или конечного publication Ready. Приоритет исключений и исходные auth/CSRF/CAS/ownership/TLS guards не меняются.

## Открытый production consumer

В базовом sol-net production `DomainPolicyTCPExecutionOwner` отсутствует; есть только явный socket/process model в тестах. Новые source/issuer методы пока не вызываются обычным App. Наличие методов не заменяет actual producer. Полный native RPDB/post-DNAT firmware-equivalence source ещё нужен: CheckPrepared доказывает pre-DNAT часть, а не весь путь.

Единственный следующий путь предлагается согласовать с CORE после literalIP-порции:

`actual App list policy owner → SAME Manager frozen domain/synthetic plan → ONE DomainPolicyTCPExecutionOwner → original WithTCPProcess/WithCapture registration → NET baseline source/reserve/COMMON → actual prepared capture → original publication owner → Manager Commit transfer ACK → receiver/baseline retainer`.

CORE владеет App/Manager/control/journal, shared inventory observations и durable Commit transfer. VLESS владеет реальным Xray process/selected TCP consumer. CORE согласовал NET как единственного автора concrete `DomainPolicyTCPExecutionOwner` в новых dataplane-файлах после literalIP-порции; NET также владеет original mapping/baseline/equivalence/retainer. Не создавать второй manager, отдельный journal или заменяющий DTO factory.

Shared inventory должен принимать только original registered consumer с actual COMMON borrowed receipt либо удерживаемым complete receipt. `syntheticBaselineReceiptRows` является преобразованием после аутентификации, не whitelist по имени `RZSB_*`. Full inventory и receipt/source bookends обязательны.

Receiver/retainer должен сохранять issued aliases в пределах 256 записей и удерживать restorative baseline после Stop/изменения исключений. Existing DNS reservation ledger не делает TTL/LRU reuse и не восстанавливает original source из JSON. Конечный bootstrap scope не является Commit ACK или активным listener lifetime. Нужны согласованная durable передача и отмена publication epoch; ни expiry, ни два conntrack dump сами по себе не разрешают cleanup.

## Проверки

Windows/amd64 Go 1.26.5; `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`.

| Проверка | Фактический результат |
|---|---|
| `go test ./internal/dataplane -run '^Test(SyntheticBaseline\|SyntheticExecution\|NetworkPolicyManagerSynthetic\|PolicyEffectCommandInvocation)' -count=1` | RC0, 3.025s после финального Start barrier |
| `go vet ./internal/dataplane ./internal/dnscontrol ./internal/startuptools` | RC0 после финального изменения |
| То же `go vet`, `GOOS=linux GOARCH=arm64` | RC0 после финального изменения |
| `GOOS=linux GOARCH=amd64 go test -c ./internal/dataplane` | RC0, финальная версия; не Linux runtime |
| `GOOS=linux GOARCH=arm64 go test -c ./internal/dataplane` | RC0, финальная версия; не Linux runtime |
| `go test ./internal/dataplane ./internal/dnscontrol ./internal/startuptools -count=1` | Выполняется отдельно; старт до финального четырёхстрочного Start barrier, не считать PASS до завершения |
| Race | Не проверен: текущий `go env CGO_ENABLED` = 0 |
| `git diff --cached --check` | RC0 для согласованной порции |

Первый адресный запуск остановился на отсутствующих CORE hooks. Первый linked test выявил ошибку test expectation: nil mapping даёт `ErrSyntheticBaselineTransition`, пустой mapping — DNS refusal; исправлено ожидание теста, production guards не ослаблялись. Новые тесты проверяют отсутствие регистрации/файлов/Start для missing/copied/tool-only source, closed scope и sticky unknown. Native положительный combined issuer/capture/receiver путь ими не доказан.

CORE явно разрешил включить его три finished файла (`network_policy_manager_resource_scope.go`, `network_policy_manager_synthetic_baseline_scope.go`, его `_test.go`) с четырьмя NET Go-файлами и этим handoff в один атомарный коммит. VM/native/router/shared ports/GitHub не запускались и не менялись; прежняя `.scratch` сохраняется, новые compile binaries остаются вне коммита.
