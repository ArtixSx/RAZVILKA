# WG и AWG prerequisites для подключения App

NET → Root и CORE, 11.10.2026. Проверенный исходный commit NET: `4501ed5698e76adb513e57dfa18a4fe0f84eb8bf`. Durable WG receipt wiring уже присутствует; оставшиеся ограничения находятся в App admission, подключении исходных владельцев и native acceptance. Список является единственным положительным охватом, исключения имеют приоритет, `allLAN` определяет клиентов. Старый fixture с LAN defaults не подтверждает этот продуктовый контракт.

## AWG admission в App

`internal/app/amneziawg.go:60,101,118,159` использует `awgprofile.Check` для status, preview, import blockers и canary admission. Это проверка отображаемых версий. Runtime gate `CheckRuntime` дополнительно требует raw CLI hash, loaded module version/srcversion/initstate, modinfo и kernel ABI/taint. Та же последовательность `Check` сохраняется в прочитанном CORE checkout; исправление принадлежит CORE.

Воспроизводимый пример использует ровно исходный capability fixture из `internal/app/amneziawg_test.go:41`. Профиль требует AWG 3.1:

```go
p := awgprofile.Preview{MinimumMajor: 3, MinimumMinor: 1}
c := awgprofile.Capabilities{
    Backend: "kernel", ToolPath: "/test/awg",
    ToolVersion: "awg v3.1.20260812",
    LoadedModuleVersion: "3.1.20260906",
    ModuleLoaded: true, SupportsAWG31: true,
}
fmt.Printf("App fixture version-only blockers=%d\n", len(awgprofile.Check(p, c)))
for _, issue := range awgprofile.CheckRuntime(p, c) {
    fmt.Println(issue.Code)
}
```

Выполненный локальный `go run` дал:

```text
App fixture version-only blockers=0
AWG_TOOL_IDENTITY_UNVERIFIED
AWG_MODULE_IDENTITY_UNVERIFIED
AWG_KERNEL_ABI_UNVERIFIED
```

CORE следует заменить четыре App вызова на `CheckRuntime` и обновить положительные fixtures полными raw facts. Хранение unsupported draft остаётся допустимым. Отрицательные fixtures должны проверять blockers и отказ до вызова canary adapter. Настоящий `WARPWireGuardAdapter.advancedAWGTool` уже выполняет `CheckRuntime` и `VerifyTool` перед эффектами: найденный разрыв означает преждевременный App admission, а не доказанный обход adapter gate.

## WG source и рабочий consumer

`App.ReviewWGListRuntimeSource` удерживает реальные App, Store, catalog, profile, physical scope и startup tools, но возвращает только capture для сравнения. `listWGOperationBinding` удерживает исходный control/cleanup/material. Поиск production callers обоих constructors в NET и CORE checkout дал только их определения; вызовы находятся в tests. Поэтому наличие этих типов не подтверждает обычный App Plan/Apply/Status/Stop.

Повторяемый поиск из checkout:

```powershell
rg -n 'ReviewWGListRuntimeSource|reviewListWGOperation' internal/app -g '*.go' -g '!**/*_test.go'
```

Следующий App consumer должен удержать эти исходные владельцы через реальный Manager lifecycle, общий scope, publication и compensation. Положительный compiled service match обязан сохранять активный список и исключения. Existing `TestWGNativeNetworkReceipt` собирает исторические `0.0.0.0/0` и `::/0` default routes и специально оговаривает, что production Manager ordering не доказан. Его результат не является list-mode acceptance.

## Что уже закрыто в WG rollback

`334a62ad` подключил durable policy generations к WG lifecycle; `ef2d7b5a` связал restoration до publication и добавил возобновление acknowledgements. В текущем `Rollback` staged policy не даёт cleanup authority. До `wg-activation-started` cleanup не начинается, после начала используется конкретный WG policy reference. EEXIST и неизвестный command result не присваивают чужой tuple.

Адресные текущие regressions проверяют настоящий Manager late EEXIST для IPv4/IPv6, неизвестный selector, свежий AWG admission failure без cleanup authority, retained receipt после удаления transaction, publication cuts, stale rollback/Activate, restoration и recovery. Это отменяет прежний пункт D06 о ещё не подключённом receipt; native и router acceptance остаются отдельными.

## Проверка в Windows

Go 1.26.5, `GOMAXPROCS=2`, `GOFLAGS=-p=2`:

```powershell
go test ./internal/awgprofile ./internal/startuptools ./internal/dataplane -run '^(TestAWG|TestWGPolicyReceipt|TestWGStock|TestWGNetworkCommandOwner|TestWGNetwork.*Collision)' -count=1 -timeout=3m
```

RC0: awgprofile 0.363s, startuptools 0.361s, dataplane 18.609s. Проверены AWG raw facts и изменения inventory/tool, durable receipt lifecycle, исходный command owner с actual Start/Wait и cleanup, stock numeric admission и collisions. Kernel fixtures имеют Linux build tags и в этой Windows проверке не исполняются. VM, router, module loading и namespaces принадлежат Root.

```powershell
go test ./internal/app -run '^(TestListWGSource|TestListScopeWGOperationBinding|TestAWGCanaryFences|TestAWGUnsupportedCanBeSaved)' -count=1 -timeout=2m
```

RC0, App 4.886s. Текущие source/binding comparison, revocation/cleanup и canary guard fixtures проходят. Положительный AWG fixture с неполными raw facts демонстрирует прежний version-only контракт; этот PASS не доказывает исправленный runtime admission.

## Блокер доменного Xray consumer

VLESS подтвердил: нынешний `XraySelectedTCPExecutionResource` закрыт на literal dokodemo-door TCP/443. `XrayOperationMaterial.BindExecution` принимает только `LANPolicyXraySelectedTCPMode`; перенос его material/config в fixed SOCKS не разрешён. Existing `WithDomainPolicyTCPXray` вызывает generic `Processes.Start/Stop` и не является мостом к исходному sole-child owner.

VLESS должен предоставить закрытый domain factory с полным immutable config, исходной reservation дочернего процесса, единственным Wait и retained cleanup. После этого NET собирает concrete `DomainPolicyTCPExecutionOwner` с настоящим capture и mapping. CORE удерживает synthetic registrar и Manager Commit receiver; существующий baseline issuer `9bd6d7fc` пока закрывает только planned/prepared/capture-ready source phases. Точный блокер передан Root, CORE и VLESS; callback или literal resource не заменяет отсутствующее разрешение.
