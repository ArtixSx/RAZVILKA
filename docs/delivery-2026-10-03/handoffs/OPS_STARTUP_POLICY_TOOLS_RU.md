# D07 — held IP + xtables policy runner (OPS)

Дата: 2026-10-07. Отдельное расширение readonly startup lease `ca8ccce2a3aaa8147d7fced1be406117084031d3`, diagnostic parent `d24b8b9119ee52b71934431e41338edd375e130b`, branch `sol/ops-20261003`. Scope — только `internal/startuptools` и OPS handoff. Main, CORE admission implementation, dataplane, NFQ lifecycle, DNS/DEFAULT не редактируются.

## Callable API

```go
lease, err := startuptools.AcquireUbuntuLegacyPolicy(serviceLifetime, provider)
// Либо explicit accepted stock startup selector:
lease, err := startuptools.AcquireReviewedStockNC1812Policy(serviceLifetime, provider)
tools, runner, err := lease.PolicyRuntimeTools() // PolicyEffectTools, NFQWS2Runner
inventoryTools, err := lease.InventoryTools()  // Same retained policy review
ctx = startuptools.WithCommandAdmission(ctx, actualCOREAdmission)
// runner supplies actual process-start barrier, never an enqueue ACK.
err = lease.Close()
```

Existing readonly factories и `Lease.Run` остаются readonly: они не выдают policy runner. Policy factories дополнительно удерживают IP entry/alias/recursive ELF closure, используя тот же настоящий provider, protected roots и original service lifetime. Digest включает IP binding; empty IP field omitted, поэтому readonly review digest не меняется из-за расширения. DTO/alias/hash/наличие callback не создают admission.

```go
type CommandAdmission interface {
    WithStart(ctx context.Context, absoluteName string, copiedArgs []string,
        toolsReviewSHA256 string, begin func() error) error
}
```

CORE реализует этот interface из **original** operation/control/review и frozen typed plan под своим уже удерживаемым exclusive lease. Он сравнивает точные alias, argv, tools digest, свежо проверяет своё admission и вызывает `begin` ровно один раз синхронно. `Operations.Enter` повторно не вызывается. `WithCommandAdmission` только сохраняет этот owner в context, не конструирует права. В production нельзя заменить owner функцией, которая просто вызывает begin, или использовать QA callback.

Runner копирует argv до owner call; owner получает отдельную копию. Внешний owner вызывается без tool gate, так что может повторно выполнить `Lease.Check`. Lifetime reference удерживает fds до полного завершения команды; Close отменяет context и ждёт references и reads перед закрытием fds. Новые references после Close запрещены.

Caller OS thread locked через owner barrier, opening identity, actual `Cmd.Start`, closing identity. Begin от другого thread, повторный, не вызванный или сохранённый после owner return отказывает. Проглоченная ошибка Start, owner refusal/panic также Unknown. Если процесс уже стартовал перед последующим отказом, runner отменяет его и обязательно выполняет Wait; ACK не выдаётся.

До actual Start проверяются original context, service lifetime, held complete file review и freshly issued exact namespace identity. Provider closing check обязателен. Child исполняет held fd `/proc/self/fd/3`, fixed original alias в argv[0], compiled environment и bounded output. Эффект ограничен 25s; review/provider/start <=2s, shorter original deadline сохраняется. Внешний trusted callback должен соблюдать context: синхронный Go callback нельзя принудительно прервать.

Успешный actual Wait после корректного admission/start/closing identity — ACK фактического эффекта. Поздняя cancellation этот ACK не стирает: receipt owner записывает `added` и затем проверяет отмену. Ошибки Start/identity/owner/Wait, output overflow или nonempty stderr остаются Unknown, receipt intent не превращается в успех.

## Fixed IP facts и узкий ABI

Root read-only `IP121`/`IP121b` подтвердил:

| Profile | Alias → target | SHA256 | Exact version / interpreter |
|---|---|---|---|
| Ubuntu AMD64 | `/usr/sbin/ip` → `/usr/bin/ip` | `2829deca72cff655d6d1290646abb9cc829da2e2db615eec8bc0ccd283acf3a7` | `ip utility, iproute2-6.19.0, libbpf 1.6.3`; `/lib64/ld-linux-x86-64.so.2` |
| Stock NC-1812 ARM64 | `/opt/sbin/ip` → `/opt/libexec/ip-full` | `cce8d3fafdf0c1393878adb53e596c16788b37f8ecdd0d0ac25c4a751b0b7b88` | `ip utility, iproute2-ss4.4.0-11-entware`; `/opt/lib/ld-linux-aarch64.so.1` |

Version probe — exact `-Version`, stdout с одним newline, RC0/stderr empty. Ubuntu NEEDED: libselinux, libbpf, libelf, libmnl, libcap, libc; stock libgcc_s/libc. Recursive capture использует actual ELF metadata; список facts не заменяет held review. DSO standalone interpreter libc не становится entry requirement.

Без effect admission runner допускает только exact xtables `-t TABLE -S` и numeric IP `-4/-6 -N rule show`, каждое чтение <=2s и <=1MiB. Это покрывает текущий LAN gate readback. Route show/get, link/addr JSON и neigh пока **explicit capability refusal**; raw runner fallback не допускается.

Root130 выявил unsupported `-N` на actual stock 4.4.0. Отдельный [stock v2 held-absence adapter](OPS_STOCK_NUMERIC_RULES_RU.md) сохраняет public numeric ABI и связывает builtin normalization с protected absence name inputs; исходный b306 stock read был реальным refusal, не PASS. Longer bounded parent теперь допускается только с собственным leaf <=2s; aggregate budgets и их actual acceptance принадлежат owners/Root.

Admitted effect ABI: fixed two xtables aliases с `-t TABLE` и одним начальным `-A/-D/-I/-N/-X`, либо fixed IP alias с `-4/-6 rule add/del` или `route add/del/replace`. 128 args maximum, <=1024 bytes each, <=32KiB total до копирования, valid UTF-8 без NUL/newline. Batch/file restore, shell, flush/policy-wide ABI не выдаётся. Эти shape bounds не являются авторизацией: exact typed command подтверждает CORE owner.

## Checks / Root native gate

Portable tests проверяют сохранение original context и command, отдельную argv copy, missing/not-called/repeat/wrong-thread/late-async/swallowed-error/owner-refusal/panic/cancel, readonly-vs-policy lease scope, ABI bounds, actual typed dual-family/MAC LAN compiler commands и Close joining retained admission. Linux-only test дополнительно проверяет concurrent begin на другом настоящем kernel thread.

Root opt-in `TestProductionStartupPolicyNative` использует реальные Policy factories и retained IP execution для numeric RPDB reads. Inherited loader/env poison не попадает в child. Unadmitted create-chain shape обязан отказать **до Start**; fixture не вызывает допущенный mutation. После Close сохранённый runner отказывает. Actual effect admission/write/receipt проверяет только интегрированный CORE native owner fixture.

```sh
RAZVILKA_STARTUP_TOOLS_NATIVE=ubuntu-legacy ./startuptools-policy-linux-amd64.test \
  -test.run '^TestProductionStartupPolicyNative$' -test.v
RAZVILKA_STARTUP_TOOLS_NATIVE=stock-nc1812 ./startuptools-policy-linux-arm64.test \
  -test.run '^TestProductionStartupPolicyNative$' -test.v
```

Readonly predecessor: Root VM124 PASS (factory/public inventory/protected FS regressions); router124 FAIL `ACQUIRE/PATH_OWNER` за 0.25s. `d24b8b9` добавил только fixed path/reason diagnostics; Root router126 подтвердил `ACQUIRE/PATH_OWNER_OPT_ETC_UID`, `/opt/etc` имеет UID 1001. Это точный protected preload-parent refusal. OPS policy не ослаблял и ownership не менял; проверка наличия preload, возможное точечное восстановление metadata с undo и повторный native gate принадлежат Root. Package/bootstrap должен ясно сообщать об этом prerequisite перед install; скрытый recursive chown `/opt` не допускается. Policy native, actual admitted effects и ordinary main Apply остаются отдельными gates; portable checks не объявляют их PASS.

OPS validation: Windows `go test ./internal/startuptools` PASS; Linux AMD64/ARM64 test cross-compilation RC0, Linux AMD64 vet RC0, staged diff check clean. OPS native execution не выполнял. Windows race unavailable при текущем CGO/toolchain; Root Linux race — отдельная проверка.
