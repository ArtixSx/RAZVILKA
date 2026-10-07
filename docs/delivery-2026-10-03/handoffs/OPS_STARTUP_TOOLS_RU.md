# D07 — production startup xtables lease (OPS, readonly slice)

Дата: 2026-10-07. Base `dc1d72765da71da07ac8a88eedd04671a876bfe2`, новый изолированный package `internal/startuptools`. Existing main, netidentity, dataplane, NFQ lifecycle, DNS/DEFAULT не редактируются. OPS выровнял свою ветку с base; cherry-pick нужен только commit нового package/handoff, не merge commit.

## Callable contract

```go
lease, err := startuptools.AcquireUbuntuLegacy(serviceLifetime, provider)
// Либо explicit trusted stock startup code:
lease, err := startuptools.AcquireReviewedStockNC1812(serviceLifetime, provider)
tools, err := lease.InventoryTools() // dataplane.BackendInventoryTools
err = lease.Check(boundedReadContext, expectedNetworkIdentity)
err = lease.Close()
```

Factories выбирают **только** Ubuntu AMD64 `iptables-legacy 1.8.11` либо accepted NC-1812 ARM64 Entware `iptables 1.4.21`. `provider` — настоящий `NewProcProvider` для Ubuntu или `NewReviewedStockNC1812Provider` для stock. Factory сама свежо проверяет identity, затем связывает неизменяемый held review с тем же boot/network scope. Caller получает expected identity через тот же provider; mismatch отказывает. Provider zero value, другая kind/architecture, nil/cancelled original context не дают lease.

`serviceLifetime` — исходный долгоживущий startup/service context, не короткий setup context: cancellation отзывает descriptor. Acquisition внутренне ограничена 2s; каждая read/check операция также <=2s, deadline collector не меняется. `InventoryTools` выдаёт fixed aliases, digest полной связанной review, реальный callback `Lease.Check` и bounded retained runner. DTO/callback presence/hash alone не issuer. Success constructor не доказывает пустоту ruleset и не даёт operation/effect admission.

CORE использует `NewBackendInventory(provider, tools)` либо explicit stock `NewReviewedStockNC1812BackendInventory(provider, tools)`. При refusal factory/main должен оставить capability unavailable; не подставлять QA callback, другое имя CLI, пустую inventory или произвольный ExecRunner.

## Файлы, ELF и execution

- Main pins: Ubuntu `da62b7b5…8ac`; stock `966a3efa…acf`, полные значения в compiled profile. Stock backend/xtables/libiptext pins из `NFQWS_ENTWARE_REVIEW_INPUTS.json`; два exact reviewed libiptext variants учитывают packages 1.4.21-5/-6.
- Удерживаются реальные `O_NOFOLLOW|CLOEXEC` regular-file descriptors. Проверяются root UID, protected modes, inode/SameFile, content hash и оба alias resolution chains. Symlink traversal учитывает **все** intermediate targets и не нормализует `..` до их проверки. Временный writable ancestor не скрывается безопасным final target.
- Bounded ELF64 target/parser до allocation-driving metadata; file-backed extents, dynamic-linked string tables и search policy ограничены. NOBITS не читается как file data. Entry, DSO и loader роли отдельные: entry требует exact interpreter, DSO standalone `PT_INTERP` не разрешается/не загружается, loader не имеет собственного interpreter. Image cache не пропускает новую entry-role проверку.
- Рекурсивно удерживается DT_NEEDED closure в fixed protected roots с exact lookup precedence; ранее отсутствовавшие candidates остаются отсутствующими. Alternate CPU/TLS loader search directories не допускаются этим узким profile. RPATH/RUNPATH может совпасть только с prefix fixed library search order. Audit/filter/preload overrides не допускаются.
- Complete stable extension set проверяется в fixed `/usr/lib/x86_64-linux-gnu/xtables` либо `/opt/lib/iptables`, с recursive DSO dependencies. Stock path подтверждён [pinned Entware recipe](https://github.com/Entware/Entware/blob/969c703e6fd8b2ad84d82affaeb14b48d1fcb105/package/network/utils/iptables/Makefile): `--with-xtlibdir=/opt/lib/iptables`, bundled libiptext и libxt modules. Не выбирать extension root по отсутствию файла или environment.
- Child исполняет actual held main fd через `/proc/self/fd/3` + `ExtraFiles`; `argv[0]` остаётся exact iptables/ip6tables alias для multicall dispatch. Только compiled PATH/LD_LIBRARY_PATH/XTABLES_LIBDIR/locale; inherited environment не копируется. Constructor и Check проверяют точный backend `--version` обоих aliases. stdout/stderr bounded, nonempty stderr/overflow/timeout/error не выдаёт данные.
- Inventory runner допускает только `-t <canonical registered table name <=31> -S`, включая unknown registered tables. `Run` также readonly; `-A`, `-D`, shell/loader/extra argv отказывают. До и после каждого command проверяется held review и actual provider scope.
- Close отменяет текущие reads, ждёт их завершения, затем закрывает все fds; concurrent повторный Close тоже ждёт завершения первого. После Close/cancel любые сохранённые Check/Runner callbacks отказывают. System calls на локальных trusted paths не являются обещанием preemption зависшего kernel IO.

## Tests / Root native gate

Portable Windows tests проверяют ELF entry/DSO distinction, invalid/oversized metadata и linked-NOBITS allocations, cancel, bounded output/hash, zero/closed lease, original context, concurrent Close и readonly ABI. Linux-only filesystem regressions требуют UID0 и protected `/root` scratch; проверяют writable intermediate перед `..`, role promotion через cache, identical-byte replacement и новый dependency search occupant. Они не исполняют tools и не меняют deployment.

Native smoke — **настоящие production factories + public BackendInventory**, без fake Check/runner. Только test opt-in выбирает fixture; production constructors QA env не читают. Устанавливается inherited loader/environment poison, который не должен попасть в admitted child. Version probes проверяют actual heldFD/argv0 semantics; после закрытия descriptor collector не получает evidence.

Root, не OPS, запускает на соответствующем fixed deployment:

```sh
RAZVILKA_STARTUP_TOOLS_NATIVE=ubuntu-legacy \
  ./startuptools-linux-amd64.test -test.run '^TestProductionStartupToolsNative$' -test.v
RAZVILKA_STARTUP_TOOLS_NATIVE=stock-nc1812 \
  ./startuptools-linux-arm64.test -test.run '^TestProductionStartupToolsNative$' -test.v
```

OPS Windows `go test ./internal/startuptools`: PASS. Linux AMD64/ARM64 test cross-compilation: RC0; Linux AMD64 vet: RC0. Native execution не выполнялся OPS. Windows race недоступен: configured Go имеет CGO disabled, gcc/clang не найден; Root Linux race остаётся отдельной проверкой. Full backend/native/ordinary Apply не объявляется PASS по portable tests.

## Следующий отдельный slice: IP и effect admission

Readonly two-alias lease недостаточен ordinary LAN effects/RPDB/routes. Existing `nfqws2ExecRunner.Run` — raw `CombinedOutput`, не готовый admitted effect runner. Нужен отдельный protected IP entry review для fixed Ubuntu/stock deployment; actual alias/target/hash/version/interpreter должен дать Root своим tooling, OPS router/VM не трогает.

В readonly commit `ca8ccce` effect API не реализован и не выдан. Отдельное расширение после accepted Root/CORE contract и actual IP facts описано в [OPS_STARTUP_POLICY_TOOLS_RU.md](OPS_STARTUP_POLICY_TOOLS_RU.md). CORE `WithStart(ctx, frozen name/argv/digest, onceOnlyBegin)` под **существующим** exclusive lease свежо проверяет original operation/control/review и вызывает begin ровно один раз синхронно в actual start barrier, без повторного `Operations.Enter`. OPS begin проверяет held tools/network/lifetime и выполняет actual `Cmd.Start`; внешние callbacks нельзя вызывать под tool mutex. Presence callback/command DTO не grant. Readonly Check и constructor admission не вызывают.
