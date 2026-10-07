# Полный typed backend inventory — 07.10.2026

Finished collector/decoder slice на accepted integration `1a3fdd26f948f4dd55331c42d44a621d1f45dbd6`, branch `sol/nfqws-backend-inventory-20261007`. Только `internal/dataplane/network_backend_inventory*.go` и этот handoff. Main, receipts/journal, NFQ Spec/adapter/readiness, NET/LAN и netidentity не меняются. ROOT отдельно принял exact stock NFNETLINK/NFT ABI после RESEARCH pinned-source review; native acceptance и production consumers ещё отдельные шаги.

## Callable contract

```go
NewBackendInventory(provider *netidentity.Provider, tools BackendInventoryTools) (*BackendInventory, error)
NewReviewedStockNC1812BackendInventory(provider *netidentity.Provider, tools BackendInventoryTools) (*BackendInventory, error)
collector.Read(ctx context.Context, expected netidentity.Identity) (BackendInventorySnapshot, error)
snapshot.RequireComplete() error
```

`BackendInventoryTools` содержит `Runner NFQWS2Runner`, absolute distinct `IPTables/IP6Tables`, `ReviewSHA256` и mandatory `Check(context.Context, netidentity.Identity) error`. Runner дополнительно обязан иметь `RunBounded(ctx, path, limit, args...)`; fallback к unbounded Run отсутствует. Check должен проверить held admitted tool descriptor, реальные aliases/legacy backend, loader/extensions/environment и пути. Constructor freezes descriptor fields/callback, **не приобретает tool lease**: consumer удерживает свой admitted descriptor на протяжении каждого Read. Review hash сам по себе не proof. Никакого нового production trust issuer в этом slice нет.

Оба Check получают тот же bounded operation context и полную typed identity, равную expected/current. Original caller deadline/cancellation/values сохраняются: reader выводит только 2s child context; provider.WithCurrent выводит свой child в этом же бюджете. Второй Check расположен между двумя classic images, до последнего полного чтения, поэтому callback не может незаметно изменить возвращаемые classic rules. Collector не вызывает consumer Verify/authority callbacks.

`Read` всегда выполняется внутри concrete `netidentity.Provider.WithCurrent`: actual locked thread, fresh opening/closing identity, полное `==`. DTO/retained expected — только binding. nil provider/context/check, unsupported ABI, mismatch/closing/cancel дают zero snapshot + `ErrBackendInventoryUnknown`. Stock factory — explicit trusted startup NF ABI selection, не verification при construction: каждый Read требует fresh `ReviewedSingleInitNet`, inode0 и exact compiled namespace profile SHA `f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733`. Generic factory выбирает закрытую known Linux7 wire schema; errno не меняет выбранный ABI.

`BackendInventorySnapshot` имеет Schema1, `Scope.Network netidentity.Identity` + ToolReviewID, exact tool paths, detached `Rows{Family,Table,Tokens}`, NFTState/NFTGeneration/NFTTables и coverage. Tokens сохраняют opaque extensions и quoted comments; они не нормализуются как ownership. Экспортированы aliases `BackendInventoryRow`, `BackendInventoryCoverage`, `BackendNFTTable`, `BackendNFTState` и states Unknown/Empty/Present/NoRegisteredSubsystemAtCapture.

`RequireComplete` требует Schema1/valid scope/review, stable registered classic coverage обеих семей, complete native coverage и Empty либо exact stock NoRegisteredSubsystemAtCapture. Любая NFT table, mixed DTO или partial/unknown отказывают. **Это только coverage/absence predicate**, не effect permission: consumer выполняет свои pure owned-prefix/all-reference predicates по ВСЕМ Rows, writer/ownership/resources/process guards и fresh operation boundaries. DTO/RequireComplete не заменяют actual fresh Read и не сохраняются как grant.

## Полное classic чтение

На удерживаемом thread открываются anchored `/proc/PID/task/TID/net/ip_tables_names` и `ip6_tables_names`: O_NOFOLLOW walk, procfs root inode/type, same dev/fsid/mount ID через anchored fdinfo, PID/TID и closing descriptor checks, bounded complete EOF, checked close. Global `/proc/net` или namespace string fallback отсутствуют. Missing/unreadable/overmounted/invalid names — Unknown; успешный empty EOF — известный пустой зарегистрированный список.

Для каждого семейства читаются **все** уникальные зарегистрированные table names, включая custom/vendor names. Два полных batch `-t name -S`; каждый batch имеет before/after registered-name closure, затем сравниваются обе family sets и byte-exact table images. Fixed-five больше не является источником coverage. Не требуется наличие raw/security или запуск незарегистрированной таблицы. Standard [upstream x_tables registry/proc enumeration](https://github.com/torvalds/linux/blob/v7.0/net/netfilter/x_tables.c) перечисляет per-net registered tables под family mutex; vendor NF source contract принят отдельно.

Caps: names 4096 bytes/64 tables на family, safe ASCII names до31 bytes; общий двухпроходный CLI output 1MiB/8192 rows/65536 tokens; прежние row/token limits и newline completeness. Непредставимые/слишком большие корректные deployments отказываются, никогда не считаются пустыми. Exec bounded seam разрешает safe registered names, fixed readonly argv и fixed environment `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, LANG/LC_ALL=C; inherited loader/xtables overrides отсутствуют. WaitDelay остаётся100ms.

Stable double sampling не доказывает atomic snapshot против произвольного внешнего writer/registration ABA; consumer сохраняет принятые writer assumptions и held boundary. Эти ограничения не снимаются typed identity или coverage=true.

## Закрытые NFT ABI и sole-negative proof

Original diagnostic decoder остаётся closed49; accepted old modern-shape refusal tests продолжают PASS. Inventory явно выбирает closed Linux7 либо exact NC1812/vendorkernel `7b6c9477d429217042117fbfa3d2e9894a087607`. Linux7 normal [GEN/table output](https://github.com/torvalds/linux/blob/v7.0/net/netfilter/nf_tables_api.c) поддерживает exact GEN_ID/PROC_PID/PROC_NAME, CAPPED success ACK, table HANDLE/PAD/USERDATA/OWNER, known flag bits включая orphan PERSIST. Unknown extensions, flags, families, malformed shapes, inconsistent generation, interrupted/filtered dumps и unsolicited replies остаются Unknown.

Normal path: свежий socket, complete ACKed GETGEN A → all-family GETTABLE dump → classic capture → complete GETGEN B, equal generation, checked Close, provider closing. NFT presence любой family/dormant/owner table сохраняется Present и не проходит absence gate.

Stock negative path — отдельный decoder result, **не errors.As(Code22)**. Canonical единственный20-byte UNSPEC GETGEN REQUEST|ACK, fresh socket/seq/assigned port, authentic kernel sender/groups0, exact full request echo, flags0, errno−22. Только первый request/socket, первый и единственный frame/datagram; success GEN/ACK, mixed/trailing/junk, mismatched echo/seq/port, multicast/truncation, другой errno/request/ABI отказывают. После terminal candidate свежий nonblocking receive обязан сообщить empty queue; любой queued datagram или I/O error seals Unknown. До этого `finish/registration` не дают negative proof. Перед Send также проверяется пустая очередь; failed socket не переиспользуется.

После первого negative socket закрывается. После classic capture выполняется второй GETGEN на **другом fresh socket**, затем checked Close; оба результата должны совпасть. Это `BackendNFTNoRegisteredSubsystemAtCapture`, не CONFIG_NF_TABLES=n, permanent unsupported или future absence. Две отрицательные пробы не исключают registration ABA. Синхронный exact vendor GETGEN/ACK reply path — часть отдельно принятого [research contract](RESEARCH_NETCRAZE_EXACT_GETGEN_ABSENCE_RU.md), не свойство произвольного kernel. GET может вызвать autoload; userspace2s не является hard kernel preemption/settlement proof.

## Проверки и handoff

Windows amd64 все `TestBackend*` PASS0.090s; Windows package vet PASS; Linux amd64/arm64 package vet и full test binary cross-compile PASS. Адресные проверки: custom/empty registered families, four name closures и two images, drift/callback mutation/cancel/closing failure, typed stock selection/mixed states, modern known families/flags/metadata, old ABI refusal, sole negative before/after drain и24 ambiguous counterexamples, schema gate и caps. Production checks не исполняли Linux/native/race/VM/router/netlink.

Для ROOT full actual collector будет отдельный QA-only commit с opt-in `TestBackendInventoryFullNativeObservation`, concrete providers, реальным bounded runner и явным ROOT fixed-tool deployment fixture. Старый `RAZVILKA_BACKEND_NFT_OBSERVE_NATIVE` остаётся diagnostic-only. До ROOT source/native acceptance finished production library не означает main wiring или platform PASS. Active lifetime/typed NFQ Spec — последующий отдельный owner slice.

Follow-up compatibility checkpoint: fixed production Exec environment intentionally does not forward the old native CLI fixture's role markers. IO/deadline/Wait implementation выделен в один shared bounded body с explicit env; production RunBounded всегда передаёт прежний fixed safe env, старый test-only CLI worker передаёт свой dedicated role env этому же body. Caps/argv/output/Wait bounds не изменены, native markers не проходят в production environment. Actual full collector fixture вызывает именно production RunBounded с реальными reviewed CLI.
