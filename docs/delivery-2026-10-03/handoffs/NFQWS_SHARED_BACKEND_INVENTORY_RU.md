# Общий read-only backend reader — source slice, 07.10.2026

Finished private reader/contract для ROOT поручения по RESEARCH `2696c70` и ABI NFQWS `25fc6e4`. База source `75221cf`; отдельная test-only поправка strategylab `39414a490a015c673dd056d690e35177443a8ec5` уже передана ROOT. Она исправляет три logical probe fixtures через existing ResourceInspector seam, production load/RAM guard не меняет.

**Это завершённая ограниченная библиотечная порция, не полный LAN namespace proof и не production provider.** Shared файлы принадлежат NFQWS; LAN не создаёт второй NFT decoder. Reader не подключён к main/capability/Manager assembly. Existing NFQWS other-backend guard не ослаблен до missing nft/EINVAL→empty. Router/VM/modules/packages не менялись; native/race/live здесь не запускались.

## Согласованный private API

LAN подтвердил форму и владение в finished handoff pins `ae1da16` и `3995d33`:

```go
backendInventoryReader.Read(ctx, backendInventoryScope{
    BootID, NetNamespace, ToolReviewID,
}) (backendInventorySnapshot, error)
```

Reader хранит existing admitted `NFQWS2Runner`, fixed `IPTables`/`IP6Tables` paths и mandatory `CheckTools(ctx, scope)`. Дополнительно Runner обязан реализовать private `backendInventoryBoundedRunner.RunBounded(ctx, path, remainingBytes, args...)`; неподдержанный runner отказывает до NFT/CLI reads, fallback к unbounded Run отсутствует. `nfqws2ExecRunner` получил дополнительный fixed read method только в shared файле; его старый Run не менялся. Новый метод принимает только absolute executable и fixed `-t {raw,mangle,nat,filter,security} -S`, не mutating argv. stdout+stderr имеют общий лимит **до** расширения capture buffer; overflow отменяет subprocess сразу. CommandContext останавливает direct child, Run выполняет Wait; WaitDelay100ms ограничивает drain у неожиданно унаследованного pipe. Это read CLI, не NFQWS supervision receipt/ECHILD proof.

CheckTools — обязанность уже существующего protected tool-review holder: тот же held review ID, exact aliases/paths, backend identity обеих семей, loader, extensions, environment, ancestor immutability. Строка ID, hash executable или version suffix сами не являются таким доказательством. Nil checker отказывает; model nil-return checker не является runtime acceptance. Reader не создаёт tool-review authority, execution token, journal или network owner. Frozen copy descriptor используется для одного read.

Result detached: scope, exact tool paths, explicit coverage, NFT classification/full generation/tables и classic rows `{Family, Table, Tokens}`. Error всегда возвращает **нулевой snapshot с NFT Unknown**, без частичных rows/coverage. Даже успешный read не является reusable grant; хранить его через следующий effect/Stop/control/network/module change нельзя.

## Реализованный порядок и границы

1. Original ctx сохраняет cancellation/shorter deadline; derived timeout2s. Fresh protected tool check + boot/process/thread netns sample. System Read фиксирует inherited OS thread, не вызывает setns.
2. Один AF_NETLINK NETLINK_NETFILTER12 SOCK_RAW/CLOEXEC/NONBLOCK socket, groups0, assigned port, random nonzero sequences. Только fixed20-byte UNSPEC GETGEN A → GETTABLE whole dump.
3. Обе classic families; raw, mangle, nat, filter, **security**. Никакой four-table reduction или custom table inference.
4. GETGEN B после **всего** classic batch; A==B. Explicit Close и fresh tool/endpoint checks. Ошибка Close/cancel/stale endpoint оставляет Unknown.

NFT aggregate: ≤3 requests, ≤256KiB received, ≤64 datagrams, ≤1024 frames, ≤64KiB/datagram. Classic aggregate: ≤1MiB stdout+stderr, ≤8192 input rows (пустые строки тоже занимают budget), ≤65536 tokens; ≤16KiB/line, ≤128 tokens/line. Bounded capture проверяет size до allocation; lexical/row collectors проверяют aggregate до split/collection.

Linux decoder следует закрытому reviewed upstream4.9 ABI из `25fc6e4`: kernel sockaddr sender PID0/groups0, header nlmsg_pid **assigned destination port**, exact sequence/type/flags/payload, bounded framing/alignment, zero padding, no unknown/duplicate/nested attrs. nfgen version0 и generation low16 res_id проверяются; full NFTA_GEN_ID — BE32. Tables требуют NAME/FLAGS/USE, known family inet/ip/arp/netdev/bridge/ip6. Known integer attrs разрешают NLA_F_NET_BYTEORDER; string flags отказывают. Generation требует exact success ACK (header echo); successful table dump требует DONE status0 без extra ACK, как4.9. Negative NLMSG_ERROR получает diagnostic errno лишь при exact header+nfgen request echo; EINVAL/EOPNOTSUPP/permission/error **никогда** не дают unsupported/empty. Positive/out-of-range errno, interrupted/filtered dumps, overrun, truncation, unknown attrs/flags, duplicate terminal и incomplete read отказывают. После decoder error состояние sealed failed, partial tables не сохраняются.

**Любая NFT table, включая dormant и чужую family, даёт Present; empty разрешён только после полного zero-table dump + обеих ACKed generation samples.** Reader не разбирает expressions/chains в NFT и не выдаёт compatibility grant существующим NFT objects. ABI расширения, включая неизвестные newer attrs/ACK flags, дают Unknown; автоматического permissive modern-kernel fallback нет.

Контекст ограничивает userspace poll/receive и CLI. NONBLOCK не прерывает synchronous kernel GET handler/request_module; hard wall-clock bound для зависшего kernel syscall здесь не доказан. GET может вызвать kernel autoload. Никакого explicit modprobe, mutation/empty-batch probe или заявления absolute no-autoload не добавлено.

## Общий parser и consumer граница

`backendXTablesTokens` — выделенный existing NFQWS quote-aware tokenizer, без shell expansion. Old `nfqwsScopedTokens` сохранён wrapper с прежним own error. `backendXTablesRowTokens` — одна shared structural validation -A/-N/-P/chain; old NFQWS readRules использует её. Shared parser дополнительно отказывает control chars внутри quotes/escapes. Старый NFQWS collector сохраняет своё existing observation/receipt поведение; новый combined reader требует nonempty newline-terminated CLI output. Общий semantic normalizer не вводился: NFQWS exact rule vocabulary и LAN predicates остаются раздельными. Unknown extension остаётся raw foreign data; quoted comment с literal NFQUEUE/--mark остаётся одним inert token.

Coverage в этом source всегда `LegacyFixedFiveBothFamilies=true`, `NativeNFTAllFamilies=true` только после complete successful read, **RegisteredTablesComplete=false**. Pure `requireLANBackendCoverage()` отказывает для такого snapshot, в том числе при NFT Empty. Это обязательный gate для будущего LAN adapter, а не готовый NamespaceCheck. Existing retained=nil/retained-gate authority остаётся у LAN/Manager; reader не вызывает Manager.Verify, LAN.Verify, NFQWS.CheckKnownReferences либо callbacks, возвращающиеся в него.

## Проверки этой порции

- Windows ordinary Go tests: full `internal/dataplane` и `internal/strategylab` PASS. После последнего parser/overflow уточнения — fresh targeted Backend/NFQWSScoped PASS.
- Targeted malformed/truncated wire fixtures: every strict prefix of complete gen/dump; wrong sender/port/sequence; generation/ACK/DONE; padding/endian/duplicate/unknown NLA; interrupted/filtered/overrun; sealed EINVAL; all six foreign NFT families. Aggregate byte/datagram/frame/request, classic byte/row/token и output allocation/overflow tests PASS.
- Combined model: generation вокруг всех ten classic reads, security IPv6/unknown extension + quoted comment, foreign/dormant NFT, changed generation/boot/netns/tool review/cancel/Close, nil/unbounded runner/no partial proof, detached rows/tables и explicit full-LAN refusal PASS.
- Windows/Linux amd64 vet; Linux amd64+arm64 test cross-compilation PASS. Это compilation/model evidence, не actual NFT kernel acceptance.
- Output overflow проверен на bounded writer/cancellation callback model; actual CLI overflow/cancel/pipe-drain acceptance ещё не выполнен. Source RunBounded выполняет command.Run/Wait, но writer fixture нельзя объявлять native subtree/quiescence proof.
- Отдельная strategylab test correction: три named fixtures + existing sustained-load/low-memory refusal, count10 Windows PASS; Linux amd64 cross-compile PASS.

## Реальный остаток для ROOT / LAN / CORE

1. ROOT review этого pin и actual kernel wire fixtures на accepted platform; особенно 4.9 vendor ACK/DONE framing и cooperative GET deadline/autoload limit. Native/router acceptance отсутствует в этом source slice.
2. Полный protected tool/dependency/environment/ancestor review на router. Уже известный writable `/opt` ancestor не превращается в trust через root-owned descendants; никакого recursive chown здесь нет.
3. Arbitrary registered classic tables: exact reviewed `/proc/net/ip_tables_names` / `ip6_tables_names` semantics, bounded both-family names before/after и custom table read/refusal; other required hook/backend sources. Fixed-five snapshot не закрывает это. LAN NamespaceCheck остаётся отказом, пока coverage недоказано.
4. Exact firmware/build positive unsupported proof пока отсутствует. Missing nft executable, sysmodule/files/config либо raw GET EINVAL не являются substitute; обе consumer стороны сохраняют Unknown/fence.
5. LAN подключает свои pure exact retained/no-consumer predicates через existing mandatory NamespaceCheck после review, без decoder copy и без recursion. NFQWS AdditionalReadback integration и duplicate classic read elimination — отдельная согласованная consumer порция. Snapshot нельзя подставить к текущему old callback так, чтобы независимый classic batch оказался за пределами NFT generation bracket.
6. Existing queue/process/listener/RPDB/routes/flow settlement, common receipt/Execution generation и actual Add/Delete guards по-прежнему обязательны. This inventory не доказывает их, не выдаёт cleanup/adoption permission и не разрешает last LAN gate removal.
