# D07 — stock iproute2 4.4 numeric rule inspection

Дата: 2026-10-07. Parent `0213929b9c64b67e8452b5e8054c92cd55390ea1`, branch `sol/ops-20261003`. Scope — `internal/startuptools` и OPS handoffs; BackendInventory/netidentity budgets меняют их owners, не OPS.

Root130 подтвердил actual pinned `/opt/libexec/ip-full`: `-4/-6 -N rule show` возвращает RC255 (unsupported option), `-4/-6 rule show` RC0/stderr empty. Root133b binary artifact имеет compiled SHA `cce8d3fafdf0c1393878adb53e596c16788b37f8ecdd0d0ac25c4a751b0b7b88`; OPS проверил этот hash и embedded `/opt/etc/iproute2` paths локально, без исполнения. Root metadata: config directory root0:0, mode0755; group, rt_dsfield, rt_protos, rt_realms, rt_scopes, rt_tables, rt_tables.d и rt_protos.d отсутствуют.

[Pinned Entware recipe](https://github.com/Entware/Entware/blob/969c703e6fd8b2ad84d82affaeb14b48d1fcb105/package/network/utils/iproute2/Makefile) задаёт version4.4.0-release11 и `/opt/etc/iproute2` config root. [Upstream v4.4.0 name lookup](https://github.com/iproute2/iproute2/blob/v4.4.0/lib/rt_names.c) использует table DB и `.d`, DS field, realm и group mappings; [rule formatter](https://github.com/iproute2/iproute2/blob/v4.4.0/ip/iprule.c) помещает их в отдельные поля вывода. Adapter ограничен этими точными binary/profile facts.

Новый stock policy profile v2 требует protected config root и удерживает **отсутствие** всех восьми inputs. Existing held review проверяет negative paths до/после каждого read и до actual effect Start; new name DB или database directory отзывает review. Present custom config — явный отказ без удаления, переписывания или ambient normalization. Readonly xtables factories и Ubuntu actual `-N` execution не изменены.

Public read ABI остаётся `-4/-6 -N rule show`. Только compiled stock v2 исполняет actual held IP fd с `-4/-6 rule show`, затем адаптирует полный bounded вывод:

- `lookup/table local/main/default` → `255/254/253`;
- `suppress_ifgroup default` → `0`;
- `realms unknown` → `0` в соответствующей части пары;
- numeric fields сохраняются; canonical numeric tokens, bounds и known old formatter fields проверяются.

Замена происходит по **позиции поля**. Interface с именем `local` или `main`, addresses и marks не меняются. Неизвестные names/fields, malformed framing, detached/unresolved markers, ambiguous syntax, noncanonical/oversized numbers или output limits возвращают Unknown **без частичного вывода**. Никакие строки или foreign rows не отбрасываются. Custom table names не угадываются. Actual empty stdout EOF остаётся пустым наблюдением, а не искусственным fallback.

При held отсутствии name inputs numeric-string aliases не могут подменить numeric effect arguments в stock lookup/protocol/scope/group DB. Ubuntu naming inputs остаются отдельной review-задачей; наличие `-N` само по себе не доказывает независимость argv parser от name DB. OPS не объявляет этот аспект закрытым по stock fix.

Root132 также установил actual capture timeout: acquisition287ms, capture2000ms, contextDEADLINE, `INVENTORY_TOOLS_B / NET_IDENTITY_UNKNOWN / DEADLINE`. Root согласовал stock collector6s и aggregate Provider boundary16s (owner changes), с leaf <=2s и сохранением original shorter context. OPS `RunBounded` теперь принимает bounded более длинный parent и создаёт свой <=2s child; original cancellation/deadline сохраняется. Это конечный timing budget, не admission grant. Constructor, Check, each tool read и effect-start review по-прежнему capped2s. Native PASS не выводится из изменения budget.

Portable tests проверяют position-specific builtins, сохранение всех rows и других selectors, refusal custom/unknown/partial data, numeric/framing/row bounds, empty EOF и longer-parent/shorter-original leaf deadline. Linux-only protected filesystem regression проверяет отказ при появлении name DB после удержания отсутствия. OPS: Windows tests PASS; Linux AMD64/ARM64 cross-compilation RC0 и AMD64 vet RC0; native execution выполняет только Root.

Root повторяет actual `TestProductionStartupPolicyNative` и `TestProductionStartupToolsNative` с согласованными aggregate budgets; native диагностика сохраняет отдельные acquisition/capture/read timings, context state до cancellation и static error categories. Ordinary main Apply/effect writes не объявляются PASS по unit/cross-compilation.
