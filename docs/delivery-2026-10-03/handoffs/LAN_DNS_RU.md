# LAN/DNS D08 — checkpoint 04.10.2026

База worktree `sol/lan-dns-20261004`: `f1d0768170458cf07c9d45f17c1bc580e486e386`; по разрешению root выполнен normal fast-forward merge принятой integration `a3a7944467c5363d3313dbf0603f2ea0f7c72ce6`. VERSION0.19.3 и Go1.26.5 не изменены. VM/роутер/публичные аккаунты не использованы.

## Общий gate: API для CORE/DEFAULT/VLESS/NFQWS

`CompileLANPolicyRuntime(generation, []LANPolicyIngress)` возвращает detached `*LANPolicyRuntimePlan{Schema,Generation,Digest,Ingress}`. Каждый ingress: `SegmentID,Interface,Sources,ExcludedSources,ExcludedMACs`. Generation — полный digest общего reviewed compiler; payload должен войти в immutable Plan.LAN/Manager journal, а ScopeCheck обязан сверять реальные физические ingress/WAN/boot/control/scope bindings. Пустой Sources не означает any. ExcludedMACs канонические uppercase, до membership-проверки обеих семей, поэтому неизвестный новый IPv6 privacy address того же MAC не получает owned permission.

Marks `managed0x20000000`, `bypass0x08000000`, gate mask `0x28000000` — **предложенные owned координаты**, не утверждение, что firmware их освобождает. Preflight читает обе семьи, все raw/mangle/nat/filter tables, отказывается при пересечении mark masks, неизвестном CONNMARK, существующем RZG gate или старом owned table selector. Existing indexed service priorities невозможно безопасно перепрыгнуть с сохранением firmware100+; их надо отдельно вывести из эксплуатации до новой capability.

`LANPolicyMatch()` обязателен для всех owned исходящих DNS/proxy/NFQUEUE jumps; RPDB должен требовать ту же положительную маску и exact iif. Gate первым на physical mangle PREROUTING снимает старое permission только из gate mask0x28000000. MAC/source/outside устанавливают bypass, сохраняя остальные bits, включая0x10000000/0x01000000. RPDB53 `iif + bypass goto73` перепрыгивает owned60..72; anchor73nop продолжает firmware100+ без forced-main. Endpoint control pins50/51/52 остаются раньше.

`LANPolicyRuntimePlan.Effects()` выдаёт точные logical Tool/Add/Delete пары (ip/iptables/ip6tables), максимум4096; executable paths берутся из trusted startup. Сначала готовятся RPDB anchors/selectors обеих семей, затем все chain bodies, затем только публикуются ingress jumps. Cleanup — обратный порядок, **только по существующему common durable addition receipt**. Runtime не создаёт файлов/journal/worker/нового Manager. `LANPolicyRuntime.Activate` требует shared `Execute` callback; unknown/error не повторяется, владелец выполняет settlement/rollback. VLESS расширяет общий backend, CORE владеет Plan.LAN и Manager ordering.

`Preflight`, `Verify` и `InspectEffect` — реальные read-only команды через существующий Runner. Verify сверяет порядок тела, все references, отсутствие duplicates и gate jumps перед другими PREROUTING actions. InspectEffect реконструирует expected effects из sealed payload, возвращает count/foreign; persisted argv не даёт authority. Partial chain должен быть prefix expected; published jump требует полного тела. Для cleanup Inspector не требует текущего review/ScopeCheck, чтобы Stop/expiry не мешали точному удалению.

Return flows от owned TUN не получают physical ingress mark автоматически. Сохраняется отдельный exact TUN→LAN source/destination + ESTABLISHED,RELATED grant; incoming skb/connmark не объявляется доказанным. При применении нового device exclusion владелец обязан согласовать drain старых exact flow permissions; массовый conntrack flush запрещён. Этот checkpoint не выдаёт такую возможность за выполненную.

## Проверки и граница

Go1.26.5 Windows, GOMAXPROCS2, GOFLAGS-p=2: `go test ./internal/dataplane ./internal/dnscontrol -run 'TestLANPolicyRuntime|TestLANClassifier' -count=1`: RC0, dataplane0.113s; dnscontrol компиляция без выбранных tests. Новые тесты: detached review identity, invalid scope, MAC-before-membership обеих семей, owned-bit mask, ordered publication, exact readback/foreign refs/late gate/legacy selectors, cleanup after review revocation, mark collision до эффекта.

Предыдущий более широкий `TestScopedDNS` Windows sandbox прогон RC1: существующие TempDir atomicrename получили AccessDenied; dnscontrol0.584s RC0. Production atomic-write guard не ослаблен. Не считать полный dataplane/Linux/race/native/HIL пройденными.

D07/D08 не закрыты: shared receipt binding, Manager actual ordering/admission, consumers, precise flow drain и независимый namespace/router acceptance ещё требуются. `NETWORK_POLICY_EXECUTOR_REQUIRED` сохраняется.

## Исправления независимого review

Root/CORE обнаружили в первом checkpoint неправильный negative mask0x38000000: он очищал дополнительный бит, не проверявшийся collision scanner. Исправлен на0x28000000; regression сохраняет0x10000000 и WG0x01000000. Второй P1: decimal-only owned table detection мог пропустить alias. Все RPDB readback теперь запрашивают `-N` numeric output; unknown named aliases и неизвестные nonblank строки отклоняются. Если old ip не поддерживает числовое чтение, capability отказывается, alias не угадывается.

Verify повторно читает late foreign mark/CONNMARK collisions обеих семей/всех tables после effect ACK. Когда другие positive consumers уже присутствуют, обязателен ConsumerCheck их точных common receipts/generation. `BeforeDelete` удерживает anchor73 до исчезновения всех goto73 (включая foreign priority); chain deletion требует отсутствия всех contents/references. Scope/Stop не отменяет точную cleanup authority.

После исправлений `go test ./internal/dataplane ./internal/dnscontrol -run 'TestDomainPolicy|TestNetworkPolicyDNS|TestLANPolicyRuntime|TestLANClassifier' -count=1`: RC0, dataplane0.118s, dnscontrol0.597s. Domain/DNS новый WIP этим локальным запуском проверен, но пока не включён в mask/alias исправляющий commit. Linux amd64 CGO0 test compilation native fixture RC0; выполнение namespace fixture остаётся у root.
