# LAN/DNS D08 — checkpoint 04.10.2026

База worktree `sol/lan-dns-20261004`: `f1d0768170458cf07c9d45f17c1bc580e486e386`; по разрешению root выполнен normal fast-forward merge принятой integration `a3a7944467c5363d3313dbf0603f2ea0f7c72ce6`. VERSION0.19.3 и Go1.26.5 не изменены. VM/роутер/публичные аккаунты не использованы.

## Общий gate: API для CORE/DEFAULT/VLESS/NFQWS

`CompileLANPolicyRuntime(generation, []LANPolicyIngress)` возвращает detached `*LANPolicyRuntimePlan{Schema,Generation,Digest,Ingress}`. Каждый ingress: `SegmentID,Interface,Sources,Membership,IncludedMACs,ExcludedSources,ExcludedMACs`. Generation — полный digest общего reviewed compiler; payload должен войти в immutable Plan.LAN/Manager journal, а ScopeCheck обязан сверять реальные физические ingress/WAN/boot/control/scope bindings. Пустой Sources не означает any. ExcludedMACs канонические uppercase, до membership-проверки обеих семей, поэтому неизвестный новый IPv6 privacy address того же MAC не получает owned permission.

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

## Positive MAC membership и cleanup dependencies

LANPolicyIngress дополнен IncludedMACs/Membership: `all` только для reviewed lan_except/inherit; `mac` требует непустой whitelist подтверждённых MAC. Positive mark устанавливается по физическому prefix **и MAC**, поэтому selected known device сохраняет default при новом privacy IPv6, а unknown device не наследует selection. Excluded MAC проверяется раньше positive whitelist. Компилятор нормализует пустой Membership из наличия IncludedMACs; sealed payload уже обязан иметь явный mode. BindIngress должен сравнить весь payload с DEFAULT immutable compilation, включая whitelist, а не принять режим из UI.

LANPolicyEffect дополнен Needs[] с earlier indexes: goto зависит от anchor своей семьи; каждый body rule — от предыдущего/chain declaration; каждый publish jump — от всех prepared RPDB и последних chain-body steps обеих семей. Bound4096 проверяется до fanout. Shared receipt adapter переносит эти зависимости без второго журнала.

BeforeDelete для **любого body rule** дополнительно требует отсутствие всех live references, даже exact-looking PREROUTING jump после acknowledgement его удаления. Такой новый reference не становится нашим effect. Protocol readback принимает реальное `proto 3` numeric spelling с bounded uint8; exact сравнение собственных tuple не ослаблено. Regression включает disjoint firmware proto, отсутствие body-delete permission при late identical attachment и empty whitelist refusal. Последний focused run RC0: dataplane0.086s, dnscontrol0.470s.

## Domain decisions до выбора outbound

Новый `CompileDomainPolicy` принимает detached concrete schema2 policy, физический scope и frozen service catalogue одного поколения. `Decide` сначала выполняет общий negative device/guest/address gate. Затем разрешает имя только от существующего движка для **этого соединения до outbound**: application, TLS SNI для TCP или QUIC SNI для UDP. DNS observations, неподтверждённый fake-IP, ECH outer name, late sniff и coalesced origins не дают domain authority. Этот API не реализует frontend/sniffer и не утверждает, что такой producer уже подключён.

Same-CDN неизвестное имя, literal IP, непрозрачный UDP и удалённый/source-mismatched override идут к явному default. Известное service name или отдельно reviewed IP/CIDR selector выбирает service. Mandatory domain-direct/RU/direct-service исключение при непрозрачном flow требует отказа до outbound: shared IP нельзя объявить domain-wide DIRECT. Явное IP/CIDR direct исключение действует независимо от непрозрачного имени и других domain rules. Service outbound error остаётся typed `failed`, без повторного default/direct. `Dispatch` использует guard существующего owner; самостоятельного listener/journal/scheduler нет. `DecideWithScope` разрешает обновлять только bounded freshness того же boot/network/revision/device/segment identity; изменение binding требует нового review generation.

## DNS wire composer на существующем NET listener

По точному разрешению root зависимости NET `5a1328526c9ebf025257d78156412c4dce56f6d1` и `5778aa4a1b5031aa44bb526c2fef941d196c7fdb` cherry-picked как `eed807d` и `639a04a`; NET-owned файлы вручную не редактированы. `NewNetworkPolicyDNSResolver` использует тот же Manager, strict HTTPS exchange, production profile identity и existing scoped answer cache/ledger. Доверенная identity default и service providers снимается одним snapshot; изменения при создании/разрешении/публикации отказывают. Второго DNS cache нет.

Owner предоставляет `NetworkPolicyDNSAuthority{Generation,ControlEpoch,BindingRevision}` и точное physical admission `Ingress,DeviceID,Kind`. Peer IP сокета сам по себе не доказывает MAC/ingress. Exact service question использует selected service DNS; valid NoMatch использует явно выбранный production default DNS, включая A/AAAA/TXT. Matched unsupported type/provider failure не становится NoMatch. Explicit baseline name decision допускается только через заранее reviewed loop-free baseline exchange; excluded device не делает baseline/upstream/cache запросов.

`Serve` переиспользует NET `ServeScopedDNS` и комбинированный `ScopedDNSHandler.Exchange`; `Publish` делает Resolve ровно один раз. `NetworkPolicyDNSPublisher(ctx, admission, send)` обязан удерживать короткий lease общего owner **через синхронную отправку**: durable Stop/generation, current physical binding и exact gate readback. Перед send wrapper ещё раз сравнивает admission/provider, проверяет context и вычитает весь publication residence из wire TTL. Вызов strict address-only `MatchClientQuery` к valid default TXT не производится: final service provider проверяется только для exact selected key. Firewalls/DNAT/INPUT/precise old-flow settlement остаются у общего Manager adapter и этим checkpoint не реализованы.

Оригинальные DNS question/ID/CD/RD/EDNS и RDATA сохраняются; wrong question/flags/ID/trailing layout отклоняются. HTTP Age, transport и final-owner residence уменьшают TTL, не возобновляют lease. Existing CNAME minimum ledger сохраняет terminal aliases и expiry; новые observation IDs различают client/domain/family/provider/CD/DO/generation и не меняются при переходе fresh→stale. Ledger — диагностика, не flow identity, IP route или fake-IP mapping.

## Namespace fixture и итоговые локальные проверки

Новый opt-in Linux `TestNativeLANPolicyMACGate` отказывается от mutations без `RAZVILKA_LAN_POLICY_NETNS=1` и начального namespace с **единственным lo**. Root запускает его в выделенном пустом netns; этот чат VM/роутер/netns не запускал. Fixture создаёт собственные bridge/veth/dummy interfaces, actual mangle gate и RPDB обеих семей. Отправляет реальные Ethernet UDP frames: selected MAC (включая IPv6 внутри prefix), excluded MAC с новым privacy IPv6 и unknown MAC вне whitelist. Owned selector61 получает только positive exact mark+iif; остальные продолжают foreign firmware-like100→table220. Cleanup fixture process-local acknowledgements **не заменяет production durable receipt**. VPN/DNS redirect/NFQWS/TCP/physical-HIL acceptance здесь не заявлены.

Go1.26.5, Windows, GOMAXPROCS2, GOFLAGS-p=2:

- Полный `go test ./internal/dataplane ./internal/dnscontrol -count=1`: RC0, dataplane78.775s, dnscontrol2.320s. Запуск вне Windows sandbox нужен существующим TempDir atomicrename и loopback sockets; production guards не ослаблены.
- После последних IP-direct/provider-snapshot изменений focused `TestDomainPolicy|TestNetworkPolicyDNS|TestLANPolicyRuntime|TestLANClassifier`: RC0, dataplane0.096s, dnscontrol0.939s. Включает реальные loopback UDP/TCP selected service A/default TXT и revoke внутри publication lease: ни одного ответного байта.
- `go vet ./internal/dataplane ./internal/dnscontrol`: RC0.
- Linux amd64 CGO0 dataplane test binary compilation с native fixture: RC0; это cross-compilation, **не native execution**.

`NETWORK_POLICY_EXECUTOR_REQUIRED` остаётся закрытым. Для готового D08 всё ещё нужны accepted frozen Plan.LAN/common receipt adapter, actual Manager first-activate/last-retire ordering и shared scope/control admission, exact domain producer/frontend, baseline equivalence, DNS ingress leases, precise owned flow drain и независимые mixed-consumer/native/HIL proofs. Ни boolean capability, ни diagnostic pass этих условий не заменяет.

## Review follow-up: IP-direct и known domain conflict

Координатор обнаружил P1 в `180b231`: ранний IP/CIDR MANUAL_DIRECT возвращался до извлечения имени потока и мог обойти допустимую в конфиге пару IP-direct + mandatory domain-bypass. Исправление всегда формирует full shared question (genuine name и service context), затем выполняет `DecideNetworkPolicy`; MANUAL_RULE_CONFLICT остаётся refused/unavailable, без outbound. При opaque/unknown имени explicit IP-direct сохраняется, если full shared decision действительно MANUAL_DIRECT. Добавлен regression known TLS SNI/conflict/Dispatch без outbound и opaque/known-miss IP-direct. Go1.26.5 `TestDomainPolicy*` RC0, dataplane0.079s; diffcheck RC0.
