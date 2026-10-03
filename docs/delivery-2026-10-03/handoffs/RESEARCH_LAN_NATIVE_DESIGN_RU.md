# D07/D08: малый native путь на существующих контрактах — 04.10.2026

Запрос координатора после принятия research `1f5675e` в `d010e13`: конкретный normal path для domain overrides/excluded sites на shared CDN, excluded MAC перед всеми owned RPDB/engines/DNS, privacy IPv6 и no DNS-IP flow identity. Только дизайн и чтение кода; production, чужой WIP, VM/роутер, зависимости и VERSION не изменены. Native/HIL не запускались.

База runtime-разбора — `delivery-review` commit `d010e13d6a55ed19ed21bf8f7a9475cbefc00921`; пока шло чтение, интеграция продвинулась до `f1d0768`, изменения в исследованных dataplane runtime files не установлены. DEFAULT `sol-default` HEAD `e0e83db` с новым незакоммиченным `default_route_executor*.go`; CORE ingress/iif и authority/CAS — активный WIP, не принятие. Ссылки ниже ведут в текущие рабочие деревья; baseline SHA и границы WIP обязательны при переносе.

## 1. Что можно реализовать первым

Две небольшие порции внутри **существующего Manager.Apply / Adapter lifecycle / execution journal**, а не новый control plane:

1. **Native device admission + IP-only default:** реальные MAC/CIDR отрицательные gates BOTH IPv4/IPv6, exact ingress/iif и normal default/override IP rectangles существующего DEFAULT compiler. Baseline DNS остаётся самостоятельным путём. Это даёт выполняемый all-except для поддержанных IP policy, в том числе без выбранных сервисов.
2. **Named TCP connection path:** один подтверждённый LAN ingress, один exact IPv4 client/MAC, TCP80/443 с visible TLS SNI/HTTP1 Host; scoped owned TCP listener получает исходный tuple, держит bounded начало и выбирает existing loopback SOCKS либо подтверждённый baseline socket до upstream Dial. Это первая реальная domain capability, затем её можно расширять по протоколам/сегментам.

Общий guard снимается только для фактически принятой capability и полного scope/protocol покрытия конкретного запроса. Нет причины объявлять D07/D08 навсегда UNSUPPORTED; нет основания объявлять весь D08 закрытым первым TCP slice.

## 2. Existing code: что переиспользовать, где пробел

| Код | Реальная опора | Чего ещё нет |
|---|---|---|
| [autonomy/network_policy.go](C:/Projects/RAZVILKA/delivery-review/internal/autonomy/network_policy.go:73) | Fresh MAC/segment/scope; unresolved negative identity закрывает соответствующий segment; `DecideNetworkPolicy` уже задаёт excluded-device → direct → override/RU → default и scope mismatch → default | Runtime producer доверенных flow metadata и native admission |
| [DEFAULT compiler](C:/Projects/RAZVILKA/worktrees/sol-default/internal/app/default_route_executor_compile.go:69) | Immutable `Ingress()` с Sources/ExcludedSources/ExcludedMACs, guest opt-in, disjoint IP rectangles, profile/control/scope digest | IP-only; domain policy/RU/scoped DNS пока отвергаются. Reference `Classify` не устанавливает rules |
| [DEFAULT executor](C:/Projects/RAZVILKA/worktrees/sol-default/internal/app/default_route_executor.go:20) | Observe → BindIngress → existing Build/Apply → CORE CAS/rollback; declared FlowBridge = тот же Adapter | Dependencies требуют настоящих shared owners; interim binder не допускает произвольного изменения input |
| [lan_classifier.go](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/lan_classifier.go:111) | Pure tuple generation и exact ordered readback | Нет live adapter/caller; MAC RETURN лишь отменяет default mark, не service RPDB/NFQ/DNS. Table0 вообще отвергает MAC |
| [policy coordinates](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/policy.go:34) | Shared layout2 service60–71, default72; endpoints50–52; existing exact receipt | Legacy layout0 остаётся на18100+ и далее; current parser/receipt не поддерживает новые mark/goto/nop/firewall resources |
| [scoped DNS](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/scoped_dns_plan.go:19) | Один exact IPv4 client/service/profile, UDP/TCP53 к gateway, owned socket/DNAT/health/rollback | Нет общей MAC admission или LAN IPv6 DNS transport; AAAA answer support этого не меняет |
| [managed proxy sidecar](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/proxy.go:1715) | gVisor TUN → literal-target loopback SOCKS, auto_route=false; существующие checked engine runtimes | Stock SOCKS не передаёт original LAN src:sport/MAC/ingress; sniffing сейчас не включён |

CORE передаёт `Route.Ingress → PolicyRule.iif`. DEFAULT должен потребить этот точный контракт, а CORE — довести его до kernel rule grammar, readback, snapshot/hash и removal. Наличие DTO field либо `route get … iif` в диагностике не доказывает установку iif selector в реальном `ip rule`.

## 3. Native negative admission: конкретный packet path

Новый proposed `LANAdmissionPlan` в общем Input/Plan: policy/control/network/boot generation, exact ingress, confirmed negative `{deviceID, MAC, segment}`, source CIDRs, owned bit/anchor, consumer list и coverage. Не список lease `/128` вместо MAC. MAC проверяется раньше positive source selection, включая свежий privacy IPv6 address.

Candidate bit **B=0x08000000** не занят в прочитанной Go vocabulary, но это не доказательство отсутствия foreign use. CORE выделяет его только после bounded snapshot/readback всех конфликтующих marks/RPDB/hooks. Existing default bit0x10000000, endpoint bits0x01000000/0x02000000/0x04000000 сохраняются отдельными ресурсами. Canonical пример intent, не shell для запуска:

```text
LAN mangle entry (exact iif): negative MAC/CIDR -> set-xmark B/B
every owned NFQ/TUN/default entry: negative MAC/CIDR or B -> RETURN from OWN chain
owned DNS nat entry: negative MAC/CIDR or B -> RETURN BEFORE DNAT
pre-FIB reassert on exact LAN ingress: negative MAC/CIDR -> set-xmark B/B
IPv4 + IPv6 RPDB: priority59 iif <ingress> fwmark B/B goto73
IPv4 + IPv6 RPDB: owned priority73 nop
```

`goto73` проходит мимо layout2 service60–71 **и** default72, затем продолжаются firmware policies; `goto72` недостаточен, `lookup main` подменяет baseline. Endpoint slots50–52 имеют full-mask predicates без B: excluded packet с B должен быть доказанно disjoint и с ними. Если новый earlier owned selector этого не обеспечивает, CORE переносит отрицательный guard перед ним либо меняет строго typed predicate. Foreign occupant в обходящемся interval не перескакивается. Legacy layout0 требует exact migration через existing receipts или отказа этой capability, иначе goto73 всё ещё попадёт в поздний owned route.

Masked set сохраняет чужие bits, **но меняет весь mark**: foreign full-mask rule может перестать совпадать. Unknown marking, overlapping full-mask predicates, late foreign CONNMARK restore или невозможность подтвердить порядок hooks закрывают segment. Ранний gate защищает owned consumer; повтор перед FIB защищает RPDB. Каждый DNS/engine entry независимо проверяет negative MAC **и CIDR**, либо заново выполняет полную admission classification: restore старого connmark не должен отменить ни device, ни address exclusion до consumer. Ни global ACCEPT, ни flush, ни запись чужого mark-word не нужны.

L2 source MAC должен быть подтверждён на выбранном hook; AP/routed downstream/mesh не получают capability лишь по DeviceBinding. Если виден MAC промежуточного роутера, нет fallback к lease addresses. Guest/WAN/OUTPUT не получают LAN jump без отдельного разрешённого scope. IPv6 matcher/negative gate обязателен даже если первый named TCP slice IPv4-only.

RPDB local priority0 предшествует59: DNS нельзя защищать только `ip rule`. Raw PREROUTING NFQUEUE также предшествует mangle — native queue owner должен разместить gate раньше своей очереди либо иметь свой direct MAC admission. Current [NFQWS2 Stage/Activate](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/nfqws2.go:131) собирает domains/CIDRs и restart внешнего init; этот путь не доказывает consumption B/iif/source. Managed payload OPS/NFQWS prerequisite нужен **когда NFQ участвует**, а TCP/default slice без NFQ им не блокируется.

## 4. Named flow без shared-CDN подмены

Первый frontend предлагается реализовать как **новый owned TCP DNAT/REDIRECT listener**, pattern lifecycle берётся у scoped DNS. Capture selector: exact ingress + client `/32` + confirmed positive MAC + public destination + TCP80/443, после negative admission. INPUT lease допускает только соответствующие перенаправленные соединения. Listener не является общедоступным SOCKS/HTTP proxy.

Accepted RemoteAddr даёт LAN src:sport; checked Linux `SO_ORIGINAL_DST` даёт исходный IPv4 destination:port. Перед любым Dial они связываются с exact owner/generation/capture rule и проверенной original conntrack tuple; прямое подключение к высокому listener port либо mismatch закрывается. Linux kernel documentation прямо отмечает race получения original destination при REDIRECT — её нельзя скрыть под DTO. Не удалось доказать original tuple → закрыть этот flow. TPROXY без NAT может стать следующей capability, но требует проверенных socket/target/module/policy support. [Linux transparent proxy contract](https://www.kernel.org/doc/html/latest/networking/tproxy.html).

Более дорогая альтернатива — existing gVisor TUN + **новый trusted metadata bridge** к gateway. Обычный общий SOCKS loopback не даёт original 5-tuple; fixed-client lease даёт context, а не потерянный source port. Поэтому включение stock sniff либо inferred client из loopback RemoteAddr не заменяет предложенный native frontend.

Bounded предлагаемые limits:32KiB handshake/header buffer,2s read deadline,128 simultaneous capture flows, fixed per-client limit и cancellation/join. Это проектные значения, не измеренная производительность. TLS ClientHello собирается через TCP/record boundaries, проверяются длины/duplicate SNI; HTTP1 Host/absolute target нормализуются и противоречия отвергаются. TLS не завершается на роутере, buffered bytes пересылаются неизменными. Нельзя удерживать SYN до ClientHello: клиент сначала ждёт handshake. Нельзя сначала Dial через default, затем менять маршрут после SNI.

`OriginalFlowReceipt{boot, controlEpoch, admissionGeneration, ingress, clientID/MAC, originalTuple, flowID, nameState, canonicalName, nameSource, policyDigest}` создаёт только frontend. `nameSource` — TLS-SNI/HTTP-Host actual connection; не DNS/PTR/CNAME/IP cache. Receipt — authority source привязки к flow, не криптографическое удостоверение сайта.

После parse frontend вызывает **тот же** `DecideNetworkPolicy` с trusted ClientPacket и literal destination. Service matcher берёт frozen catalog domains; override scope miss, ноль overrides и удалённый override продолжают default. Domain decision не добавляет IP rule для DNS address; `excluded.example` и `service.example` на одном IP получают разные connection decisions. SOCKS backend получает literal original IP:port, не re-resolved SNI.

Typed `NameState`: Known / NoName / EncryptedOuterOnly / Ambiguous / BoundExceeded. Это **новое CORE extension**, не существующее поле `ClientPacket`/готовый API. Only Known делает exact/suffix match. ECH outer name не inner hostname, HTTP2/3 coalescing не per-request identity. Unknown нельзя молча назвать NoMatch, когда mandatory domain exclusion требует visibility: требуется заранее определённое policy outcome base/block/retain; base нуждается в baseline grant, retain — в matching ранее принятом решении. Обычный Known-name miss продолжает default. UDP/QUIC/IPv6 named traffic остаётся отдельной capability, а не false TCP PASS. UI/backend показывают coverage, без silent partial activation policy, требующей большей полноты.

### DIRECT baseline — отдельная небольшая NET работа

Router-originated direct Dial не равен LAN forwarding. Existing [FreshWANProfile](C:/Projects/RAZVILKA/delivery-review/internal/systemprobe/network_epoch_wire.go:181) исключает nondefault routes/другие tables; [LAN route-get](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/policy.go:272) доказывает forwarded FIB, [WG endpoint reader](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/wg_endpoint_lifecycle.go:236) — собственный mark0/main path. Ни один не baseline socket grant.

Первый `UniformBaselineSocketGrant` ограничить одним client/ingress и uniform WAN: frozen all relevant RPDB/routes/marking digest, exact interface/gateway/local source, отсутствие пересекающегося foreign PBR/непрозрачного OUTPUT rerouting. Проверяется equality forwarded baseline и bound local socket route для literal target; проверяемый [SO_BINDTODEVICE primitive](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/wg_canary_socket_linux.go:11) может быть частью исполнения. Перед каждым Dial fresh generation guard, при изменении suspend/review. Не forcing main и не новая global route. Если такую equality нельзя доказать, этот named capability не активируется, IP/device slice продолжает отдельный допустимый путь. Grant доказывает равенство egress; исходные TCP port/stack после локального proxy не сохраняются.

## 5. Один lifecycle, existing-flow settlement и DNS

CORE задаёт явную dependency order: admission сначала, checked backend/consumer после, positive capture последним; остановка в обратном порядке. При неизвестном consumer cleanup admission сохраняется вместе с fence. Current [alphabetical Apply](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/manager.go:1435)/[Deactivate continue-on-error](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/manager.go:1050) этого сами не гарантируют. Snapshot/Stage/Validate/Activate/Health/Commit/Rollback, independent Stop/effect admission, config CAS и immutable LKG сохраняются.

NAT first-packet state и уже открытые proxy flows не отменяются новой отрицательной rule. При exclusion cutover frontend отменяет matching owned flow leases; DNS owner settles exact old client/original53/NAT-listener tuples; conntrack removal только по доказанным owned tuples/IDs, не по всему client/subnet/CDN IP. Старые snapshot без такой authority не разрешают broad cleanup. Неизвестное settlement → withdraw positive catch-all этого segment, retain negative guard/recovery fence; прежний LKG применим только если соблюдает **текущие** исключения. При replacement old/new negative gates объединяются до settlement, rollback не открывает окно захвата исключённого устройства.

NET повторно использует [NewScopedDNSResolver / Resolve / Serve](C:/Projects/RAZVILKA/delivery-review/internal/dnscontrol/scoped_query.go:44), existing TTL/cache/negative fences. Guard на query/cache/final answer включает тот же admission/Stop/policy generation. Новый listener INPUT admission проверяет negative MAC/CIDR/B на каждом пакете, допускает только доказанную capture lease и закрывает прямой доступ к high port; old DNS query/session leases cancel/join и exact conntrack settlement нужны отдельно. Current [scoped listener](C:/Projects/RAZVILKA/delivery-review/internal/dnscontrol/scoped_listener.go:43) извлекает source IP, не trusted MAC/ingress: новый authority bridge/INPUT lease нельзя считать уже существующим. Только вместе эти меры обеспечивают, что excluded MAC не попадает в owned DNS. Query name может выбрать DNS provider, а DNS ledger/CNAME/A/AAAA **не** заполняют FlowName и не публикуют service IP route. Общая IPv6 DNS interception — отдельное расширение NET.

[UseLocalBaseline](C:/Projects/RAZVILKA/delivery-review/internal/dnscontrol/scoped_baseline.go:16) посылает router-originated query к loopback53 и теряет LAN client/ingress context. Его можно использовать только с отдельным `DNSBaselineEquivalenceGrant` для подтверждённой uniform resolver policy; per-device firmware DNS baseline этим helper не доказан. Неизвестная per-client policy не заменяется loopback resolver. Excluded DNS остаётся на собственном firmware path без owned interception.

## 6. Малый carveout владельцам

| Предлагаемый один владелец | Точные новые файлы / shared изменения | Первое проверяемое завершение |
|---|---|---|
| CORE | `dataplane/lan_admission*.go`, shared `plan.go`, `manager.go`, `policy*.go`/`ownership.go`, registration/control/CAS | Immutable gate + iif/mark/goto/nop grammar; exact order/readback; guard first/last; capability без NFQ |
| DEFAULT, после назначения координатором | Собственные `app/default_route_executor*.go`; новые `dataplane/lan_tcp_flow*.go`, `flowname/tcp*.go` | BindIngress consumption; native TCP frontend/typed receipt/DecideNetworkPolicy; no app/config shared writes |
| NET | Новые `dataplane/baseline_socket*.go`; свои `scoped_dns*.go`/`dnscontrol/**` | Uniform baseline receipt, pre-DNAT negative gate, query/answer generation, exact existing-flow settlement |
| NFQWS + OPS | Свои `nfqws2*.go` и managed payload/install hooks | Native queue entry consumes same admission before queue; no stock-init coverage inference |
| VLESS (shared receipt owner) | Согласованное typed extension `policy_addition_receipt*.go` | Новый resource vocabulary внутри existing transaction; no arbitrary argv / second journal |

Existing [PolicyAddition expected steps](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/policy_addition_receipt.go:91) создаёт default routes и ordinary RPDB tuples; iptables chain/jump/mark/goto/nop сейчас не покрыты. [Ownership parser](C:/Projects/RAZVILKA/delivery-review/internal/dataplane/ownership.go:219) специально не принимает unknown selectors. Расширять полной строгой грамматикой и derived expected tuples, не универсальным shell-command replay. Private adapter owner/snapshot — часть существующей transaction, не второй control journal.

## 7. Приёмка координатором и границы чтения

Native matrix первой порции: excluded MAC IPv4 + новый privacy IPv6, default+override+DNS вместе, guest/outside/OUTPUT, late mark restore/full-mask foreign predicate, layout0 refusal/migration, gate loss, consumer unknown cleanup, exact conntrack settlement, Stop/reboot. NFQ добавляется только после native admission его owner. Shared CDN: два имени одного IP → разные выбранные пути; DNS-only label не меняет flow; SNI fragmented/HTTP duplicate/ECH/timeout/limit; first upstream Dial только после decision; default при Known miss/удалении override; direct baseline mismatch → отказ. Эти сценарии здесь **не запускались**.

DEFAULT WIP fingerprint при чтении (может меняться у автора): `default_route_executor.go` SHA256 `6aeda44a62f1b8e767c188b16c301cc604bc7253cfb6090bba628881c5e4e9ad`; compile `121f57162ac9961206d70338fa522ddfcb8c298bc206d8e8aa58ae1d256d2af4`; classify `2cf24d72bc3e123556d03f699bbce9abd16026b192068ad491771af657242118`. Это не commit/final API. CORE WIP Route.Ingress[]/PolicyRule.Ingress прочитан отдельно; не смешивать его с baseline d010e13.

Read-only parallel source review выполнен тремя агентами. Проверка ограничена источниками, существующими контрактами и первичной Linux/Sing-box документацией; package/kernel/runtime support не проверялся. Никаких inter-chat сообщений VLESS/CORE/NET не отправлено; назначение файлов/передача контракта остаются координатору.
