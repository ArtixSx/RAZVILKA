# D13: actual USQUE — checklist для root

04.10.2026. Этот документ готовит root-run acceptance; все строки ledger ниже пока **UNVERIFIED**. CLOUD не подключался к роутеру/VM, не запускал USQUE, MASQUE server или live probe и не регистрировал аккаунт. Local TLS H2/H3 harness, fake proc/network fixtures, injected runners и compile-only результаты не являются USQUE tunnel acceptance.

Producer: `2b23a613e3fe970451ba4a3f3adf91fce19ff986`; required P2 DNS boundary fix: `a0b8cec28d5340bde6bceddafeff6d881ec381e4`, branch `sol/cloud-20261004`. Commit objects доступны в shared Git. Owner bridge/admission SHA пока pending.

## Почему выбран live путь

Найден pinned [Vincent-bin/masque-server, commit127abc164d3233ebdbb260522c127322da36052e](https://github.com/Vincent-bin/masque-server/tree/127abc164d3233ebdbb260522c127322da36052e). Его [Cloudflare-compatible dialect](https://github.com/Vincent-bin/masque-server/blob/127abc164d3233ebdbb260522c127322da36052e/docs/protocols.md#cloudflare-compatible-clients) поддерживает USQUE H3 cf-connect-ip и H2 cf-connect-proto/raw-IP DATAGRAM; обычный RFC CONNECT-IP H2 server не заменяет этот диалект. Однако reviewed [testing recipe](https://github.com/Vincent-bin/masque-server/blob/127abc164d3233ebdbb260522c127322da36052e/docs/testing.md#cloudflare-compatible-client-interop) не демонстрирует qualification нашего exact official v4.2.1 artifact. Это кандидат для будущего interoperability стенда, не выполненная проверка.

Unchanged [USQUE socks command](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/cmd/socks.go#L20) может читать локальную EC session без регистрации; outer TLS использует [server public-key pin и client certificate](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go#L33). Но стандартный localhost/private-IP/:4433 server не проходит текущий public IPv4:443 профиль. Сгенерированные server enrollment `id`/`access_token` пусты и также не проходят production session guard. Заполненная lab session остаётся lab session, не Cloudflare account.

Главное ограничение: full producer требует реальный verified-TLS `www.cloudflare.com/cdn-cgi/trace` с `warp=on|plus`; этот trace применяется для [проверки WARP routing](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/manual-deployment/). Plain Internet egress локального MASQUE server не доказывает WARP. Fake trace body, fixture CA или injected Warp не разрешены как full acceptance. Controlled public-IP:443 server с genuine existing WARP egress теоретически подходит, но уже зависит от внешнего WARP и пока не воспроизведён. Поэтому следующий практический шаг — реальные existing-account Cloudflare candidates в окне root.

## Gate перед запуском

1. Root принимает законченные commits producer + DNS boundary fix, VLESS bridge и CORE admission/readback; фиксирует integration SHA и app build digest. До этого production-action acceptance имеет статус BLOCKED, даже если library API доступен. No WIP consumption.
2. VLESS сохраняет ownership existing process/receipt backend. Его thin hook работает внутри `runCanaryAttempt` после `Start`/`waitForSOCKSProcess`, до `Stop`, передаёт actual private ProcessSpec и candidate bytes, сохраняет typed `CanaryEvidence.Owned` целиком. CLOUD не создаёт другой process controller, CLI или receipt backend.
3. CORE подтвердил reuse `dataplane.WithReviewGuard`: current seal включает configRevision, Stop/SafeMode, WAN epoch и owned identity. Missing review guard отказывает **до active capture**, а не превращается в пустой PASS. Authority rechecks до capture, перед network и после результата; context cancellation связан с текущим worker. `Manager.EvidenceRuntime` читает только private current live ProcessSpec через `ObserveOwnedUSQUE`; GET/login не запускает action.
4. Root выбирает один уже зарегистрированный usable native session без fresh enrollment. До/после окно должно иметь одинаковые original enrollment facts и отсутствие нового registration POST. Отсутствующая/unknown session — остановка сценария, не auto register.
5. Installed actual executable имеет один из exact v4.2.1 SHA из [bridge contract](CLOUD_USQUE_BRIDGE_RU.md). Version text/opkg label недостаточны. Linux `/proc`, launcher identity и listener доступны в той же network namespace; неизвестный binary, args/profile или proxy child environment означает refusal, не fallback.
6. Candidate: explicit public canonical IPv4:443, exact args `socks -b 127.0.0.1 -p <owned-port> --always-reconnect -S`, optional approved SNI, и `--http2` только для H2. Нет `-6`, alternate port, hooks, `--insecure`, другого backend или скрытой подмены transport. Empty upstream H2 default запрещён.
7. Stable approved ServiceID/HTTPS target; для semantic proof — controlled server с publicly trusted TLS certificate и exact `TransportChallengeResponse(nonce)` на `TransportChallengeHeader`. 2xx без challenge доказывает reachability. UDP target — отдельный controlled public literal endpoint, возвращающий полученные nonce bytes без изменения; TCP HTTPS challenge не заменяет UDP echo.
8. DNS boundary fix должен быть принят: fresh A+AAAA DoH идёт по **этому owned SOCKS** на literal `1.1.1.1:443`, TLS hostname `cloudflare-dns.com`; весь DNS set public, конечный CONNECT literal, original target hostname остаётся для TLS. DoH использует [DNS wireformat POST](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/). Нет system DNS/ATYP3/direct fallback. Если owned DoH недоступен, результат unknown/failure, не registration failure и не разрешение другого resolver.
9. Root фиксирует active LKG, private restore availability, control/admin connectivity и cleanup plan. Canary не устанавливает routed TUN/default policy; routed/LAN/IPv6/ECH/media/voice acceptance не следует из этого SOCKS proof. Весь producer window ≤30s, network default8/max20s, fresh DNS ≤3s на обе семьи, receipt TTL ≤5min.

Read-only inventory в root router shell, после назначения trusted absolute `USQUE_BINARY`:

```sh
date -u
uname -r
sha256sum "$USQUE_BINARY"
readlink /proc/self/ns/net
```

Runtime/config/argv/environ/private account не печатать в общий log. Producer выдаёт bounded safe identity/hash/error codes. Для теста нужен exact **owner-approved action/endpoint**, его transport selection и hook SHA; пока владельцы не сообщили их, команда вызова здесь намеренно не выдумана. `ProbeOwnedUSQUE` из ad-hoc harness может подтвердить библиотеку, но не production worker/admission wiring.

## Матрица actual-run

| Run | Root действие и обязательное свидетельство | Критерий результата |
|---|---|---|
| P0 admission/readback | Normal GET/login до action; отсутствующий guard; отменённый worker; Stop/SafeMode/revision/epoch seal drift до сети. Счётчик invocation и owned socket/network metadata снимает root из реального production пути. | Нет active capture/network и нового receipt в отказах. GET выполняет только local observer, не DNS/trace/service probe. |
| H2-WARP | Один explicit H2 owned candidate; actual process/executable/session identity до/после; настоящий WARP TLS trace и approved service. | Успех producer, Warp on/plus, stable binding, ProtocolPath HTTP/2, PeerObservation tcp-established-peer, Negotiated=false. Service IDs только реально проверенные. |
| H2-no-UDP | Root фиксирует **оба** actual config pins endpoint_h2_v4 и endpoint_v4: они могут различаться, H2 address не обязан обслуживать QUIC. До старта отдельного candidate ставит временные exact destination UDP:443 blackholes для его выбранных pins. Они не используются active LKG; rule image/counter и root cleanup ledger обязательны. Реальный QUIC drop-control использует именно покрытый endpoint_v4; H2 attempt выполняется в том же drop window. | H2-WARP проходит при действующем UDP block. Preferred→fallback success не считается QUIC negative control; H2→QUIC/другая endpoint попытка не засчитывается за H2 run. При отсутствии безопасного scoped blackhole — UNVERIFIED, не глобальный UDP drop. |
| QUIC-WARP | Root снимает exact temporary drop и запускает новый explicit QUIC candidate без --http2. Owned UDP inode/socket binding и actual encrypted outer UDP tuple к pin подтверждаются root metadata; одновременно проходят real WARP TLS/service bytes. | Producer success, Warp on/plus, ProtocolPath QUIC, stable binding. PeerObservation остаётся udp-unconnected-exclusive-config-inference либо udp-connected-default-peer; Negotiated=false. UDP:443 traffic/CONNECT200 сами по себе недостаточны. |
| H2-UDP | Новый H2 proof с optional controlled public UDP target, при scoped outer UDP:443 blackhole. SOCKS UDP relay exact owned loopback host/port; сервер реально получил/вернул свежий nonce. | UDPForwarding=true только при exact target + relay + fresh nonce. Это inner SOCKS UDP через H2; outer UDP availability и TUN не объявляются. |
| QUIC-UDP | Новый QUIC proof с тем же independent UDP echo, outer drop снят. | Warp/service и отдельный UDP nonce проходят; UDPForwarding=true. QUIC-WARP без этого run сохраняет UDP unknown/false. |
| UDP-negative | Root закрывает/blackhole только controlled UDP target либо возвращает wrong nonce; actual candidate/WARP path остался тем же. | Action failure/zero new successful evidence, без partial fresh UDP/Apply. Existing LKG не заменяется и account не регистрируется заново. |
| DNS/TLS-negative | Controlled approved hostname с private-only/mixed A+AAAA; затем public response→rebind. Public DNS fixtures/root-owned authoritative domain и network metadata, не injected runner. Отдельно wrong TLS identity у controlled service. | Ни одного private target CONNECT/пакета. Rebind не меняет уже проверенный literal в данном CONNECT; последующий Dial опять проверяет весь fresh set. Wrong certificate не даёт service proof. |
| Stop/restart | Root завершает именно candidate через existing owner Stop; затем новый owned start с launcher receipt. | Старое evidence хранится как история, OwnedFresh=false; новый RuntimeID/BindingID. Current-green возвращается только после нового explicit action. |
| WAN/session/exe drift | Root разрешёнными owner workflows меняет epoch/session/executable; возвращает исходное состояние через existing cleanup/recovery. Не редактирует произвольно действующий LKG ради теста. | Capture/action отказывает при before/after drift; readback stale, no apply authority. Original account/LKG сохранены. |
| TTL/receipt/proxy | Receipt expiry при реальном clock; malformed/expired/mismatched receipt; import write/adoption boundary; actual child proxy env; неверный/unowned listener/socket. | Malformed/expired/mismatched evidence stale; env/listener/ownership guards отказывают. Import/UI не может создавать или изменять trusted producer proof и не выдаёт admission. Копия уже valid текущего trusted receipt может оставаться fresh диагностикой, но не producer/action/apply authority. |

Blackhole, capture и process stop выполняет **только root** в согласованном окне. Rule ограничивается точным candidate outer endpoint/protocol/port и имеет восстановление исходного image; UID0/global DROP не является безопасной изоляцией. Packet capture/conntrack/FD tuple усиливают path observation, но не превращаются в negotiated ALPN или peer export. Endpoint/IP/port без owned inode/runtime correlation не атрибутирует packet процессу.

## Receipt и cleanup

Для каждого positive run сохраняются safe typed evidence, integration/bridge/admission SHA, app/USQUE SHA, UTC window, actual transport args hash, environment/runtime/session/socket binding, ServiceIDs + reachability/challenge grade, отдельный UDP outcome и root evidence references. Keys/config/argv/environ и сырые account/API responses остаются в existing private paths. BindingID не подписывает proof fields; запись разрешена только trusted producer-owned writer.

В `finally` root вызывает existing owner Stop/cleanup, снимает **только** свои temporary drop/capture/echo effects и сверяет restored rule image, process/listener inventory, LKG/account hash и admin path. Cleanup error оставляет gate закрытым и требует existing owner recovery; ручное удаление чужих процессов/rules/receipts запрещено. Canary receipt после Stop является историей; для Activated live process требуется собственный explicit probe.

## Ledger для root отчёта

| Case | Integration + owner hook SHAs | UTC / RC | Safe evidence / rule-counter / cleanup references | Status |
|---|---|---|---|---|
| P0 | pending | — | — | UNVERIFIED |
| H2-WARP / H2-no-UDP | pending | — | — | UNVERIFIED |
| QUIC-WARP | pending | — | — | UNVERIFIED |
| H2-UDP / QUIC-UDP / UDP-negative | pending | — | — | UNVERIFIED |
| DNS/TLS-negative | pending | — | — | UNVERIFIED |
| Stop/restart/WAN/session/exe/TTL/receipt/proxy | pending | — | — | UNVERIFIED |

PASS относится только к исполненной строке с фактическим output/RC/cleanup. `Negotiated=false` сохраняется даже после положительных actual runs этого профиля. D13 не закрывается compile/unit/local TLS результатом или заполнением ledger без выполнения.
