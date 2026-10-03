# NET: scoped DNS hook для единственного LAN/DNS owner

04.10.2026. Отдельный checkpoint поверх `ef2d7b5a19447e3f985e5526a8a7e440a5e3aa6a`, ветка `sol/net-20261003`. Изменены только существующие NET-owned `scoped_listener.go`, `scoped_query.go`, новый regression test и этот отчёт.

## Контракт

`dnscontrol.ServeScopedDNS(ctx, udp, tcp, ScopedDNSHandler)` использует явно переданные парные UDP/TCP sockets с одинаковыми конкретными IP/port >=1024. Все три callbacks обязательны:

- `Admit(ctx, client) error`: owner проверяет текущий physical LAN/device scope.
- `Resolve(ctx, client, query) ([]byte, error)`: owner выбирает service/default/direct/refused. Listener самостоятельно не выбирает default или upstream.
- `Publish(ctx, client, query, send) error`: owner удерживает актуальный generation/device lease во время синхронного вызова `send`. Check только до Resolve недостаточен.

Каждый ответ проходит Publish, включая UDP busy SERVFAIL. TCP prefix и body отправляются вместе внутри callback, до разрешения не выходит даже prefix. `send` одноразовый и закрывается после возврата Publish; сохранённый callback нельзя позднее использовать для ответа. Callback обязан вызывать send синхронно под своим owner lease.

Listener сохраняет bounds: четыре общих worker slots, query <=4096 bytes, bounded DNS reply, UDP EDNS truncation, максимум 16 frames на TCP connection, deadline 6 s. Cancellation закрывает sockets/connections и ждёт завершения accept loops и workers. Отсутствующий Publish отвергается до принятия sockets во владение.

`(*ScopedDNSResolver).MatchClientQuery(ctx, client, query) (bool, error)` — только exact client/name selection. `false, nil` означает валидный NoMatch при прошедшем guard; это **не** разрешение default. Выбранный service с изменившимся provider возвращает `true, ErrServiceDNSChanged`; malformed/refused/cancelled/revoked query возвращает error. Caller обязан сначала проверить error. DNS answer/reverse map не доказывает identity последующего flow.

Существующий `ScopedDNSResolver.Serve` использует тот же listener: прежние exact client bindings, epoch guard и повторная проверка выбранного provider перед actual send. Явно настроенный `UseLocalBaseline` сохранён, включая unselected non-address questions; selected unsupported type остаётся REFUSED и не уходит в baseline. Этот legacy check не заменяет generation/device lease нового LAN/DNS owner.

## Проверки

Windows Go 1.26.5, `GOMAXPROCS=2`, `GOFLAGS=-p=2`, `GOTOOLCHAIN=local`:

- Финальный `go test ./internal/dnscontrol -count=1`: PASS 1.629 s.
- Реальные локальные UDP/TCP sockets: authorized reply; revocation после Resolve подавляет UDP packet и весь TCP frame; shutdown joins workers.
- Дополнительные regressions: provider error не становится NoMatch; invalid/epoch error не разрешает default; delayed/repeated send отвергается; missing Publish не принимает sockets; explicit local TXT baseline сохраняется, selected TXT не leaks.
- Windows и Linux amd64 vet DNS пакета: PASS.
- Linux amd64 DNS test binary cross-compile: PASS. Это не Linux execution.
- Полная группа dataplane/awgprofile/wireguardprofile/dnscontrol/netresolve: PASS (dataplane 77.765 s, остальные четыре пакета PASS). Windows/Linux vet пяти пакетов: PASS. DNS пакет после финальной baseline compatibility правки перепроверен отдельно, как указано выше.

## Передача LAN/DNS

Новые `network_policy*.go` должны передать три callbacks одного owner и Compose Resolve поверх существующего resolver/cache. На valid NoMatch default resolver допустим только по явной current network-policy authority. Refused/provider/epoch/cancel errors не становятся default. Publish должен удерживать lease до окончания actual send, а не возвращать разрешение, которое listener применит позже.

Второй cache, DNS manager, scheduler, wildcard listener, redirect/DHCP/firewall mutation здесь не добавлены. Physical LAN discovery, negative MAC/source classifier, exact kernel admission receipt, default/domain flow composition, policy/TTL lease integration и единственное live окно принадлежат LAN/DNS/CORE/DEFAULT и координатору. Native Linux execution, race, router/HIL нового hook здесь NOT_RUN.

Два `wg_network_profile*.go` в рабочем дереве — отдельная незавершённая WG подготовка; в этот checkpoint не входят. D07/default и D05 actual app handoff этим DNS checkpoint не объявляются завершёнными.
