# D08: библиотечный DNS expiry и scoped cancellation

## Результат и API для CORE

Добавлен `dnscontrol.Manager.NewEndpointDNSResolver(profileID, guard)` с методом `Resolve(context.Context, string) ([]netip.Addr, time.Time, error)`. Его method value совместим с существующим `WARPWireGuardAdapter.EndpointResolver`:

```go
resolver, err := dnsManager.NewEndpointDNSResolver(profileID, transactionGuard)
if err != nil {
    return err
}
wgAdapter.EndpointResolver = resolver.Resolve
```

`transactionGuard` обязателен. CORE должен связать его с неизменяемыми network/settings/policy review и сроком операции; смена выбранного profileID/настроек должна инвалидировать callback, даже если определение прежнего провайдера осталось тем же. Сам resolver дополнительно сравнивает полное captured provider definition с текущим до/после каждого обмена и перед выдачей результата. Разрешены только настроенные production DoH profiles по существующему ScopedProfileIdentity: custom/lab/experimental/trusted-local/system не повышаются до production после успешной диагностики.

Выбран ровно один DoH endpoint, без fallback на другого провайдера, UDP53 или системный lookup целевого tunnel hostname. Существующий HTTPS transport сохраняет нормальную TLS trust/SNI/Host проверку, Proxy=nil и reviewed bootstrap IPs для известных built-in endpoints. Получение адреса самого DoH endpoint без pinned bootstrap по-прежнему выполняет существующий transport; новый API не доказывает bootstrap DAG/WAN path и не создаёт маршруты. NET не подключал callback в CORE/app и не менял DNS роутера.

## Срок и целостность

- Общий timeout5s, полный A+AAAA ответ через один endpoint, не более32 записей суммарно; сверхлимит не обрезается. Обе семьи должны завершиться; timeout/transport/integrity error одной отклоняет всё. Валидный NODATA одной семьи допускается с положительной другой; NXDOMAIN/пустые обе — отказ. CNAME chain обеих семей должна совпасть.
- Используется существующий DNS wire validator: ID/question/class/family/terminal CNAME, ответы<=64, reachable aliases<=16. Дополнительная whole-wire проверка ограничивает весь packet<=65535B, RR<=256, запрещает trailing bytes, непубличные адреса во всех секциях, чужой class для address RRs, скрытые extended RCODE/EDNS version/flags и неоднозначный OPT. RD/CD должны соответствовать исходному запросу. AD остаётся утверждением удалённого resolver, не локальной DNSSEC проверкой.
- Expiry = минимум `queryStarted + min(CNAME/address TTL, либо NODATA SOA TTL/MINIMUM) - HTTP Age` по обеим семьям. Запрос не получает добавочного времени за latency. High-bit TTL считается0 существующим parser. Unknown/zero/consumed TTL даёт zero expiry и повторный resolve перед каждым start; fixed TTL нет. Истёкший во время обмена положительный срок или clock reversal дают отказ.
- DNS public-address boundary унифицирована с существующим publicfetch/WG. Регрессия **до исправления FAIL** для0.1.2.3; теперь также отвергаются reserved IPv4, NAT64/Teredo/6to4 и zone-bearing addresses, которые прежний более короткий список DNS пропускал. Shared publicfetch файл не изменялся.
- WG revalidation не принимает результат callback после отмены и обновляет DNS lease только после успешного неизменённого WAN readback. WAN mismatch сохраняет весь прежний endpoint tuple и timestamps. Scoped cache hit не выдаёт ответ, если guard отменил context, но вернулnil.

## Проверки

Go1.26.5 Windows, GOMAXPROCS2, GOFLAGS-p=2:

- Полный `go test ./internal/awgprofile ./internal/dnscontrol ./internal/netresolve ./internal/dataplane -count=1`: PASS; dataplane49.631s. После последних изменений отдельно полный dnscontrol PASS, targeted dataplane `WGEndpoint|ScopedDNS|DNS` PASS9.567s и окончательный полный dataplane PASS50.070s.
- Новые DNS regression fixtures используют реальные DNS wire сообщения и контролируемый DoH exchange, без внешнего DNS/network запроса. TTL/HTTP Age/latency, NODATA с/без SOA, оба семейства, malformed/private/overflow/extended-error, cancellation/epoch/provider change и production factory покрыты. Фактическая смена настроенного NextDNS profile инвалидирует прежний callback; custom остаётся непродукционным.
- Windows и Linux amd64 vet DNS/netresolve/dataplane PASS; Linux amd64 CGO0 test compilation DNS/dataplane PASS. gofmt и diff-check PASS. Linux execution/race для D08 NET не запускал.

## Оставшиеся gates

D08 целиком **не закрыт**. Общий LAN/default executor, exclude devices во всех owned путях, guest opt-in, IPv6/UDP, bootstrap DAG, shared CDN, existing-connections scoped cleanup и router acceptance остаются за CORE/root. `NETWORK_POLICY_EXECUTOR_REQUIRED` не снимается. TTL/cache observation не является route authority или service PASS. WG successful-addition receipt wiring и полный Manager.Rollback crash/EEXIST regressions ожидают общий VLESS API.

Применимый контракт из переданного root Research: использовать один reviewed source/device/guest gate и для DNS, и для traffic; observation сохраняет original qname/client/profile/network generation/CNAME min expiry. Read-only `ScopedDNSResolver.Observations` не является атомарным route publication ack. CORE должен подтвердить публикацию нужной scoped policy до выдачи ответа клиенту. Один CDN IP у двух имён даже одного клиента не даёт однозначного service classifier: при ambiguity нужен безопасный default или явно проверенная/согласованная capability, а не последняя IP→domain запись. Второй DNS cache/IP reverse-map не создавался; upstream код не копировался.

Координатор сообщил native-awg-02 RC0 после c334eee: actual loaded kernel AWG3.1 receipt и independent server/client TCP/UDP IPv4/IPv6, same-key/wrong-peer/live-after; WG candidate/lifecycle regression обеих семей PASS. Это VM Ubuntu/kernel7.0 acceptance D06 в заданных пределах, не Netcraze HIL/Commit/reboot и не проверка будущего общего policy receipt. NET сам VM не изменял.

D09 `strategylab/**` и `nfqws2*.go` переданы NFQWS по сообщению координатора; D09 WIP у NET отсутствует.
