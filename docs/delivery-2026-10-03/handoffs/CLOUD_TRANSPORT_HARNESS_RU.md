# CLOUD — локальный native H2/H3 harness, без enrollment

Дата: 04.10.2026. Base: `c44ffeec4289534d6cb197e7a821aaa920bc8355`, worktree `sol-cloud`. Реализация и тестовый binary собираются; **opt-in native запуск здесь не выполнялся**, его окно принадлежит координатору. Это отдельная транспортная проверка, не реальный WARP/USQUE acceptance.

## Что реализовано

`internal/usquediag/transport_probe.go` добавляет:

```go
ProbeNativeTransport(context.Context, TransportProbeOptions) (TransportProbeEvidence, error)
TransportChallengeResponse(challenge string) string
TransportProbeEvidence.Fresh(now time.Time, endpoint netip.AddrPort, environmentID string) bool
```

Trusted options задают `Enabled`, `AllowLoopback`, HTTPS URL/SNI, **literal pinned Endpoint**, ровно `HTTP/2` либо `HTTP/3`, optional trusted RootCAs, bounded Timeout и current Environment callback. Это конфигурация локального harness, не вход HTTP API. Missing opt-in, private/mapped endpoint, loopback без явного разрешения, credentials/query, port mismatch, auto/fallback и неизвестный environment отвергаются до сетевой попытки.

Клиент не делает DNS lookup, не читает proxy environment, не следует redirects, не переключает протокол, не выключает TLS verification и не выполняет enrollment/profile/export/route operations. H2 использует exact TCP/TLS/ALPN h2; H3 — exact UDP/QUIC/TLS1.3/ALPN h3, full handshake без 0-RTT. CA/SNI и actual response protocol проверяются. Challenge — новый random 32-byte nonce в `Razvilka-Transport-Challenge`; controllable server возвращает **ровно** `TransportChallengeResponse(header)`. Generic HTTP 200, HTTP/1, wrong body/oversized/unfinished body не становятся proof. Raw body/errors не возвращаются.

Environment callback проверяется до и после запроса. Успешный результат имеет expiry не позже пяти минут, exact endpoint/environment и закрытый seal. Изменение публичных fields или JSON roundtrip не даёт `Fresh=true`. Это инертный diagnostic result; никакой конвертации в `CanaryEvidence`/registration candidate здесь нет.

`http2_confirmed` подтверждает только H2. `http3_confirmed` и `quic_udp_confirmed` подтверждают H3/QUIC по UDP **между этим клиентом и этим pinned сервером**. Они не подтверждают generic UDP forwarding, MASQUE CONNECT-UDP, WARP account, route/service через USQUE или native benefit Mihomo/HEV. Producer настоящего WARP canary по-прежнему обязан проверить exact native process, endpoint ownership/pin, Cloudflare trace, service/control route и cleanup.

H2 sockets явно удерживаются и закрываются при выходе, включая отмену response stream; H3 Transport/QUICTransport/UDP socket закрываются при каждом исходе. TCP reachability не выдаётся как UDP proof. TLS, redirects и ошибки проверяются отдельно.

## Opt-in сценарий координатору

Новый `scripts/test-cloud-transport.sh` требует явного `RAZVILKA_NATIVE_CLOUD_TRANSPORT=1`. Без него выходит **RC 2**, без запуска сетевой fixture. Нужны только Go 1.26.5/dependencies и localhost TCP/UDP; root, namespace, роутер, аккаунт, USQUE binary и внешняя сеть не нужны.

```sh
RAZVILKA_NATIVE_CLOUD_TRANSPORT=1 \
GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2 GO=/path/to/go \
sh scripts/test-cloud-transport.sh
```

Либо в выбранном координатором локальном Linux окне:

```sh
RAZVILKA_NATIVE_CLOUD_TRANSPORT=1 \
GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2 \
go test ./internal/usquediag -run '^TestNativeLocalCloudTransportHarness$' -count=1 -v -timeout=60s
```

Fixture создаёт ephemeral ECDSA server certificate, добавляет его в конкретный client trust pool и использует `cloud-harness.invalid` только как TLS SNI. Сокеты закреплены на 127.0.0.1 ephemeral ports; DNS/registration не нужны. TCP и UDP серверы контролируются самой fixture и закрываются.

Native матрица:

- H2 success оставляет H3/UDP unknown; H2 доступен, UDP того же tuple blackhole → H3 не подтверждён;
- H3 success подтверждает H3/QUIC-UDP, оставляет H2 unknown;
- неверный CA/SNI, HTTP/1, redirect, wrong/oversized body не проходят;
- изменение environment во время запроса и TTL boundary инвалидируют evidence;
- отмена зависшего H2 response не оставляет socket; сервер видит Closed;
- изменение evidence fields или JSON roundtrip не выдаёт in-process Fresh proof.

Вывод этой матрицы должен быть сохранён координатором с actual Go/OS и RC. Здесь **нет её PASS**: default запуск показал SKIP, а не native evidence. Реальный WARP проверять отдельно с существующим разрешённым аккаунтом и соответствующим dataplane/native окном; локальный fixture его не заменяет.

## Фактическая адресная проверка этой порции

С `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`, Go 1.26.5:

| Команда | Результат / граница |
|---|---|
| `go test -count=1 ./internal/warp ./internal/usquediag ./internal/privaterestore` | RC 0: 4.565s / 0.277s / 9.392s, opt-in native fixture не запускается |
| `go vet ./internal/warp ./internal/usquediag` | RC 0 |
| `go test ./internal/app -run 'Warp.*Backup|Native.*Backup|PrivateRestore' -count=1` | RC 0, 1.668s; actual encrypted native HTTP backup/restore и выбранные private restore regressions |
| `sh -n scripts/test-cloud-transport.sh` | RC 0, syntax only |
| `GOOS=linux GOARCH=amd64 go build ./internal/warp ./internal/usquediag` и arm64 | Обе RC 0, только сборка библиотек |
| `GOOS=linux GOARCH=amd64 go test -c ./internal/usquediag` и arm64 | Обе RC 0, native test binary compile, без исполнения |
| `go test ./internal/usquediag -run '^TestNativeLocalCloudTransportHarness$' -count=1 -v`, opt-in unset | RC 0 со **SKIP**, не native PASS |
| `sh scripts/test-cloud-transport.sh`, opt-in unset | Actual RC 2, ожидаемый отказ до native fixture |
| `git diff --check` | RC 0 |

Unit test `transport_probe_test.go` проверяет invalid/trusted opt-in boundary и отсутствие raw secret в ошибках **без сетевого обращения**. Native transport server fixture только компилировалась. Предыдущие full Linux/native/HIL результаты на других commits не расширяются на этот код.
