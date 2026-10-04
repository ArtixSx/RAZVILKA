# CLOUD → VLESS/CORE: buildable owned USQUE producer

04.10.2026. Новый production entry point — `usquediag.ProbeOwnedUSQUE(ctx, OwnedProbeOptions)`. Его реализация и fixtures находятся целиком в CLOUD-owned `internal/usquediag/owned_runtime*.go`, `owned_probe_network*.go`; existing VLESS `proxy.go` не менялся. Это функциональный explicit probe уже запущенного owned SOCKS runtime, а не только описание receipt.

## Точная граница владельцев

CLOUD реализует producer/observer/typed receipt/doctor reader. VLESS вставляет вызов в свой `runCanaryAttempt` **после Start + waitForSOCKSProcess, до Stop** вместо legacy USQUE trace/service ветки. Для новой тонкой adapter части предлагается VLESS-owned `internal/dataplane/usque_owned_bridge.go`: она переводит существующие ProcessSpec/RoutePlan в CLOUD types; существующие proxy/process/routeidentity файлы остаются их владельцам. Граница не требует передачи существующих файлов CLOUD, нового root, capability, CLI или hooks. Согласование/применение adapter call остаётся у VLESS/координатора.

CORE предоставляет trusted current Authority callback из worker/action admission: текущие lease/revision, Stop/SafeMode и epoch revalidation. `Enabled=true` задаётся только этой веткой. Callback перечитывается трижды (до capture, непосредственно до network, после результата). `Manager.EvidenceRuntime` — **другой**, local-only readback callback, вычисляемый из текущего live ProcessSpec; он вызывает ObserveOwnedUSQUE и никогда ProbeOwnedUSQUE. GET/login не должны задавать Enabled или создавать worker.

## Adapter call

Кандидат уже записан в `spec.Dir/engine.json` и запущен existing ProcessController с RouteProof=true. CLI ABI проверяется ровно как у текущего adapter: IPv4 outer, port443, explicit config pin, `socks -b 127.0.0.1 -p <port> --always-reconnect -S`, optional `-s`/`--http2`, без неучтённых args/family/port/hooks. `-S` не означает outer IPv4; его отсутствие/новый `-6` требуют отдельного профиля и verifier изменения владельца.

```go
pin, err := usquediag.SelectedOwnedUSQUEEndpoint(candidateBytes, transportName)
if err != nil { return err }
req := usquediag.OwnedRuntimeRequest{
    Root: spec.Dir, Binary: spec.Binary, SOCKSAddress: address,
    Transport: transportName, Endpoint: pin,
    Environment: usquediag.OwnedUSQUEEnvironment(a.FreshProfile),
}
proof, err := usquediag.ProbeOwnedUSQUE(ctx, usquediag.OwnedProbeOptions{
    Enabled: true, Runtime: req, Authority: currentAdmission,
    Network: usquediag.OwnedNetworkRequest{
        SOCKSAddress: address, Services: selectedServiceProbes,
        UDP: optionalControlledPublicUDPChallenge, Timeout: min(a.timeout(), 20*time.Second),
    },
})
if err != nil { return err }
receipt := proof.CanaryEvidence()
```

`selectedServiceProbes` — максимум8 approved HTTPS public targets с stable ServiceID, не display name/произвольный UI URL. Без query/userinfo/fragment/redirect/proxy; nonchallenge подтверждает только verified-TLS2xx reachability. Для semantic service proof задан Challenge=true и server возвращает TransportChallengeResponse(header nonce). UDP optional: public literal target управляемого echo server, ответ — точный свежий nonce; relay должен быть exact owned SOCKS loopback host/port. Это **SOCKS UDP forwarding**, не routed TUN proof. Timeout сети default8/max20s, весь producer window30s. Нет auto retry/fallback/registration.

После independent P2 review hostname CONNECT заменён fresh bounded A+AAAA DoH по owned path: literal bootstrap `1.1.1.1:443` + verified TLS `cloudflare-dns.com`, не system resolver. Весь DNS set во всех sections проверяется на public, mixed/private/mapped отвергается; один CONNECT к проверенному literal сохраняет original service URL/TLS hostname. SOCKS ATYP3 request больше не создаётся. DNS обеих семей имеет общий window3s внутри network deadline, без cache/retry/fallback; недоступный owned DoH оставляет proof неподтверждённым.

Follow-up VLESS review выявил Go1.26 Transport `WithoutCancel` перед dial. Оба production DialContext теперь восстанавливают private per-request bounded operation context из сохранённого typed value. DoH заменяет outer marker своим DNS child; missing/canceled/unbounded marker отказывает до соединения. SOCKS проверяет deadline до Dial и закрывает stalled greeting/CONNECT при отмене. API caller не добавляет этот marker вручную: его создаёт CLOUD HTTPS/DoH request boundary. [Actual Transport regression для root](CLOUD_OWNED_DIAL_HARNESS_RU.md) использует только opt-in localhost fixtures и не заменяет actual USQUE acceptance.

Полученный typed `receipt.Owned` надо сохранять целиком в existing staged/evidence.json, а не повторно marshaling старую private usqueCanaryEvidence без нового поля. `CanaryEvidence()` намеренно оставляет legacy installed-session BindingID пустым. Нельзя заменить identity текущими installed usque.conf/session.conf hashes. Existing Stop cleanup обязателен; после остановки canary readback не считает его current. После Activate новый live process имеет другой RuntimeID и обязан получить свой explicit owned proof до current-green статуса. Старый receipt остаётся историей и не даёт apply authority.

Receipt сохраняет только trusted producer-owned writer. BindingID связывает runtime identity, а не криптографически удостоверяет Warp/routes/UDPForwarding; safeOwnedEvidence проверяет форму полей. Импорт backup, HTTP/body/UI и произвольный receipt не заменяют producer action или admission. Readback показывает свежесть сохранённых фактов при совпадении live runtime; он не повторяет сетевой challenge и не даёт apply authority.

## Что producer действительно наблюдает

ObserveOwnedUSQUE до/после network вызывает routeidentity.Verify, читает exact config/argv/environ и launcher identity, хеширует **открытый /proc/PID/exe**, сверяет inode с installed binary, проверяет fd→socket inode before/after и bounded tcp/tcp6/udp/udp6 tables. Session hash включает весь приватный engine.json; ArgsSHA включает SNI/transport; secrets/argv/environ в receipt не попадают. Config reader допускает только один JSON object с уникальными lower-case top-level keys: case aliases/duplicates отвергаются, чтобы map и upstream struct decode не выбирали разные pin. Epoch адаптирован из FreshProfile через ValidWANProfileID; смена любой identity/env/binary/socket не разрешает результат.

H2 требует unique owned established TCP peer к exact pin. QUIC upstream использует unconnected wildcard UDP socket: это **не наблюдённый remote peer**. Producer явно записывает PeerObservation=`udp-unconnected-exclusive-config-inference` либо `udp-connected-default-peer`. UDP connect default тоже не является packet attribution. Sock table namespace-wide, поэтому unowned inode вообще не учитывается. Два snapshots не доказывают непрерывное отсутствие короткого reconnect/FD ABA.

## Truthful fallback и release provenance

ProofBasis=`official-release-owned-path-inference`, ProtocolPath=`HTTP/2` или `QUIC`, Negotiated=false. Actual owned WARP TLS trace и service/UDP challenges — наблюдённые факты. H2/H3 программный путь — **inference** из exact official artifact, strict args/config и успешного owned SOCKS flow. Он не выдаётся за экспорт native ALPN, actual QUIC RemoteAddr, CONNECT-UDP или TUN readiness. Legacy `transport_capabilities` не получает confirmed от этого receipt; новый doctor показывает свежие owned WARP/service/UDP факты отдельно.

Поддерживаемый reference — official [USQUE v4.2.1](https://github.com/Diniboy1123/usque/releases/tag/v4.2.1), tag `6aa03fc97d12848dce34eedbd187fb1077b5d1ea`. В source endpoint/branch выбирается однократно: [selection](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/config/endpoints.go), [H2/H3 implementation](https://github.com/Diniboy1123/usque/blob/6aa03fc97d12848dce34eedbd187fb1077b5d1ea/api/masque.go). H2 поддерживает ProxyFromEnvironment — любая непустая HTTP_PROXY/HTTPS_PROXY/ALL_PROXY (case variants) в **actual child environ** запрещает этот proof; лог/текст версии не заменяет проверку. Пустой endpoint_h2_v4 с upstream default также отвергается: candidate должен иметь explicit pin.

Read-only официальный ZIP → memory extraction сверил archive SHA с GitHub asset.digest и [checksums.txt](https://github.com/Diniboy1123/usque/releases/download/v4.2.1/checksums.txt); в код включены **executable**, не archive hashes:

| Linux | Executable SHA256 |
|---|---|
| amd64 | a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10 |
| arm64 | 8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002 |
| mips | c7dd8a80eca37e5e5770073d72c85630d671e6d288214185c2f9bf246f01f59d |
| mipsle | 2b466b9595704c6741472d1ffd17ef004d676871005504401105b5cd277c0dbf |

Release buildinfo содержит vcs.modified=true. Hash подтверждает точный официальный artifact, **не** воспроизводимую чистую сборку из reference commit. SourceCommit в identity — reference tag. Unknown opkg/self-reported version/custom executable не принимается как этот профиль; supported official candidates не требуют новой регистрации. Никакие бинарники не устанавливались/запускались этим чатом. Upstream post-CONNECT hooks существуют, но async/no connection generation/export ALPN; этим checkpoint они не используются как полномочие.

## Проверки и следующий root шаг

Portable fake-proc/network-parser fixtures покрывают identity/config/args/exe/env/FD drift, stale readback, peer ownership/ambiguity/endian, H2/QUIC inference, отдельный UDP challenge, admission revocation, secret-safe errors и отсутствие сетевого действия в disabled/invalid/canceled случаях. Linux test binary cross-compile и unit/vet результаты добавляются в CLOUD_RU.md.

Adapter call/CORE current callback **ещё не подключены**: compilation библиотеки не означает интегрированный action. Следующий bounded owner шаг — VLESS thin bridge + typed receipt retention, CORE Authority/EvidenceRuntime wiring, затем root candidate tests на exact official executable без регистрации: H2 with UDP blackhole; QUIC path; отдельный UDP ASSOCIATE echo; Stop/restart/executable/config/WAN drift. Actual USQUE/MASQUE native run этим чатом не выполнялся.

04.10.2026 dependency coordination: VLESS/CORE получили готовый producer SHA/API и запрос finished hook. CORE подтвердил reuse current `dataplane.WithReviewGuard` seal; missing guard отказывает active capture, GET остаётся local-only. Finished VLESS/CORE hook SHA/root acceptance ещё pending. [Actual USQUE live checklist для root](CLOUD_USQUE_LIVE_CHECKLIST_RU.md) отделяет реальные WARP/H2/QUIC/UDP результаты от protocol interoperability и synthetic fixtures; ledger UNVERIFIED.
