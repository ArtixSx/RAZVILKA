# D13: native USQUE front door, независимая CLOUD-подготовка

База: `c0c235255f32069f87765fe2f755641f3fe434b0`. Добавлены только новые CLOUD-файлы. Main, shared dataplane и существующие producers не изменены. Native, аккаунт, регистрацию, процессы USQUE и сетевые пробы CLOUD не запускал.

## Готово

`cmd/usque-owned-native` и `internal/usquediag/nativeaccept` собираются отдельно. Нужны явный `--run-existing-account`, ровно один `--mode h2|quic`, абсолютные canonical paths, SHA256 executable и существующего account JSON, приватный существующий `--work-parent`, loopback port >=1024. Проверка ограничена 1–30 секунд, cleanup отдельным original retained grant — 1–5 секунд. Parent deadline не расширяется для самой проверки.

Production defaults используют именно `usquediag.ProbeOwnedUSQUE`, `usquediag.ObserveOwnedUSQUE`, `systemprobe.FreshWANProfile` и общую audited allowlist/strict session grammar. H2 требует явный `endpoint_h2_v4`; QUIC — `endpoint_v4`. Используется exact adapter argv `-c <private stage>/engine.json socks -b 127.0.0.1 -p <port> --always-reconnect -S [--http2]`. Process environment передаётся явно, с пустыми proxy variables. Account source читается ограниченно и не изменяется; stage создаётся отдельно с `0700`, engine.json эксклюзивно с `0600`. Binary и config проверяются по SHA и incarnation. Root descriptor проверяется до записи секретов и при readback/cleanup.

Одна попытка без direct-control, fallback, scan-masque, регистрации, подмены паспортов или загрузки saved evidence. После реального producer заканчиваются все внешние authority/epoch/stage callbacks, затем выполняется отдельный local identity leaf с уже проверенным environment ID. Проверяются original CheckedAt/ValidUntil, exact argv/config/binary/endpoint/WAN binding и `OwnedEvidenceFresh`. JSON содержит фиксированные коды и allowlisted public hashes/proof fields. Raw error, account, argv, paths, trace body и log не выводятся.

Observation — исторический результат на момент проверки. После успешного settlement child остановлен; при неуспешном cleanup settlement остаётся pending. Output не утверждает, что tunnel всё ещё current. `official-release-owned-path-inference` остаётся inference; `negotiated=false`, подтверждение ALPN, generic UDP, TUN, router readiness и service confirmation не заявляются. Original TTL не обновляется.

Cleanup всегда относится к тому же Execution, включая partial Acquire/Start. Требуются StopAndJoin и отдельный VerifySettled с exact birth/session, join/ECHILD/ACK и receipt-owned settlement. При ошибке secret сохраняется и Release не вызывается. После settlement удаляется только свой engine.json; replacement file/root не удаляется. Logs/receipts сохраняются приватно. Recursive cleanup отсутствует.

## Конкретный блокер CORE

CORE подтвердил: на этой базе нет finished/exported generic original-execution USQUE process/namespace factory. `OSProcessController.Start` и self-update barrier не являются такой authority; Xray/NFQ factories относятся к своим adapters.

`nativeaccept.Issuer` / `Execution` / `Launch` — явная pending integration seam, **не реализованный grant**. Необходимо подключить настоящий owner API, который удерживает исходные review/control/actual namespace bindings, immutable program/assets/argv/environment, Current с новым bounded context, one-use admission у actual Cmd.Start, genuine owned passport и listener readiness, exact child settlement и retained cleanup/recovery scope. Actual start admission должна быть короткой; readiness не держит общий control lock. CORE должен pin/retain staged namespace/assets под тем же execution, включая partial errors и recovery.

`retainedCOREIssuer()` в CLI сейчас всегда nil. Нет mutable registration hook, ambient process controller, флага выдачи grant, JSON grant или permissive production callback. CLI возвращает exit 3 до чтения account, native epoch IO, stage, процесса и сети (на Windows — native-linux-required). Actual native H2/QUIC и закрытие D13 **ещё заблокированы** до concrete issuer и review Root. Интерфейс нельзя считать evidence этого issuer.

## Проверка Root

Pure QA без account/process/network:

```sh
unset RAZVILKA_NATIVE_CLOUD_TRANSPORT RAZVILKA_NATIVE_CLOUD_OWNED_DIAL RAZVILKA_NATIVE_CLOUD_RETENTION
GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2 GOPROXY=off \
  go test ./internal/usquediag/nativeaccept ./cmd/usque-owned-native ./internal/usquediag \
  -run '^(TestRun|TestArguments|TestAssets|TestCommand|TestOwned(Native|Producer|Capture|SelectedEndpoint|Environment))' \
  -count=1 -timeout=120s
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/usque-owned-native
```

Fixtures с synthetic authority/identity существуют только в pure tests и не сохраняют owned passport/receipt. В Windows QA пропускаются POSIX private-mode и rename-open-root fixtures; Linux test binaries собраны, но CLOUD их не выполнял. Root должен выполнить эти чистые filesystem fixtures на Linux. Команда не запускает genuine native acceptance до подключения concrete issuer. После wiring Root отдельно принимает existing-account H2 и QUIC в одинаковом ограниченном сценарии; закрытие D13 требует фактических producer/readback/settlement outcomes.
