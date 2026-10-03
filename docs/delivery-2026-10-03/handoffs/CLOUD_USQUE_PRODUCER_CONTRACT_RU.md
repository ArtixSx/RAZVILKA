# CLOUD → CORE/VLESS: actual USQUE producer freshness

04.10.2026, read-only audit исходников `4d15788`. Это предложение wiring на существующем root и `evidence.json`; runtime/CORE файлы не изменялись. Новый apply/enrollment authority из diagnostic receipt не создаётся.

## Уже доступные поля

| Источник | Что подходит для binding и origin |
|---|---|
| `dataplane.ProcessSpec` (`process.go:18`) | Binary, полный Args, MatchArg, Dir, PIDPath и RouteProof задаются managed launcher; origin `managed-usque-canary` можно присвоить только этой доверенной ветке |
| `routeidentity.Receipt` (`runtime.go:19`) | PID, BootID, StartTicks, Executable, ArgsHash, ConfigHash. RouteProof=true уже создаёт `engine.pid.identity.json`; пути/PID недостаточно без текущей проверки |
| `routeidentity.Verify(canaryRoot,"usque",SOCKSAddress)` (`runtime.go:104`) | Проверяет current receipt/config/args, process identity, network namespace и owner SOCKS listener; Passport.ID меняется при runtime/listener change. Вызвать до/после WARP/service probe и сравнить ID |
| `systemprobe.FreshWANProfile(ctx)` / `ValidWANProfileID` (`network_epoch.go:33`/`:24`) | Свежий token меняется при наблюдаемом WAN/DNS/route event, reboot, observer restart/error. Для existing EvidenceEnvironment пригоден SHA-256 канонического JSON `["usque-environment-v1",profile.ID]` после проверки ID и ошибки; перечитать до/после probe и при readback |
| `canary/engine.json` + фактические CLI args (`proxy.go:434`, `:1165`) | Точные private candidate bytes; `--http2` и `-s` задают transport/SNI. ConfigHash и ArgsHash из проверенного launcher receipt входят в identity, а не публикуются вместе с private config |

Существующий `FreshProfile` у adapter и CORE helper подходят для trusted callback. Cached profile, receipt-provided environment, UI request и passive observer не заменяют текущий epoch. Token не видит скрытую upstream смену внутри DNS forwarder/reconnect без OS event; этот практический предел сохраняется.

## Пробелы текущего producer

`ProxyTunnelAdapter.checkRouteNetwork` (`proxy.go:156`) сейчас пропускает USQUE; вокруг `runCanaryAttempt` runtime passport проверяется только у scoped Xray (`:511`, `:573`). `usqueCanaryEvidence` (`:92`) содержит только legacy CheckedAt/Transport/Warp/trace/routes. Transport записывается из выбранного CLI (`:481`), не из native negotiated proof. WARP trace через SOCKS (`:1726`) подтверждает WARP/egress, но не connected peer и negotiated MASQUE H2/H3.

`Executable` receipt — путь, **не digest исполняемых bytes**. Producer должен сверять actual launched executable digest до/после окна, вместе с runtime identity. Список endpoint_v4/v6/h2v4/h2v6 в config, direct route exclusions и trace EgressIP не являются фактическим remote peer. Нужны exact public pin и trusted native observation успешного MASQUE транспорта, без скрытого endpoint/family/fallback. Пока таких данных нет, capabilities остаются unknown.

## Семантика reader

Existing `usquediag.CanaryBinding` привязывает **installed legacy config/session/binary hashes** и trusted environment digest. `Manager.Check` читает `ConfigPath`/`SessionPath`/binary и использует эти hashes (`usquediag.go:475`). Временный managed canary использует иной transformed `engine.json` и CLI selection; подставлять его hash вместо legacy session SHA в ту же функцию нельзя.

Для producer нужно согласовать typed current-runtime binding с reader: origin + проверенный Passport.ID/config/args + actual binary digest + current environment + connected endpoint + negotiated transport. Exact serialization/domain/version и reader callback пока не реализованы; существующий installed-session reader не должен принять candidate receipt с иной семантикой. Если retained receipt отражает уже закрытый canary, новый live runtime обязан заново доказать соответствие или receipt остаётся historical.

После согласования receipt в existing `evidence.json` может получить BindingID, Endpoint и ValidUntil не позднее CheckedAt+5m. Сначала producer получает текущий origin/env/runtime/binary/peer/transport, затем WARP/service proof, затем сверяет всё повторно и пишет receipt; reader вычисляет current binding независимо. Unset callback, mismatch, expired time, runtime restart/Stop/rollback, иной executable/session/SNI, endpoint fallback или неизвестный peer сохраняют diagnostics без confirmed. Корректный clock и монотонная продолжительность окна также нужны; payload timestamp не является полномочием.

H2 подтверждает только H2; QUIC/H3 подтверждает свой транспорт и UDP до этого peer. Generic UDP forwarding/CONNECT-UDP benefit нельзя вывести из WARP trace или H3 HTTP request. `TransportProbeEvidence` локального harness не конвертируется в `CanaryEvidence`: он не подтверждает MASQUE/WARP.

CORE: `main.go` задаёт EvidencePath в настройке USQUE диагностики, но не EvidenceEnvironment. Его можно подключить к имеющемуся FreshWANProfile; это само по себе не закрывает producer/peer/binary пробелы. VLESS владеет dataplane/proxy, CORE — startup/manager wiring; CLOUD сохраняет fail-closed reader и не меняет их файлы.
