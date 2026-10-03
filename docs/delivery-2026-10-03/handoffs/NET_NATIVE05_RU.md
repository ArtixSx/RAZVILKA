# NET — native-round-05: изоляция отказов и kernel capture

Base: `99ac304778f881bab24692f9d87f880d41da4d09`, ветка `sol/net-20261003`.
Координатор передал read-only `delivery-review/.review-local/native-round-05.log`.

Фактический независимый Linux результат: **D04 TestWGNativeCandidateIsolation PASS IPv4/IPv6 + live-after**, **D05 TestWGNativeEndpointLifecycle FAIL**. В D05 IPv4 Canary TCP timeout 8s, затем IPv6 Stage отказал с `endpoint WAN route is not unique`. В логе нет kernel-state непосредственно во время failed probe; по одному timeout нельзя достоверно выбрать между handshake/bootstrap/RPDB/server path. Успех D05 не заявляется.

Этот отдельный коммит исправляет две наблюдаемые проблемы стенда, без ослабления production:

- Каждое семейство D05 теперь получает собственную полную topology в отдельных test-owned namespaces. Cleanup зарегистрирован у родительского subtest и выполняется после child exit/t.Fatal. Failed IPv4 больше не может передать IPv6 собственный interface/policy/Noise-state. Успешные rollback/Stop и preservation foreign host route по-прежнему проверяются самим тестом, изоляция не заменяет эти assertions.
- При failed service probe выполняется bounded read-only capture **до production Canary cleanup**: iproute2 link/address/rules/all tables, оба unmarked endpoint lookups, candidate source+oif lookup, WG public-key/peers/endpoints/handshake/transfer/fwmark и rp_filter. Также снимается server state до cleanup; родитель снимает client/server после failed subprocess, а child — финальное состояние при t.Fatal. private-key/preshared-key/showconf/dump не вызываются.

Локально: Go1.26.5, GOMAXPROCS=2, GOFLAGS=-p=2; Linux/amd64 `go test -c ./internal/dataplane` RC 0; gofmt и `git diff --check` RC 0. Новый native запуск из рабочего чата не выполнялся. Production файлы не менялись.

**Точный запрос координатору:** повторить только `RAZVILKA_WG_NATIVE=1 go test ./internal/dataplane -run '^TestWGNativeEndpointLifecycle$' -count=1 -v -timeout=4m` в том же exclusive Linux окне и AppArmor-approved TMPDIR. Не наследовать `RAZVILKA_WG_NATIVE_ROLE/ROOT/READY/RECOVER_ROOT/ENDPOINT/NOW/TEST_ENDPOINT/SERVER_NS`. Передать новый read-only лог. Нужны строки capture обеих сторон с endpoint/handshake/counters, kernel route-get JSON и RPDB, включая IPv6 Stage. Это диагностический checkpoint, **не исправление неизвестной причины timeout и не D05 PASS**.

D06/D08/D09 не начаты до адресного разбора этого сбоя; read-only изучение D06 выявило отдельные требования строгого loaded module/ABI/CLI receipt, они не смешаны с данным коммитом.
