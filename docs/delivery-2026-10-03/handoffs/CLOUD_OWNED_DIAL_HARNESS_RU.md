# CLOUD: regression deadline через настоящий HTTP Transport

04.10.2026. Исправление blocker после DNS boundary `a0b8cec`. Production Go1.26 Transport перед dial вызывает `context.WithCancel(context.WithoutCancel(ctx))`: значения сохраняются, отмена и deadline исходного request context снимаются. Переданный напрямую SOCKS handshake поэтому отказывал до greeting; DoH также терял shared DNS window3s.

## Исправление

Каждый HTTPS/DoH request несёт private typed marker со своим ограниченным operation context. Оба production DialContext восстанавливают именно этот context; missing, canceled или unbounded marker даёт отказ без fallback. DoH request заменяет inherited marker текущим DNS child, поэтому outer network window не расширяет его 3s. Public DNS set, literal CONNECT, original TLS hostname, proxy/redirect запрет и production trust roots сохранены.

SOCKS command проверяет deadline до Dial и закрывает соединение при отмене во время greeting/CONNECT. Deadline остаётся на socket; обычная HTTP cancellation и общий owned network cleanup ограничивают дальнейшие TLS/body effects. Новая private HTTP transport factory используется самим producer, а не только fixture.

## Portable и native regression

`owned_probe_dial_context_test.go` проверяет context values после WithoutCancel, отмену, deadline, nested DNS override и отказ без marker в памяти. Native файл `owned_probe_dial_context_native_test.go` по умолчанию SKIP и запускает только приватные localhost TCP/SOCKS/TLS fixtures через настоящий `http.Transport` и обе production factories. Fixture SOCKS сопоставляет ожидаемый public CONNECT literal с локальным TLS сервером; он никогда не соединяется с внешним IP. Test CA добавляется только в fixture clone TLS config.

Root должен проверить success с фактическим SOCKS greeting/literal target и TLS hostname, отсутствие соединения без marker, stalled greeting/CONNECT cancellation с EOF у server, bounded deadline, неправильные TLS name/trust и вложенный DNS3s при outer20s. Полный список leaf results сохраняется с точным combined source SHA; relevant SKIP не считается PASS.

Эти fixtures не запускают USQUE, не наблюдают owned procfs identity и не дают WARP/MASQUE/UDP/service semantic acceptance. Они проверяют работоспособность и cancellation границы HTTP/SOCKS. Actual USQUE root ledger остаётся отдельным: [CLOUD_USQUE_LIVE_CHECKLIST_RU.md](CLOUD_USQUE_LIVE_CHECKLIST_RU.md).

## Запуск для root

Linux source window с этим finished CLOUD commit:

```sh
RAZVILKA_NATIVE_CLOUD_OWNED_DIAL=1 GO=/path/to/go sh scripts/test-cloud-owned-dial.sh
```

Адресно:

```sh
RAZVILKA_NATIVE_CLOUD_OWNED_DIAL=1 go test ./internal/usquediag -run '^TestNativeOwnedHTTPDialContextHarness$' -count=1 -v -timeout=60s
```

Без opt-in runner отказывает RC2 до Go, native test SKIP. CLOUD выполнял только portable unit/vet, syntax и Linux cross-compilation; binaries здесь не исполнялись. Root сообщил `cloud-bundle-native42`, combined source `8a3ade8`, RC0: actual localhost HTTP/DoH Transport/SOCKS/TLS, все17 leaves PASS, включая cancel/deadline/TLS-name/trust/DNS child3s. Это приёмка deadline fix `a5d168b` до последующей semantic response порции; её новые network/body изменения требуют отдельного root review/run. Genuine USQUE/WARP этим checkpoint не проверен. VERSION/go.mod/go.sum и consumer/receipt backend не меняются.
