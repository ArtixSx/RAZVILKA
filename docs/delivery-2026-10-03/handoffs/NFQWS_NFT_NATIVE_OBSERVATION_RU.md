# NFT netlink: opt-in QA observation, без capability grant

QA-only checkpoint поверх `a9b8bd09b4214e89e96c5fcdf9c62366406a46bb`. Новый Linux test + этот handoff; существующие production backend/socket/Generation/Tables/decoder и policy не меняются. ROOT самостоятельно review/build/run на VM/router. NFQWS owner выполняет только source review, vet и cross-compile; никаких actual Linux/router/VM/netlink запусков здесь.

`TestBackendNFTNativeObservation` по умолчанию SKIP до `RAZVILKA_BACKEND_NFT_OBSERVE_NATIVE=1`; при opt-in требует euid root. LockOSThread удерживается до Close fresh `openBackendNFTSocket`. Используется прежний `backendInventoryTimeout=2s` context и original three-request budget: Generation A → Tables(A) → Generation B, final equality, затем Close. Тест не вызывает endpoint/proc identity provider, CLI/nft, module commands, batch/mutation, setns или второй decoder. Namespace provider ещё не принят; actual socket thread scope отдельно проверяет ROOT, этот тест не выдаёт NamespaceCheck/capability.

GET может вызвать kernel request_module. Существующий NONBLOCK/context ограничивает userspace poll/receive, но не preempt synchronous kernel handler/autoload; hard preemption не заявляется.

## Исходы и приватность

- PASS `outcome=validated-complete`: original decoder успешно закрыл оба ACKed GETGEN и полный all-family GETTABLE dump; поколения совпали и ctx healthy. Выводит только число complete GEN reads и complete tables, без generation values/table names/family identity или raw packets.
- PASS `outcome=validated-negative-kernel-ACK`: original decoder вернул именно `backendNFTKernelError` с validated code 1..4095 и errBackendInventory identity при healthy ctx. Static request kind указывает GETGEN_A, GETTABLE или GETGEN_B. Это packet observation отрицательного ответа, **не** NFT absence, unsupported profile, ownership или deletion permission. `complete-*` counts относятся только к ранее успешно завершённым API reads; не утверждают отсутствия partial GEN/table frames перед ошибкой.
- FAIL `outcome=generic-unknown`: любые прочие open/decoder/kernel syscall errors, bare errno, malformed/foreign/truncated/incomplete response, ctx cancellation/deadline, generation drift или Close failure. Raw error/payload не печатается. При disabled opt-in никакое наблюдение не происходит.

Допустимые поля: ASCII-sanitized bounded `uname.release`, static request/contract, validated ACK code, complete counts, stable-generation flag и всегда `capability=ungranted`. Нет raw table names, generations, PID/port/sequence, boot/netns IDs, argv, token/config/payload.

**Важная граница будущего classifier:** нынешний error-only decoder может вернуть typed negative ACK даже после ранее полученного valid GEN/ACK в том же обмене. QA observation не меняет это и не требует sole-error proof. Будущий NoRegisteredNFTSubsystem grant должен отдельно проверять GETGEN request kind, exact sole expected negative error и отсутствие earlier success/contradictory frames/datagrams. `errors.As(Code22)` недостаточно. Vendor `-EINVAL` meaning/absence contract остаётся отдельной RESEARCH/ROOT review задачей; здесь он не закодирован.

## ROOT build/run

Обычный existing package test binary допустим: `go test -c -ldflags='-s -w' -o nft-observe.test ./internal/dataplane`. ROOT выбирает actual GOARCH/ABI только по проверенной target platform. Запуск ROOT-only с explicit env и exact test regex: `RAZVILKA_BACKEND_NFT_OBSERVE_NATIVE=1 ./nft-observe.test -test.run='^TestBackendNFTNativeObservation$' -test.v`. Не запускать остальные native fixtures этим QA opt-in.

Для маленького binary можно создать Go overlay, удаляющий **только остальные** `internal/dataplane/*_test.go` из build view (`Replace` path → empty string). Сохранить `network_backend_inventory_nft_native_linux_test.go`; все production files остаются исходными. Затем тот же `go test -c -overlay=overlay.json -ldflags='-s -w' ... ./internal/dataplane`. Это не copied decoder/helper и не изменение repo source: linker убирает недостижимый код и остальные test registrations. JSON paths относительные repo-root с `/`; ROOT заново генерирует overlay из своего принятого integrated pin, не переносит локальный список тестов в другой tree.

Пример генерации ROOT-side с Python stdlib из **tracked** exact pin:

```python
import json, subprocess
keep = "internal/dataplane/network_backend_inventory_nft_native_linux_test.go"
paths = subprocess.check_output(["git", "ls-files", "internal/dataplane/*_test.go"], text=True).splitlines()
assert keep in paths
with open("nft-observe-overlay.json", "w", encoding="utf-8") as target:
    json.dump({"Replace": {path: "" for path in paths if path != keep}}, target)
```

Source/vet и full Linux amd64 test cross-compile PASS; minimal existing-package observation-only overlay amd64/arm64 cross-compile со stripped symbols PASS. Native packet path, negative ACK и positive complete path здесь не исполнялись; actual platform outcomes подтверждает ROOT после review.

В этом owner tree full Linux amd64 test binary 25,224,970 bytes; minimal amd64 5,722,274 bytes, minimal arm64 5,439,650 bytes. Это compile artifact sizes этого pin, не обещание размера ROOT integrated/router build. Локальный overlay и binaries находятся только в ignored `.hil/nfqws/nft-native-observation`; commit содержит лишь новый test и handoff. Production backend diff пустой.
