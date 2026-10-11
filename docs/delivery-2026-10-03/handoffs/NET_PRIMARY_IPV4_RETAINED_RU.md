# NET — исходный primary IPv4 witness после завершения selection context

Дата: 11.10.2026. База `sol/net-20261003`, `9bd6d7fc95f9d48107315af8a261270b8b429130`. Узкая зависимость ACTIVE literalIP Xray вертикали VLESS; synthetic publisher этим не разрешён.

`(*physicalscope.PrimaryIPv4Review).CurrentRetained(ctx context.Context) error` проверяет только уже выданный SAME witness и SAME открытый original Review/Observer. Свежий конечный caller context обязателен. Старый selection callback/context не читается, consent/forward permission не обновляется. App самостоятельно держит актуальные operation/control/CAS/policy guards.

Путь: `VerifyRetainedIncarnation` исходного review → два полных native RTM_GETADDR под SAME provider/fence с полной проверкой флагов/строк/prefix/address incarnation → закрывающий `VerifyRetainedIncarnation`. Ни Review, ни fence, ни original coordinates не создаются заново. Physical uncertainty/drift остаётся sticky и запрещает оба пути. Close присоединяет текущие чтения через original Review mutex и закрытый Review не разрешает новые чтения.

В старом `Current` selection-only отказ теперь ставит отдельный sticky `forwardInvalid` и `Review.invalid`, сохраняя физическую границу для retained observation. `Current` и `Observer.Verify` остаются отозванными даже после успешного retained сравнения. Положительный TCP/listener/effect/cleanup grant из этого метода получить нельзя.

NET меняет только `primary_ipv4.go` и добавляет `primary_ipv4_retained.go`/`_test.go`. RESEARCH подтвердил ownership selected-device projection (`observer.go`, `selected_devices.go`, `neighbors.go`, `wire.go`, `linux.go`, `original_fence_collector.go`, `retained_incarnation.go` и его тесты). Пересечение в `primary_ipv4.go` только три механических вызова старого `fence.check(held, segments, devices)` → нового `fence.check(held, originalSnapshot)`. RESEARCH больше не меняет primary-файл; Root применяет projection pin, затем эту узкую порцию с сохранением нового whole-original-Snapshot ABI. Прочие RESEARCH файлы NET не меняет.

Windows Go 1.26.5, `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`:

| Проверка | Результат |
|---|---|
| `go test ./internal/physicalscope -run 'PrimaryIPv4\|RetainedIncarnation' -count=1` | RC0, 0.340s |
| `go test ./internal/physicalscope ./internal/netidentity -count=1` | RC0, 0.370s / 2.400s |
| `go vet ./internal/physicalscope ./internal/netidentity` | RC0 |
| То же vet `GOOS=linux GOARCH=arm64` | RC0 |
| Linux AMD64 и ARM64 `go test -c ./internal/physicalscope` | RC0 обе компиляции; не native runtime |

Новые tests проверяют canceled selection owner без его повторного чтения, отсутствие replacement Review, четыре физические capture и два address dump, неизменность исходного snapshot/row, sticky physical failure, copied/unissued/closed witness, finite/canceled request и Close/address-read join. Физические/netlink факты — явно частные модели. Native hardware результат не заявляется. Race на Windows не проверен (`CGO_ENABLED=0`).
