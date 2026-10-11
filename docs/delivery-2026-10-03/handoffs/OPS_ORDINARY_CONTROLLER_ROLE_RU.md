# OPS: обычная группа обновлятора 0.20.0 → выше

11.10.2026. Отдельный API, без расширения bootstrap-роли и без новой приёмки старых версий:

```go
func (a *SelfUpdateFileAdapter) VerifyOrdinaryInstallerControllerRole(ctx context.Context, id string, pid int) error
func OriginalOrdinaryInstallerControllerAdapter(ctx context.Context, id string) (*SelfUpdateFileAdapter, error)
```

Reader проверяет production paths/root ownership, полный seal обычного review2 с paired reader proof4, растущие версии от 0.20.0, current helper identity, независимую неактивность старой панели и отсутствие PID file. Настоящие `/proc` boot/birth/exe/argv/parent читаются для всей группы helper → quiesce supervisor → child, включая самого наблюдателя и peer; затем повторяются review/header, identity, command, file receipt и все живые process facts. Cold observer, borrowed ID, иной command/parent, changed birth, bootstrap review, reader3, cancelled context или изменившийся seal приводят к отказу. Это классификация процесса, а не доказательство отсутствия sockets/kernel/effects.

После actual direct-child exit 0 и `wait4(...)=ECHILD` обычный command worker делает один synchronous runtimeInactive вызов с приватной capability на исходном конечном контексте. Capability привязана к оригинальному adapter, неизменному running command и actual reaped count; self seal запрещает копию. После callback capability отзывается. Reaped JSON/PID absence/cold context её не восстанавливают. В этом вызове reader доказывает живые helper/supervisor; ушедший child не получает роли. Bootstrap callback/reader не менялись.

Accessor нужен CORE потому, что текущий runtime callback создаёт новый adapter. Контракт:

- `(nil, nil)`: конечный контекст не содержит ordinary joined capability. Live child использует свой локальный adapter и полный reader требует живую группу.
- `(original, nil)`: capability сейчас действительна, actual caller — её supervisor, production roots защищены. CORE передаёт этот **тот же** adapter и исходный callback ctx/id в отдельный ordinary provider.
- `err != nil`: present-invalid owner либо некорректный/истёкший контекст. Fallback к bootstrap или реконструированному owner запрещён.

Существующие Main/DP не изменены. CORE подключает API в новых ordinary provider и genuine helper callbacks; `BindInstallerControllerRoles` bootstrap остаётся отдельным строгим путём. Root подтвердит настоящую future update цепочку после wiring. Canonical path relocation `/opt/razvilka` следует отдельным согласованным pin.

Windows portable ordinary/negative tests PASS; полный updatecheck PASS (99.183s) до добавления accessor, затем focused accessor/ordinary PASS (4.471s). Windows vet и Linux AMD64/ARM64 vet/test-c проверяют финальный исходник. Native test source `TestNativeOrdinaryJoinIsProducedAfterActualAllChildWait` использует реальный subreaper/exec/wait4 с detached delayed child, но synthetic quiescer и private fixture paths; это producer-boundary test, не production acceptance. OPS Linux ELF не запускал. Root выполняет native test и настоящий manual/automatic 0.20.0 → выше отдельно.
