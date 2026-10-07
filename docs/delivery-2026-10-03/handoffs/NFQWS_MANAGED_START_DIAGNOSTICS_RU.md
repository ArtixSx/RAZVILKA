# NFQWS managed Start: метки этапов отказа

Отдельный owner diagnostic checkpoint поверх `fbd53bceb3da98afae48f12552520afbfcccb2f8`. Не является startup fix или разрешением повторить invocation.

ROOT native91, source `141eb748f32a92e3d18e9a59363b7d3efdf436e0`: отказ до queue-readiness/Apply, command remaining 14.595s, original context healthy, capture receipt отсутствует. BeforeStart/intent pairing прошёл, измеренные retained review callbacks: managed-start 7/failures0 и acquisition 2/failures0. Actual SAME8/inactive/ECHILD/parent ACK assertion тоже прошёл. `ErrExecutionJournal` объясняется закрытием unresolved prepared resource; не доказывает primary ReviewGuard refusal. Два одинаковых ErrManagedUnknown могут быть тем же begin outcome, повторно joined существующим `StartOnce.invoke` seal defer.

## Изменение

Parent READY/PERMIT/STARTED handshake теперь возвращает статический этап отказа: READY receive/frame/Current/context, PERMIT send, STARTED receive/frame/child identity/Current/context. Внутри existing Current closure отдельно отмечены retained Current, helper identity read/change и self-update control. Из available nonsecret cause сохраняется error identity; Linux anonymous socket send/receive также перестаёт терять существующий I/O cause. Сохраняются `errors.Is(ErrNFQWSManagedProcessUnknown)`, original review/context/OS/I/O error causes, точный порядок short-circuit проверок, количество callback/transport calls и одноразовый lifecycle.

Метки не форматируют command/argv, binding/frame contents, control tokens, payload или конфигурацию. Fixed strings находятся в call sites. Не добавляются mutable hooks, callbacks, goroutines, timeouts, retries или новые admission paths. Actual Cmd.Start, helper/child proof, Ready/Permit/Started protocol, original Guard, cancel/stop/join/ECHILD/ACK, receipt/resource fences и caps 15/5 не меняются. После PERMIT любой отказ остаётся Unknown; диагностика не превращает его в ACK/replay permission.

DEFAULT отдельно владеет fixture-only post-settled receipt State/Started/Cancelled/ExitCode/Child-presence log. Его файлы в этот commit не входят. ROOT выполняет один combined native92 после finished pins/review, чтобы получить actual cause вместо blind retry.

## Проверка

16 protocol paths проверяют static stage, ErrManagedUnknown, original cause identity, число READY/STARTED receives, zero-or-one PERMIT, число Current checks, отсутствие formatted command/frame metadata и sealed one-use outcome/no replay. Exact path остаётся successful. Existing canceled late Current, lost ACK, foreign helper/binding/child, helper permit one-use, exceptions/swallowed-error fences и command deadlines также проверены. Windows `TestNFQWSManaged` PASS 0.328s. Linux amd64 vet и amd64/arm64 test cross-compile, diff check PASS. Реальные Linux/native/race/VM процессы здесь не запускались.

Combined Windows managed + scoped NFQ + common PolicyEffectsReceipt PASS 22.392s; Windows vet PASS. DEFAULT fixture-only finished SHA `0d98d61433e92fa43b01d3739a7761e200c7cffa` передан ROOT отдельно; этот owner checkpoint его не включает.
