# NFQWS Apply: full proof на границе actual RPC

Основание: ROOT `nfqws87`, source `2f0b438`, packet action не достигнут. Apply занял 14.281s и исчерпал исходный command deadline 15s; затем cleanup исчерпал отдельные 5.002s. Все шесть adds успешны, примерно 35ms. В Apply измерены 1831 CLI, LAN.Verify 43 / inclusive 10.040s, ConsumerCheck 54 / inclusive 7.246s, original Guard 128 / 109ms. Inclusive времена вложены друг в друга; их нельзя суммировать как wall time.

## Ограниченный owner checkpoint

Меняются только NFQ scoped Apply/private readback/helpers и owner tests. Common receipt protocol, DEFAULT assembly/instrumentation, LAN, managed producer, CORE actual Start admission и caps 15/5 не меняются. Remove/settlement также остаются прежними.

- Три common Guard на effect сохраняют original ApplyGuard и все retained resource/phase/effect/current проверки. Guard больше не добавляет повторный full namespace scan.
- Preflight и **оба** ExactPresence остаются full. Их foreign/unknown/duplicate правила не ослаблены.
- Private Apply-only Runner принимает только однозначный exact tool + frozen compiler Add. Common receipt уже сохранил durable intent. Wrapper не открывает второй receipt, не выдаёт authority по метаданным и не определяет фазу счётчиком callback-вызовов.
- Перед actual base.Run идут original Guard и full live process/ready queue/LAN/namespace proof. После closing LAN callback собирается ещё один свежий full rules image: partial shape, exact prefix `j<i:1; j>=i:0` и Needs проверяются чистыми predicates в этом одном image. После него не вызывается другой Guard/LAN callback. Более ранний image не переносится через closing LAN callback.
- Actual base Runner продолжает consume CORE admission на Cmd.Start. После successful RPC свежий target family/mangle `-S` проверяет exact local prefix и cardinality результата. Это не whole namespace/следующий RPC grant. Missing/duplicate/malformed/read failure/cancel после RPC возвращают error, common engine сохраняет intent/Unknown вместо ACK. Error-after-mutation не нормализуется.
- Последний original Guard выполняется **до** final full COMPLETE readback. Удаление body или foreign insertion внутри nominally successful closing Guard не даёт false final success. Fault(add/added) после wrapper тоже закрывается следующим fresh full boundary либо final COMPLETE.

## Чтения и измерения

Для successful Apply с N effects direct full readRules: `5N+4 → 4N+2`; full owner process/LAN readbacks: `3N+4 → N+2`; дополнительно N fresh post-target reads. Добавленный final prefix scan сохраняет безопасность при closing callback drift и намеренно повышает стоимость против исходной design-оценки `3N+2`.

Для native six-effect fixture: 34 → 26 direct full readRules, 22 → 8 full owner readbacks, 44 → 16 LAN.Verify; 544 → 422 direct classic/version/nft read CLI, прежде чем учитывать nested consumers. С неизменённым live per-row ConsumerCheck source estimate всего read CLI около 1912 → 934 (+6 mutation CLI в обоих случаях). Это successful-path расчёт, не measured speedup. ROOT должен проверить actual counts/wall и packet action.

Cleanup в `nfqws87` выполнил пять deletes, но оставил IPv4 declaration cleanup-intent после 784 CLI и отдельного 5s limit. Этот checkpoint cleanup не ускоряет и не превращает Unknown в PASS. Packet acceptance, final removal и settlement остаются отдельными обязательными ROOT gates.

## Верификация

Windows all `TestNFQWSScoped`: PASS 2.804s; combined NFQ scoped + common `TestPolicyEffectsReceipt`: PASS 16.193s. Windows и Linux amd64 vet, Linux amd64/arm64 test cross-compile и diff check прошли. Новые модели проверяют точные scan counts, late foreign queue во всех десяти table/family combinations после второго ExactPresence, missing earlier ACK/future exact copy, callback drift прямо перед attachment, post-RPC absent/duplicate/unknown/read failure/cancel/error-after-write, wrong/deletion/ambiguous wrapper command и четыре closing Guard cuts. Existing cleanup/unknown/no-replay/ECHILD/queue guards сохраняются. Native здесь не запускался.
