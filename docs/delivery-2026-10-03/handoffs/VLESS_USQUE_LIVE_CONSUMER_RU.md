# Actual USQUE consumer: свежее подтверждение выбранного runtime

## Граница готовой порции

Это отдельный VLESS consumer поверх принятых CLOUD `91ed14e`, closing fix `b9cb61e` и readonly identity leaf `f4da266`. Обычные публичные `Health`, `Commit`, `Reconcile` и `RefreshPolicy` теперь вызывают actual owned USQUE live producer через штатный `usque-engine` и постоянный SOCKS listener. Canary остаётся отдельным временным процессом; его JSON не подтверждает текущий активный процесс.

Новый private live IO seam используется только локальными fixtures. Нулевое значение вызывает штатные `ObserveOwnedUSQUE` и `ProbeOwnedUSQUE`. Нет нового HTTP DTO, выдачи разрешения из argv, generic trace, подмены TUN/LAN/egress/UDP или продления исторического TTL.

## Выбор транспорта и сохранение доказательства

1. Перед первым чтением подтверждения или наблюдением обязательны текущий review guard и точный frozen WAN profile. Routes/LAN копируются до первого callback; успешные FreshProfile/Running/probe callbacks не могут скрыть отмену или отзыв разрешения.
2. Candidate Health принимает только `transport.staged.json` из одного абсолютного transaction root; active Health принимает только `transport.json` из private StateRoot. Bounded anchored reader отвергает missing, duplicate/unknown keys, null, неверные типы и unsafe SNI. Нет fallback к package config или preferred transport.
3. Выбранный immutable ProcessSpec используется и для Running, и для SOCKS readiness. Activate и Reconcile recovery запускают и ожидают один и тот же выбранный spec; HTTP/2 не проверяется как QUIC.
4. Каждый Health вызывает producer ровно один раз. Full semantic predicate, current-call timestamp, original TTL и whole typed Owned receipt сохраняются без изменения. Проверяются точные exe/args/session/endpoint/transport/environment и current runtime identity до/после producer и непосредственно перед записью.
5. Selection readback и receipt write используют один anchored owned root; source/runtime/root/selection drift вызывает отказ. После записи выполняется closing review/cancel check.
6. Commit сначала выполняет новый Health, получает private owned copy исходных bytes и перед promotion проверяет действующий receipt/forwarding. Promotion повторно readonly проверяет whole proof и TTL, не вызывает второй producer и не перечитывает staged receipt как authority. Подмена `evidence.staged.json` старым Canary после Health не влияет на promoted proof.
7. Здоровый Reconcile обновляет current proof без Start/Stop или нового Canary. Recovery удерживает исходную committed selection и отвергает её смену до teardown. Forward-authority/WAN refusal не разрешает restart. Same-policy RefreshPolicy также требует fresh Health и closing authority после последних firewall readbacks.

## Closing kernel readback

Независимый CLOUD review исходного `22cc80b` воспроизвёл исчезновение RPDB во время успешного live producer: одной проверки до запроса было недостаточно. Corrective consumer повторно проверяет frozen PolicyState, actual forwarding и RPDB/FIB после producer и последних identity/WAN callbacks, перед заключительными чтениями файлов и сохранением receipt. Runner и LAN callbacks закрываются review/cancel guard до и после каждого вызова. Commit отдельно повторяет этот gate перед policy promotion и ещё раз перед final proof persistence. Ошибка не обновляет receipt и не подтверждает исчезнувшую kernel policy; historical rollback cleanup остаётся самостоятельным.

Повторный review `b5dbf56` воспроизвёл смерть процесса во время последнего успешного kernel readback. После всех policy/review/WAN callbacks consumer теперь вызывает отдельный `verifyOwnedUSQUELiveIdentityWith`: он сравнивает текущую локальную identity с исходной whole proof, включая PID/birth, exe/argv, session, listener и endpoint. Production nil seam вызывает actual `ObserveOwnedUSQUE`; environment callback возвращает только исходный literal EnvironmentID. Этот leaf не вызывает FreshProfile, Running, обычный action observer или второй producer. После него остаются callback-free anchored file/selection/config reads и original TTL перед записью. Смерть и перезапуск с теми же argv отказывают в публичных Health/Reconcile/Commit; ранее добавленные late RPDB cuts продолжают отказывать.

## Несколько source cells одного сервиса

Полный frozen predicate и canonical URL проверяются для каждой raw route cell. До 64 cells могут содержать до 8 различных semantic service probes. Повтор одного service ID с тем же full predicate выполняет один producer probe; различающийся predicate/URL или отсутствующий freeze вызывает отказ до producer. Sources и kernel policy cells не объединяются и не переписываются.

## Проверки и ограничения

Локальные portable fixtures покрывают strict selection, whole receipt, source/process/root/selection drift, WAN/review/cancel callbacks, current-call TTL, private capture и promotion, actual public Snapshot→Stage→Validate→QUIC-failure/HTTP2-Canary→Activate→Health→Commit→Reconcile. Exact-argv fake различает H2 и QUIC. Дополнительно проверяются stopped-H2 recovery и поздний отказ на последнем same-policy RefreshPolicy readback.

Независимые read-only audits закрывают helper, public lifecycle fixtures и выбранный transport. Конкретные результаты окончательного tracked archive передаются вместе с SHA; fixture PASS не выдаётся за native acceptance.

Проверки actual main/Manager, Linux/native TUN, account/live Cloudflare и настоящего hardware принадлежат координатору. В этой worktree native binaries, сеть, account/session и router/VM не запускались. ROOT-owned native QA files не изменялись. Single-owner generic/node Xray dispatcher и held CORE main checkpoint — следующая отдельная порция, не часть этого consumer.
