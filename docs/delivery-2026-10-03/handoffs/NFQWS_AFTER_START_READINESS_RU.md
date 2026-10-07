# NFQWS: отдельный read-only этап после Start

Основание: ROOT `nfqws81`, source `65ad25e`, actual paired FAIL 1.55s. Ошибка точно в `empty queue LAN/capture preflight`; live diagnostic до stop показывает корректный running lease, SAME8/argv/birth/netns и зарегистрированную очередь 40321 с mode 2 / range 65531. Повторный before-Start preflight требует empty inventory даже после штатного появления own queue.

## Private API для DEFAULT

В private assembly задать `b.queueReadiness = nfqwsScopedQueueReadiness`. В каждой итерации AwaitQueue вызвать `nfqwsScopedAfterStartCurrent(ctx, b, p, current) (ready bool, err error)`:

- `err != nil`: немедленный отказ с сохранением `%w`, без повторного наблюдения unknown.
- `ready == false, err == nil`: положительно наблюдалась пустая очередь; можно ждать в исходном bounded context.
- `ready == true, err == nil`: наблюдалась единственная готовая очередь reservation, принадлежащая exact child; далее обычный one-shot Prepared.

After-Start этап проверяет bounded context, opening/closing retained Current, SAME running process proof до/после, queue readiness до/после, LAN до/после, AdditionalReadback и все десять classic table reads с прежним absent-capture ruleCounts. Переход empty → exact owned ready во время LAN/rules допустим. Обратный переход owned → empty, изменившийся process proof, любой observed unknown/foreign и ненастроенная очередь дают отказ. Этап не пишет kernel effects, receipt, lock или process intent.

Concrete queue observer проверяет actual namespace и exact live child на обеих сторонах. Каждый inventory sample полностью парсится и классифицируется до следующего: stable empty либо одна exact reserved queue с mode 2 / range ≥65531. Ready queue связана через NETLINK_NETFILTER port ID → inode → exact child fd, с повторным port lookup. Stable owned samples требуют SAME tuple/inode. При empty → owned нужен ещё один stable owned sample. Foreign/malformed/missing/unconfigured sample никогда не становится transient из-за следующего empty image. Это последовательные read-only наблюдения, не атомарный снимок всего ядра.

Existing `CheckNFQWSScopedQueue`, before-Start checks, strict Prepared/Apply/cleanup, managed producer/Start/ECHILD/ACK не меняются. Private callback обязателен только для нового этапа; остальные существующие consumers не получают нового допуска. Production assembly и routercompat не подключены этим owner checkpoint.

## Проверки owner checkpoint

Windows all `TestNFQWSScoped`: PASS 1.812s. Модели включают stable empty/owned, empty → owned во время первого фактического `-S`, all-ten/both-family reads, same process + Current closure, negative foreign/malformed/missing/unconfigured/owned-disappeared/socket-replaced/late-LAN/late-current/changed-child/cancel и отсутствие receipt/kernel mutations. Linux amd64 vet и test cross-compile RC0. Actual native выполняет только ROOT после consumer integration; native PASS этим checkpoint не заявляется.
