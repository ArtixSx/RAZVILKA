# NFQ domain material: граница принятого кода

16.10.2026. Независимо просмотрены `DOMAIN_WIP_UNACCEPTED/tracked.patch`
и новые `nfq_domain*.go` из overlay. Перенос ограничен strategylab.

Материал удерживает оригинальный SelectedCandidateReview, runtime/control,
отдельные private include/exclude files с FD/inode/образом и отдельное
дочернее состояние compatibility. Старый выбранный кандидат не переписывается.
Оба final argv включают те же пять CORE flags и точные пути. Отдельная tagged
grammar проверяет candidate digest; обычная grammar и CIDR selected issuer
по-прежнему отвергают такой материал. Внешний caller не может передать hostlist
через ExportableArguments.

Это **только compatibility**, а не разрешение domain Apply. Include/exclude
сейчас являются входом этой проверки; они не доказаны как эффективный снимок
активной политики. Поддержан лишь один manual/frozen IPv4 TCP443 candidate,
канонические имена с наследованием поддоменов. Пустой effective include
отвергается; AUTO, exact-only notation, UDP, IPv6 и смешанные профили запрещены.
DNS/TTL/CNAME этим кодом не исполняются.

Неизвестный managed completion возвращается вместе с исходным material:
вызывающий обязан удерживать admission и переданный validation runtime,
повторять RetireCompatibility на этом же объекте. Close при pending отказывает.
RetireKnown закрывает только отдельный validation runtime. Source runtime и
control принадлежат исходному владельцу; Close материала их не закрывает.
После retirement удерживается образ настоящего child receipt, его FD,
идентичности и исходная retired session. Файлы после Close остаются на диске;
они сами по себе не позволяют реконструировать capability.

Найден и исправлен дефект WIP: копия nfqDomainFiles могла закрыть FD оригинала.
close теперь проверяет self identity до доступа к дескрипторам. Регрессия
проверяет отказ копии и сохранность оригинала. Проверяются также пустые и
неподдержанные наборы, bytes/inode/extra-file tamper, обе фазы final argv,
unknown/refusal, отсутствие настоящих owners, pending Close и запрет выдавать
domain review за legacy source. Linux-тест ограничивает FIFO-read отдельным
процессом с timeout; opens имеют O_NOFOLLOW|O_NONBLOCK. Проверка замены parent
одинаковыми bytes требует Linux: Windows запрещает rename удержанного каталога.

Следующие узкие интеграции:

1. Native fixture должен вызвать именно ReviewManagedNFQWSDomainMaterial с
   настоящим source, двумя различными lease и исходным admission/control;
   проверить success/refusal/unknown, повторное retirement, сохранность source
   image и отказ после подмены child receipt/списков. Моделируемый provider в
   текущих argv tests не доказывает этот полный путь.
2. Purpose-specific compiler должен связать include/exclude с точным Store
   image, revision и выбранным Home scope, сохраняя глобальные device negatives
   до queue. Старый CIDR compiler не расширять.
3. Отдельный domain issuer/runtime договор должен удерживать этот material
   через Apply/Stop/Join и проверять именно конечный command. Command сейчас
   возвращает comparison data без intercept/queue/scope capability.
4. Packet oracle на pinned binary: included/excluded/unknown/shared-IP,
   fragmented/no-SNI/ECH/coalescing, исходные DNS/RPDB/чужой nwg0, positive и
   negative counters, payload/headers/multiplicity до/после. Отключение reasm
   и hostname cache пока не является доказательством неизменности baseline.

Локальная проверка: Go1.26.5 Windows `go test ./internal/strategylab`,
`go vet ./internal/strategylab`; Linux amd64 `go test -c` (cross-build only).
Linux FIFO/parent-replacement tests, race и genuine payload/packet tests здесь
не запускались. VM/роутер/сеть не использовались. D07–D09 остаются незавершёнными.
