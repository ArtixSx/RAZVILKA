# Scoped Xray consumer: XHTTP до DNS и записи

## Граница готовой порции

Это отдельное завершённое расширение VLESS consumer поверх принятого цельного `643ed62`. Импорт, каноническое private-хранилище, reopen/history reader и `nodestore/routes.go` принадлежат XHTTP owner. Его принятый compiler/handoff `b9372bc` / `bd901f6` уже включён обычным merge; незавершённые изменения соседних worktrees не используются.

Consumer не выдаёт новое доказательство работоспособности transport, LAN/TUN, egress или UDP. Запуск actual main/Manager и native acceptance остаются отдельными gates координатора. Runtime допускает XHTTP только на точной установленной версии Xray `26.3.27`, через существующий bounded version producer, без кэширования этого разрешения.

## Последовательность допуска

1. Первый `NodeRoutes` получает копию sealed logical service/node/domain/literal-CIDR intent, ещё без service или endpoint DNS. Реальная factory передаёт это в `MaterializeXray`; актуальная engine-specific eligibility проверяется обычным NodeStore API.
2. До DNS проверяются точный blackhole default, набор выходов, теги, listener/routing scope и исходные JSON bytes. Duplicate keys и чрезмерная вложенность отвергаются. Для XHTTP исходный RawMessage проходит authoritative `ParseXrayProfile` и `ValidateXrayXHTTPSettings`; полный compiled outbound должен семантически совпасть с исходным после допустимой замены scoped tag. Настройки auth/security/flow/download/H3/extra нельзя скрыть map-декодированием или нормализацией.
3. XHTTP требует успешную свежую проверку установленной версии. Caller review authority и отмена проверяются до и после version producer, включая callback, который отозвал разрешение или отменил контекст и вернул nil.
4. После service DNS выполняется второй `NodeRoutes` и тот же полный validator. Seal охватывает упорядоченные outbounds и endpoint metadata: изменение UUID, TLS/REALITY/SNI, transport/path/extra, выхода, тега либо host metadata вызывает отказ до endpoint DNS. Меняться может только routing, точно соответствующий новым разрешённым literal destinations.
5. После обоих materializer callbacks caller authority и закрывающая отмена проверяются для RAW и XHTTP. RAW сохраняет прежний compiler admission и не вызывает XHTTP version RPC.
6. Endpoint DNS получает только validated `settings.vnext[0].address`. Private HTTP headers с именами Address/Server/Endpoint никогда не становятся resolver inputs или policy exclusions. При IP pinning сохраняются original TLS/REALITY serverName, XHTTP host/path/extra.
7. Свежая версия и authority повторно проверяются непосредственно перед первой записью `nodes.staged.json`. `validateNodeFiles` также повторяет gate до endpoint DNS при проверках staged/committed runtime. Старое успешное version observation не разрешает позднюю запись или повторный запуск.

## Bounds и владение памятью

Material config ограничен 4 MiB, число endpoint metadata — 256, host value — 4096 bytes, число scoped outbounds — 65 с первым blackhole. Aggregate bounds проверяются до private copy/decode. Consumer клонирует requests и material buffers; очищает только собственные copies. Буферы, сохранённые producer, не обнуляются.

## Проверка и независимые зависимости

Целевые scoped RAW/XHTTP tests: PASS 4.524s. Покрыты TLS и REALITY, extra headers и original names/path, mixed RAW+XHTTP, duplicate/unknown/malformed transport/security intent, two-pass drift, wrong/missing version, отмена/отзыв разрешения внутри successful callbacks, late third version gate, отсутствие staged writes/Start/kernel mutation, shared producer buffers и aggregate caps. Два независимых source review закрыли XHTTP boundary и реальную Store/factory/Stage последовательность; после дополнительного RAW callback finding выполнен отдельный regression.

Полный dataplane до последней узкой RAW callback проверки: PASS 122.150s. Полный app после принятого CORE fixture isolation `51b91f7`: PASS 228.548s. Окончательный tracked archive проверяется отдельно от общего рабочего дерева; конкретные результаты передаются координатору вместе с commit SHA.

Отдельные принятые commits `02a9909` и `159647e` здесь только зависимости: private Remove registration marker не позволяет Apply retry брать cleanup WAN waiver; readonly cold inactivity допускает действительно отсутствующие engine packages при сохранённом полном отрицательном inventory. Координатор сообщил native cold59 PASS для actual constructors в свежих PID/net namespaces, nil Configs и отсутствующих packages, с отказом на чужих interface/RPDB/FIB/firewall resources без mutation. Native binaries здесь не запускались.

Actual fresh active USQUE health — отдельная CLOUD/VLESS порция; исторический Canary receipt не обновляет timestamps и не подтверждает новый active runtime. Xray DEFAULT остаётся закрытым до отдельного полного source/IPv6/UDP acceptance. Component Router HTTPS acceptance не заменяет actual Manager-issued production acceptance.
