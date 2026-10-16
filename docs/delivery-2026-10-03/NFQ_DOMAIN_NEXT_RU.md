# Следующая ограниченная вертикаль NFQ: домены по TLS SNI

Дата: 2026-10-16. Это исследование возможности, не разрешение native Apply и не приёмка D07/D08. Production не изменён; роутер, VM и genuine packet execution автор не запускал.

## Вывод

Для обычного открытого SNI nfqws2 может выбирать соединения через собственные hostlist/hostlist-exclude без DNS, SyntheticDNS и преобразования домена в IP. Это перспективный следующий шаг после genuine CIDR Apply/Stop. Но «профиль Lua не выбран» недостаточно для обещания, что посторонний пакет прошёл неизменным: сборка ClientHello выполняется раньше окончательного выбора по имени. ECH и несколько HTTP origins внутри одного TLS-соединения дополнительно ограничивают саму наблюдаемую идентичность сайта.

Текущий CIDR compiler/issuer должен продолжать отказывать доменным и смешанным материалам. NETWORK_POLICY_EXECUTOR_REQUIRED не снимается этим документом. Общий Manager менять для исследования не требуется.

## Первичные источники и точность привязки

Проверенный wrapper pin: `nfqws/nfqws2-keenetic@077f9af6068cd3380527085ca351b503a2dcf926`, пакет 1.3.1. Первичные файлы:

- [README wrapper на этом pin](https://raw.githubusercontent.com/nfqws/nfqws2-keenetic/077f9af6068cd3380527085ca351b503a2dcf926/README.md): режим списков, исключения, поддомены, ограничения видимости ECH/offload.
- [Build recipe на этом pin](https://raw.githubusercontent.com/nfqws/nfqws2-keenetic/077f9af6068cd3380527085ca351b503a2dcf926/.github/workflows/build-nfqws2.yml): при сборке разрешает upstream `releases/latest`, затем компилирует конкретный resolved SHA и встраивает version/hash. Wrapper commit сам по себе **не доказывает upstream commit конкретного ARM64 asset**.
- [Pinned TLS reassembly fastpath patch](https://raw.githubusercontent.com/nfqws/nfqws2-keenetic/077f9af6068cd3380527085ca351b503a2dcf926/patches/001-tls-reasm-fastpath.patch): дополнительное поведение до окончательного чтения имени.

Локальные genuine AMD64 журналы `nfqws-genuine40.log` / `nfqws-genuine-root42.log` показывают upstream `v1.0.5.2`, commit `6b6c63e3385fa73f8af3be4a69171e947f5a319d`. **Это не привязка ARM64 wrapper payload.** Для него root должен сохранить actual compatibility output с version/hash и проверить raw executable SHA256 по reviewed manifest. В текущем reviewed ARM64 manifest raw binary SHA256: `0c97153a2cc72392776fc550bf7be1cec77bc5db2505ab5b9dbc6d071e739c09`.

Для анализа поведения использованы:

- [Pinned upstream hostlist.c, v1.0.5.2](https://raw.githubusercontent.com/bol-van/zapret2/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/hostlist.c).
- [Pinned upstream desync.c, v1.0.5.2](https://raw.githubusercontent.com/bol-van/zapret2/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/desync.c).
- [Текущая upstream документация](https://raw.githubusercontent.com/bol-van/zapret2/master/docs/manual.md).
- [Текущий upstream TLS parser](https://raw.githubusercontent.com/bol-van/zapret2/master/nfq2/protocol.c).
- [Текущий upstream NFQUEUE callback](https://raw.githubusercontent.com/bol-van/zapret2/master/nfq2/nfqws.c).

Ссылки на `master` описывают прочитанное поведение, но не заменяют привязку конкретного установленного бинарного файла. После получения actual ARM64 upstream SHA эти проверки необходимо повторить на нём вместе с применёнными wrapper patches.

## Что подтверждает код

`HostlistCheck_` проверяет исключения раньше includes. Обычная строка включает поддомены, `^host` ограничивает точным именем. Пустые include lists имеют совместимое разрешающее поведение: CORE обязан заранее отвергать пустой positive material. Статическая проверка не должна подменяться AUTO-списком.

`dp_match`/`dp_rediscovery` выбирают профиль по имени текущего conntrack. Без известного имени непустой обычный hostlist-профиль не подходит. Однако это лишь граница выбора профиля: она не отменяет более раннюю обработку пакета.

`--ipcache-hostname` по умолчанию выключен. При включении имя кешируется по IP, поэтому соседние домены на одном IP могут наследовать последнее имя. Для будущего договора нужен принудительный `--ipcache-hostname=0`, без caller override и zero-phase обходного профиля. DNS-пакеты для чтения открытого SNI не требуются.

`dpi_desync_tcp_packet_play` собирает неполный ClientHello до `TLSHelloExtractHost` и окончательной rediscovery. Сегменты могут задерживаться/DROP, затем отправляться raw replay. Патч wrapper при `fastpath-workaround=1` или активированном `auto` может заменять задержанные сегменты на ACK без payload. Следовательно, исключённый или неизвестный hostname не означает автоматически packetwise untouched baseline.

`TLSHelloExtractHost` читает обычный SNI extension 0. Он не расшифровывает ECH inner-name. Уже зашифрованные HTTP origins внутри существующего TLS-соединения также не становятся отдельными SNI.

## Минимальная гипотеза, ещё не production-договор

Один Home physical owner, один manual/frozen NFQ candidate, только IPv4 TCP/443, один непустой canonical include-set и глобальный exclude-set. Устройства и IP исключаются ранними kernel negatives до NFQUEUE. Нет AUTO, IP-hostname cache, дополнительных catchall profiles, UDP/QUIC и IPv6.

Для первого packet oracle стоит проверить `--reasm-disable=tls_client_hello` вместе с `--fastpath-workaround=0`. Это кандидат на более узкий режим: неполный/неизвестный ClientHello передаётся без попытки собрать его, а поддержка таких selected flows не заявляется. **Пока это гипотеза, не доказанная гарантия.** Частичный ClientHello может содержать уже читаемый SNI; все варианты расположения имени и фрагментации нужно проверять на actual bytes. Отключение reasm не делает ECH/coalescing наблюдаемыми.

Поскольку SNI ещё неизвестен при kernel capture, придётся направлять в очередь более широкий набор public TCP/443, чем нынешние literal CIDR destinations. Объём захвата, предел очереди, нагрузка и сохранение baseline требуют отдельного review. Само попадание в NFQUEUE не доказывает ни изменение, ни успешный обход.

## Минимальный genuine packet oracle

Root сначала фиксирует actual executable/asset hashes, version/upstream SHA и точный окончательный argv. Затем в disposable Linux окружении с genuine bytes и реальными NFQUEUE/conntrack использует контролируемые клиент и сервер. Stock router Apply — отдельная последующая приёмка root.

| Сценарий | Обязательное наблюдение |
| --- | --- |
| Два разных открытых SNI на одном IP, один included | Эффект только на выбранном flow; второй не получает чужую hostname |
| Одно имя одновременно include/exclude | Exclude доминирует, нет Lua tamper и лишних outbound packets |
| Parent/subdomain/exact-only, mixed case | Поведение совпадает с canonical catalog semantics |
| No SNI, неизвестный SNI, не-TLS TCP/443 | Проход baseline без fake/split/ACK-only/replay; packet bytes/marks/path сравниваются с контрольным прогоном |
| ClientHello split до/внутри/после SNI, Kyber, retransmission | Нет необъявленного HOLD/DROP/replay; unsupported positive не объявляется доступным |
| ECH с outer-name вне и внутри include, inner-name исключён | Нельзя выдавать inner-domain гарантию; фиксируется реальная граница наблюдения |
| Пустой positive, удалённый/изменённый include/exclude | CORE refuse/retirement по договору; никакого расширения до all-hosts |
| Исключённый MAC, в том числе literal offline exclusion | Пакет не достигает owned queue; остаётся исходный baseline владельца |
| Изменение config/source/component/control, частичный Start, Stop дважды | Исходные owner fences, CAS и retained cleanup сохраняются |

На каждом отрицательном потоке сравниваются pcap до/после, packet multiplicity/payload/headers/marks и фактический route baseline. Счётчиков очереди и логов выбора профиля недостаточно. Genuine compatibility dry-run/Lua подтверждает только совместимость. Полноценную доступность сервиса доказывает отдельный клиентский probe.

## Минимальные места будущей реализации

Не расширять `strategylab.ExportableArguments` разрешением произвольных `--hostlist=/caller/path`. Final argv и файлы должны принадлежать CORE, быть неизменяемым ограниченным материалом и проходить compatibility именно в окончательной форме. Нельзя дописывать неучтённые flags после проверки candidate.

- Новый concrete domain material рядом с `internal/dataplane/nfqws2_active_material.go`: original source/component/control, canonical names/exclusions, protected hostlist lifetime и final argv hashes.
- Purpose-specific compiler рядом с `internal/app/list_nfqws_packet_compile.go` и issuer рядом с `internal/dataplane/nfqws_managed_packet_plan.go`; старый CIDR issuer сохраняет отказ `Domains`.
- Сохранить исходные `ScopeReview`, `IPv4LANPacketScope`, exact Store image, approval revision, material/provider identity, CAS и retained cleanup. Runtime использует существующий managed Apply/Stop; общий Manager не переписывается.

Несколько сервисов с одним candidate позднее могут разделить один физический owner, но требуют original per-service source reviews и closed group material. Разные candidates требуют доказанного порядка профилей и exclusions на каждом. Простое снятие ограничения `len==1` или добавление `--new` не является реализацией.

## Остающиеся ограничения

ECH inner-domain, HTTP/2 coalescing и другие encrypted origins не дают строгого per-request site identity. Первый допустимый договор должен прямо описывать connection/SNI-level выбор либо отказывать, если требуется более сильное исключение. Domain hostlists не обеспечивают обход IP-блокировки и не доказывают работоспособность сервиса. UDP/QUIC, IPv6, mixed engines, hot cutover и полный active-list D07/D08 остаются отдельной работой.

## Read-only проверка first-install без TOOLS/ACTIVATE

Проверен `cmd/razvilka/nfqws_bundle_install_native_linux_test.go`, `TestManagedNFQBundleFirstInstallAppHTTP`. Для этой границы root задаёт только `RAZVILKA_NATIVE_MANAGED_INSTALL_APP=1` и новый пустой canonical private `RAZVILKA_NATIVE_MANAGED_INSTALL_APP_ROOT`; `RAZVILKA_NATIVE_MANAGED_INSTALL_TOOLS` и `RAZVILKA_NATIVE_MANAGED_INSTALL_ACTIVATE` должны отсутствовать. Тест использует `components.New()` с фиксированным production state, а не `RAZVILKA_COMPONENT_STATE` override.

В таком режиме fixture не создаёт Dataplane, default consent или managed list runtime, не вызывает Start/Apply/Stop, не меняет firewall/routes, не запускает opkg или package hooks. Из parent archive выбираются только шесть проверенных binary/Lua/blob members; stock NFQWS executable/init/config/PID и legacy sing files не заменяются. Поэтому работающий stock NFQWS на queue300 и sing не являются конфликтом queue ownership для этого режима.

Но это **не только private files и не только скачивание**. После настоящей установки fixture обязательно запускает compatibility supervisor и genuine payload: сначала `--dry-run --intercept=0`, затем `--intercept=0` с reviewed Lua и сгенерированными assertions. Кандидат фиксирован: `--filter-tcp=443 --lua-desync=fake:blob=tls_clienthello`; это fixture material, не утверждение о выбранной пользователем CLI. У candidate отсутствуют qnum/pidfile/runtime paths; no-intercept контракт проверяется до Lua. Текущий upstream `nfq_main` выходит из no-intercept ветви до NFQUEUE initialization; это необходимо подтвердить actual pinned payload output. Возможны временные процессы/raw sockets и нагрузка, но нет штатного запроса на bind queue300 или сигнал stock process.

Реальные write paths при production defaults:

| Путь | Что меняется и чем ограничено |
| --- | --- |
| `<private-root>/config.json`, `strategy-lab.json` и их file-target metadata | Только новый тестовый App/source; validation receipts и manual/frozen selection остаются здесь, config должен остаться прежним SafeMode=true |
| `/opt/lib/razvilka/nfqws2/releases/.stage-*` → `<manifest-sha256>/` | Собственная staging/generation, root-owned protected ancestry, fixed manifest hashes, atomic no-replace publication; не stock tree |
| `/opt/razvilka/state/components/update-journal/.writer.lock`, `current.json`, `<id>/managed-accepted-idle.json` | Общий permanent component writer lease, durable schema3 journal и terminal archive; при ошибке возможен pending recovery |
| `/opt/razvilka/state/components/receipts/nfqws2-managed.json` | Genuine current managed receipt, CAS/rename под тем же writer lease и original control |
| `/opt/razvilka/state/self-update-stop/.control.lock`, `current-v1.json` | `InitializeSelfUpdateControl` может создать общий control owner, если его ещё нет; existing Stop не сбрасывается, смена epoch прекращает forward admission |

`productionSelfUpdateFiles()` также читает реальные `/opt` deployment identity, self-update/self-update-files и retained controllers. `ComponentHistoryAdmission.CheckWrite(3)` проверяет полный retained fleet; несовместимый/нечитаемый controller или pending/corrupt component/self-update journal — настоящий отказ, обходить его fixture не должен. Проверка может запускать retained controller с закрытым read-version flag. Общий component writer исключает одновременную запись другого updater; долговременный runtime lease также может дать busy/refusal. Self-update/Stop может отозвать control между этапами. Сам факт существования stock queue300 не предоставляет и не отнимает эти полномочия.

При cancelled/failed compatibility сохраняются private source и genuine component journals/receipt для диагностики и штатного recovery. Fixture не доказывает отсутствие всех процессов в parent namespace и не превращает COMPATIBLE в service health. Кодовый аудит подтверждает отсутствие предусмотренных конфликтующих queue/firewall/stock writes; реальную неизменность stock PID/queue/routes/sing root проверяет отдельными before/after наблюдениями.
