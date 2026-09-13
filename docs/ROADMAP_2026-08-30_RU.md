# Актуальный план RAZVILKA

Обновлено 13 сентября 2026 года. Текущая линия исходников —
**`0.18.2-rc.1`**, исправленный DC1; стабильный канал — `v0.18.0`.
[Статус](CURRENT_STATUS_RU.md) отделяет реализованный код от аппаратной приёмки.
[DC1 review](DC1_REVIEW_2026-09-13_RU.md) описывает исправления исходного импорта.

## Ближайшая очередь

1. **Выпуск и установка `v0.18.2-rc.1`.** Проверить точный релизный commit,
   четыре сборки, пакеты и установку/запуск финального бинарника на роутере.
   Итоги публикуются в `VALIDATION_RU.md` на странице выпуска. Успешный
   [Linux CI исходного `09730c7`](https://github.com/ArtixSx/RAZVILKA/actions/runs/34779255292)
   подтверждает свой commit, а не автоматически последующую сборку.
2. **Аппаратная устойчивость основного управления.** Подтвердить выбранные
   резервные узлы и AWG/WARP на реально работающих профилях, WAN reconnect,
   перезагрузку, потерю собственного runtime, отмену и откат. Сохранить
   отрицательный контроль другого клиента и проверку чужих ресурсов.
   Отдельно проверить IPv6 HTTPS, малую память и 24–72 часа автономной работы.
3. **DC2 — единая проверка DNS и сервисного маршрута.** Связать ответ DNS
   (публичные IP, TTL, CNAME, семейство адресов и поколение настроек) с точным
   маршрутом и запросом сервиса с исходным TLS/Host. Учитывать, кто и по какому
   пути получил DNS-ответ; DNS-only результат не разрешает применение.
4. **DC3 — применение DNS к выбранной области.** Реализовать исполнитель
   с проверкой конфликтов, чтением фактического состояния, TTL/cache,
   транзакционным откатом и отрицательным контролем клиента вне области.
   Не подменять его сохранением DNS-черновика.
5. **DC4 — ограниченный автоматический выбор пары.** Выбирать DNS/маршрут
   только после общей проверки, сохранять последний рабочий вариант,
   сериализовать изменения и отвергать устаревшее поколение результата.
   Ручное управление имеет приоритет; работа не зависит от открытого браузера.
6. **Облачные подсказки — отдельные этапы CI1–CI4.** До сетевого подключения
   нужны сохранённая защита от отката версии каталога, сроки и отзыв записей,
   ротация ключей, ограниченный выбор из разрешённого локального реестра,
   отдельное согласие на отправку и защита от отравления данных/поддельных
   участников. Сейчас `recipehints` остаётся офлайн-компонентом без загрузки,
   телеметрии и права применять маршруты.

Подробные контракты DNS/Community сохранены в
[едином плане DC1](DNS_COMMUNITY_UNIFIED_DC1_RU.md).
Существующие NodeStore, подписки, очереди заданий, управление компонентами и
проверки владения NFQWS2 используются как основа. Начинать их заново по старым
handoff-командам не требуется. Номера будущих выпусков в архиве — прежняя
оценка этапов, а не обязательство выпустить незавершённые функции под этим номером.

## Сохранённые технические планы и история

Следующие разделы сохранены для технических зависимостей и критериев приёмки.
Актуальный порядок — выше; прежние заявления «не реализовано» оцениваются на
дату своего раздела.

<details>
<summary>Архив плана от 8 сентября и предшествующих редакций</summary>

## План исходной редакции

Дата пересмотра: 8 сентября 2026 года; исходная редакция 18 единого плана<br>
База main до текущих изменений: `bd36e160af5eabd40c0a8bab77c2454d4e4fb06d`, `0.18.1-dev`.<br>
Стабильная база: `v0.18.0`, commit `8fa1d61914cb7fcfb354259408e18ce1dc72e354`.

Этот roadmap переносит порядок единого master-plan на фактическую историю
версий. Опубликованный `v0.18.0` не переименовывается, поэтому номера будущих
этапов сдвинуты, но зависимости и требования безопасности сохранены.

## Текущий срез и очередь 2026-09-08

По отдельному запросу с 11 замечаниями реализованы общий режим управления,
остановка собственных маршрутов, компактные сервисы, проверка/подбор и таймер,
поиск по сайту и интерфейс обновления приложения. Проверки и ограничения
этого дополнения — в [отчёте по управлению](UI_CONTROLS_2026-09-08_RU.md).
Это не закрывает релизные ворота AUTO2+ ниже.

В рабочей копии для `0.18.1-rc.2` реализованы браузер подключений с понятными
странами и транспортами, поиск, фильтры, выборка, TCP-задержка и отдельная
точная проверка сервиса. Сохранённый результат ограничен узлом, сервисом,
сетевой сессией и сроком; перерисовка сохраняет фокус и раскрытые карточки.
Проверенный узел назначается через просмотр и одноразовое подтверждение.
Выбор группы сохраняется в черновике сервиса до явного применения.

Добавлены пять встроенных шаблонов: VLESS Key Checker, два каталога Goida,
Au1rxx Netherlands и Kort0881 RU SNI. Собственная HTTPS-подписка и её расписание
сохраняются приватно; обновление включается пользователем и переживает restart.
Есть отмена получения и подтверждение частичного импорта. Подробные источники
и границы доверия — в [контракте публичных источников](PUBLIC_PROVIDER_SOURCES_RU.md).
Получение списка не запускает сервисные проверки и не включает маршрут.

Автозамена реализована только внутри явно применённой резервной группы.
Она подтверждает отказ, отдельно проверяет сохранённый runtime и резервный
узел, сохраняет область устройств и посторонние черновики, а неудачное
переключение проходит через откат. Состояние и отмена доступны во время
длительной операции; вход не зависит от блокировки основных хранилищ.

На отдельной сборке ядра 8 сентября прошли проверки домена и публичного IPv4
через VLESS, Telegram с выбранного ПК, отрицательный контроль другого клиента,
restart приложения и восстановление после контролируемой потери собственных
процессов/TUN/правил. Исходное пользовательское состояние восстановлено.
Это подтверждение ядра до итоговых изменений UI и подписок; оно не заменяет
приёмку финального rc.2. WARP WireGuard в этой сети не подтверждён, повторный
MASQUE дал смешанные результаты.

По запросу пользователя текущий срез выпускается как `v0.18.1-rc.2` для общего
тестирования. Публикация архивов для aarch64, mips и mipsel проходит после
полного Linux CI точного commit и изолированной проверки установки/отката.
Дополнительные native HIL, настоящий WAN disconnect, перезагрузка роутера,
IPv6 HTTPS и аппаратная приёмка MIPS остаются отдельными незакрытыми проверками.
Готовность и точные границы результата публикуются в
[CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md) и [заметках rc.2](releases/0.18.1-rc.2.md).
Открытые аппаратные сценарии остаются условиями стабильного выпуска;
наличие prerelease не означает их прохождение.

## Архив очереди после повторного аудита 2026-09-06

Следующий раздел сохранён как снимок состояния 6 сентября. Его формулировки
«ещё не реализовано» и «следующий этап» относятся к этой дате; текущая очередь
приведена выше. Он не требует заново реализовывать браузер или scheduler.

Сверены редакция 18 полного пользовательского master-plan (разделы 50–55),
актуальный main и общая переписка. Новые результаты и уточнения плана — в
[AUDIT_2026-09-06_RU.md](AUDIT_2026-09-06_RU.md). Эта очередь заменяет прежние
команды начать N0.1, NodeStore или PR-NFQ0 заново. N0.1/N0.2, N1.1–N1.4,
PR-NFQ0/PR-NFQ1 уже находятся в проверенном main; аппаратные gates остаются
отдельными. Локальные исправления этого аудита ещё не имеют нового CI/release.

Реализованы локально: исправления аудита, [NET1](NET1_2026-09-06_RU.md),
NB1 check/preview/one-use Apply к сервису, PF1 ручной opt-in feed sync и native
WARP generation/recovery только в черновик. NB1 не требует нового backend;
PF1 не является scheduler, sync не разрешает check/switch. Forwarding добавлен
для точного адреса клиента и автоматически определённых Linux bridge/private
connected LAN prefixes; обязательны gVisor и точный outbound. Неизвестный LAN
scope не разрешает широкие правила. All-LAN HIL прошёл для PC IPv4 HTTP 200,
28 правил/6 IPv6 kernel checks; настоящий IPv6 HTTPS остаётся непроверенным.

Native lifecycle для точного PC /32 уже прошёл: A commit/PC HTTP 200,
активация B и намеренная ошибка после штатного health → rollback A/PC 200,
затем успешный B commit/PC 200. Второй PC не направлен в TUN; counters,
cleanup и сохранность исходных глобальных файлов подтверждены. Server endpoints
разные, observed egress одинаковый; независимость upstream-провайдеров не заявлена.

Фактический UI A/B check → preview → Apply прошёл с PC HTTP 200 и сохранением
постороннего WARP draft. PF1 UI импортировал 4 unchecked узла без Apply.
Обычный native Generate выполнил один POST на роутере; reuse не создаёт новый
аккаунт. Эти подтверждённые шаги не требуется реализовывать заново.

Native copy-only migration и encrypted export/preview/import тоже прошли на
роутере: canonical SHA и applied state сохранены, runtime STOPPED; новый POST
не требуется. Локальные older-backup/newer-pending и crash recovery тесты PASS.

После этого уточнены cleanup и recovery guards. WARP/AWG не обращается к
интерфейсу без собственных policy/runtime; partial или несовпадающая пара
сохраняется с отказом. Native schema gate учитывает canonical, legacy markers
и journal-файл, повторно проверяясь после private recovery. Node recovery
сверяет конкретный применённый scope с текущим обогащённым каталогом: отсутствие
ранее не использованной загрузки source само по себе не блокирует этот же
маршрут, но исчезновение использованного enrichment требует review. Локальные
регрессии пройдены, аппаратный warm/cold recovery новой сборки ещё ожидается.

Для рабочего ручного MVP остаются два конкретных условия выпуска:

1. **P1 — восстановление после смены сети и рестарта.** На поддерживаемом
   ARM64 проверить настоящий WAN reconnect/ABA, unknown и повторную проверку
   устаревшего маршрута; после restart интерфейс не должен показывать прежний
   proof как свежий. NET1 unit/DNS watcher и ARM64 read-only underlay/DNS ABA
   HIL уже пройдены, переписывать их не требуется. Это не фактический WAN
   disconnect. Зафиксировать понятный путь пользователя к восстановлению.
2. **P1 — воспроизводимый устанавливаемый кандидат.** Прогнать CI
   итогового commit, затем ARM64 install/update/rollback именно этого артефакта
   с текущими хранилищами. Полный изолированный installer HIL снимка `48f3e1ef…`
   уже PASS; после recovery/cleanup исправлений нужны новая сборка и bounded
   installer smoke. Этот прежний hash не является итоговым release SHA.
   Зафиксировать проверенную модель/версию, recovery
   и ограничения client scope. Другие архитектуры не блокируют явно ограниченный
   ARM64 MVP, но не получают аппаратную готовность по cross-build. Полный Windows race
   с подтверждённым работающим detector уже PASS; Linux-specific ветви требуют
   собственного race/CI-прогона, этот результат нельзя приписать Windows suite.

WG trace не прошёл на четырёх портах; повтор MASQUE дал смешанные результаты
и `working_modes=[]`. WARP не является обязательной зависимостью MVP с
подтверждённым VLESS-путём; доступность публичных узлов не обещается бессрочно.

Эти ворота завершают проверку ядра ручного MVP. По последнему запросу пользователя
сначала заканчиваются текущие исправления и HIL, затем отдельным этапом идут
упрощение UI, сетка узлов, подписки источников с обновлением и автопереключением.
После общей проверки предполагаются очистка репозитория и GitHub Releases
для aarch64/mipsel/mips. Реализация следующего этапа и публикация пока не
подтверждены; итоговый release hash не назначен. Полный native USQUE/NFQWS2,
Selective Smart DNS, AWG compatibility matrix, другие платформы и публичный
сайт остаются отдельными возможностями. P2 оптимизация повторных Fresh snapshots
не должна заменять свежую проверку перед сохранением proof и commit.

Контекст дополнительных чатов уточняет границы этой очереди: собственный
NFQWS2 без runtime-зависимости от z2k; проверяемые рецепты и узлы с provenance;
раздельные сценарии сервисов; выборочный Xbox DNS при сохранении обычного
интернета. Домашний `eth3` и чужой PPP WAN — разные сети, а running process
не доказывает exact service flow. Старые команды чатов не исполнялись;
подробности и пределы NET1 — в [контракте](NET1_2026-09-06_RU.md).

Read-only snapshot 6 сентября 12:56 UTC различает 0 применённых NFQ routes/services
и 1 процесс `nfqws2`. Процесс не подтверждает владение и выбранный service flow;
исторические managed blocks не восстанавливаются по одному наличию старого
журнала. Точные текущие данные — в [CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md).

## История редакций и уже выполненных этапов

Ниже — датированные записи развития. Слова «локально» и «следующий» в них
описывают прежние срезы; текущий порядок задан выше, уровни готовности — в
[CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md).

### Редакция 2026-09-05

Повторно изучена редакция 9 пользовательского master-plan от 5 сентября
(SHA-256 исходного файла
`33e814d28b16024ff1b2753e6e5d57b11ffcd2453be0689b1782d41d519ed602`).
Оперативными считаются раздел 47, затем раздел 33 и неизменяемые ограничения
раздела 4. Статусы и commit из приложенного документа являются снимком момента
его подготовки: фактическая локальная линия уже содержит более поздние этапы
NodeStore, поэтому готовность определяется кодом, тестами и этим roadmap.

Новая редакция добавляет обязательные gates, не меняя порядок разработки:

- внешний TCP connect/latency имеет уровень
  `tcp_reachable_from_github_runner`, но не `working` и не protocol-ready;
- `warp-gen.github.io` считается мёртвым шаблоном; его нельзя предлагать как
  рабочий источник;
- новый WARP binary без ожидаемого digest или доступного verifier всегда
  помещается в quarantine и не запускается;
- WARP `ready`, `routed`, IPv4 и IPv6 отображаются раздельно; mark/table/rules
  требуют owner lease и проверки коллизий;
- для будущего NFQWS2-подбора обязательны типизированный `ProbeIntent`,
  round-trip Strategy Fidelity, direct gate и проверка ответного направления;
- GitHub governance остаётся release gate и не смешивается с dataplane-PR.

Разделы 26–37 обновлённого пользовательского master-plan уточняют ближайший
backlog. Выполненные Cloudflare/USQUE блоки не повторяются и не удаляются.
Ближайший порядок: N0.1 строгий VLESS parser → N0.2 поштучный quarantine →
NodeStore/migrations и узлы UI → exact outbound check → node/group bindings →
provider subscriptions → Effective Route Resolver/NFQWS2 ownership →
опциональный Community Hub. Платформы и широкая автоматика остаются после
соответствующих safety/HIL gates.

Локальная реализация N0.1 описана в [контракте импорта](PR_N0_1_VLESS_IMPORT_RU.md).
Добавлен [N0.2: частичный импорт](PR_N0_2_PARTIAL_IMPORT_RU.md) с причинами отказов,
дедупликацией и явным сохранением принятых записей. Persistent quarantine/NodeStore
ещё не реализованы этим блоком.
Подготовлена [основа N1.1 — NodeStore](NODESTORE_FOUNDATION_RU.md): атомарный
приватный документ, локальная идентичность, provenance/TTL и copy-only helper.
Startup lifecycle подключён; API/UI и health promotion ещё отсутствуют, реестр
пока не используется рабочими маршрутами.
Подготовлен [N1.1b — backup/restore lifecycle](NODESTORE_BACKUP_RESTORE_RU.md):
типизированный snapshot внутри зашифрованного архива, merge без удаления более
свежих узлов, общий journal rollback и recovery после смерти процесса. Перед
startup используются отдельный versioned journal и lifetime lease старого
журнала. Общий зашифрованный export/preview/import узлов подключён; следующим
этапом остаются изменяющие операции управления узлами.
N1.2 реализован локально: API и пользовательская страница не раскрывают
приватный материал, показывают источник, срок и честный статус `не проверен`,
не разрешают выбор непроверенных записей. Подтверждённый импорт сохраняет все
принятые записи отдельно от одного выбранного черновика Sing-box. Alias,
disable/delete и reveal имеют отдельные безопасные контракты; reveal требует
подтверждения, запрещает кэширование и очищается UI после закрытия. Миграция
Старые schema 1/2 переходят на schema 3 только при явной записи.
N1.3 Exact Outbound Checker реализован локально и описан в
[отдельном контракте](EXACT_NODE_CHECKER_RU.md): DNS/transport/protocol,
route identity, proxy egress, direct-leak control и сервисный canary сохраняются
с TTL и профилем сети. N1.4 node/group bindings также завершён локально и описан
в [контракте привязок](NODE_SCOPED_ROUTES_RU.md): выбор ограничен exact proof,
fallback удерживает LKG, endpoint идёт напрямую, а транзакционный отказ возвращает
рабочий runtime. Перед стабильным релизом остаётся N1.4 HIL двух реальных узлов.
HTTPS/TLS-canary через выбранный DNS для USQUE сохранён в backlog, но не
смешивается с изменением импортера. Публикация выполняется проверенными
группами изменений, а не на каждый небольшой локальный коммит.

### Синхронизация master-plan редакции 13 от 2026-09-06

После N1.4 следующим обязательным gate остаётся аппаратная проверка двух узлов:
LKG, подтверждённый отказ, переход на резерв, endpoint-exclusion, canary rollback
и восстановление после reboot/WAN reconnect. До неё N1.4 не входит в стабильный
релиз.

Новая оперативная продуктовая очередь после этого gate:

1. `PR-NFQ0` — read-only fixtures/baseline и доказательство независимости от z2k;
2. `PR-NFQ1` — честное разделение Desired/Planned/Applied/Observed без изменения
   route behavior;
3. дальнейшая нативная очередь `PR-NFQ2..NFQ13` по одному этапу, без установки,
   вызова или runtime-зависимости от z2k;
4. отдельная ветка Selective Smart DNS `PR-DNS0..DNS10`, начиная с терминологии,
   schema migration и модели; обычные resolver-профили не выдаются за geo bypass.

NFQWS2 и Smart DNS нельзя смешивать в одном mutation PR. При конфликте маршрута
действует инвариант одного Effective Route и одного владельца потока.

Локальный статус 6 сентября 2026 года: PR-NFQ0 завершён commit `595c20b`;
PR-NFQ1 реализован локально и ожидает полный verification gate. Состав и запреты
следующего PR-NFQ2 зафиксированы в
[NFQWS2_PR_NFQ1_GAP_RU.md](NFQWS2_PR_NFQ1_GAP_RU.md); PR-NFQ2 в текущий набор
изменений не входит.

## Неподлежащие нарушению условия

- сохранять рабочий NFQWS2/YouTube baseline и WAN `eth3` эталонного Keenetic;
- не менять одновременно NFQWS2, firewall, DNS и WAN routing;
- не захватывать чужие firewall, DNS, PBR, NFQUEUE, интерфейсы и процессы;
- mutation проходит inventory → plan → validate → snapshot → stage → isolated
  canary → exact-route health → commit/rollback → observe;
- все операции имеют timeout, ограниченную параллельность и cancellation;
- приватные WARP/AWG/WG-ключи создаются локально и не уходят публичным
  генераторам;
- TLS verification не отключается, HTTPS не понижается до HTTP;
- public proxy feeds всегда недоверенные, выключенные и помещённые в карантин;
- TCP-open, ping, process/listener-ready и общий HTTP-код не равны успеху
  сервиса.

## Этап 0 — `v0.18.1` Truth & Safety

1. Единая версия, commit/date/dirty metadata и актуальный статус возможностей.
2. Evidence v2 без ложных PASS на redirect, portal, `403`, `451`, неверный TLS,
   поддельный JSON и direct leak.
3. Loopback-only candidate listeners, process timeout и owned-path guard.
4. Source Hub trust foundation: strict redirect/SSRF, digest, provenance, TTL,
   LKG, quarantine и redaction.

Срез 31 августа: пункты 1–2 опубликованы в `v0.18.1-rc.1`, Linux CI прошёл.
Пункты 3–4 реализованы локально с автоматическими тестами; новые Linux/race
и аппаратные gates ещё не пройдены. Полный Source Hub review/scheduling остаётся
дальнейшей работой. Регистрация аккаунтов и расширение живой автоматики до
подтверждения безопасности не выполняются.

## Этап 1 — `v0.19` Unified Cloudflare Provider

1. Provider model и локальное secret state.
2. Локальная генерация ключей и тестируемый registrar без передачи private key.
3. WARP Configurator generate/import/export без системных мутаций.
4. Endpoint Scanner с реальным handshake, egress, trace и service evidence.
5. Единый USQUE lifecycle и Safe Repair Wizard.
6. AmneziaWG compatibility registry и аппаратный canary.
7. `wgcf` только как явно выбранный import/fallback и compatibility oracle.

Локальный срез 31 августа: модель копий, типизированные legacy imports,
отдельный зашифрованный архив/API/UI и явное copy-only чтение старых профилей
реализованы. Добавлен [writer recovery после сбоя процесса](CLOUDFLARE_WRITER_RECOVERY_RU.md)
без удаления чужих блокировок. Пункт 1 ещё не закрыт полностью: общая транзакция
backup/recovery, secret access contract, lifecycle ownership и Linux/HIL остаются.
Подготовительный [guarded rollback общего приватного импорта](PRIVATE_BACKUP_GUARDED_RESTORE_RU.md)
реализован локально. Следующим блоком добавлена отдельная
[основа журнала](PRIVATE_RESTORE_JOURNAL_RU.md) с process-crash tests. Подключение
[первого config adapter](CONFIG_RESTORE_ADAPTER_RU.md) и защита обычных config
writers выполнены локально. Также готовы [catalog/devices adapters](REGISTRY_RESTORE_ADAPTERS_RU.md)
с защитой обычных записей и crash test трёх реестров; ошибка сохранения discovery
показывается в UI. [Staging adapter и guarded post-success undo](ENGINE_DRAFT_RESTORE_RU.md)
тоже готовы локально, с process-crash тестами. [Provider adapter](CLOUDFLARE_RESTORE_ADAPTER_RU.md)
готов локально: та же `.import.lock`, bounded CAS, merge без активации и аварийные
тесты до OpenStore. [Offline coordinator и startup recovery](PRIVATE_RESTORE_COORDINATOR_RU.md)
реализованы локально: все пять типов хранилищ, порядок leases, восстановление
до Load/API, lifetime gate и process-crash tests. [Online admission](PRIVATE_RESTORE_OPERATION_GATE_RU.md)
подключён к существующему HTTP-импорту, фоновому циклу и conntrack.
[Session-backed online journal и cache handover](PRIVATE_RESTORE_ONLINE_RU.md)
подключены локально: общий HTTP import, проверка bindings, recovery fence,
process-crash tests и busy health/supervision. Следующий обязательный блок —
snapshot после исключения writers, сохранение/совместимость private journal
при upgrade/rollback и Linux/Entware/HIL. Общий HTTP-импорт Provider-архивов
остаётся закрытым; весь PR-1.1 пока не завершён.

Локальное продолжение 1 сентября: добавлен первый слой пункта 2 — X25519-ключ
создаётся внутри Provider, API-контракт получает только публичный ключ, а mock
registrar возвращает неподтверждённого кандидата без публичного представления
private key, device ID или access token. Неактивное сохранение кандидата в
private Store и его encrypted backup/restore затем добавлены. Живой Cloudflare
API и runtime намеренно отсутствуют до golden fixtures и следующих gates.
Для будущего изолированного builder добавлен ограниченный tunnel-material
callback без account credentials; публичный API секретов по-прежнему отсутствует.
Следующий локальный блок добавляет сам inert WireGuard candidate builder с
bounded options и secret lease, но без runtime/route/DNS и без заявления о
handshake. Подробности: [CLOUDFLARE_WIREGUARD_CANDIDATE_RU.md](CLOUDFLARE_WIREGUARD_CANDIDATE_RU.md).
Также готов чистый evaluator
[Endpoint Scanner evidence](CLOUDFLARE_ENDPOINT_SCANNER_EVIDENCE_RU.md), который
не допускает `verified` без двух полных exact-route попыток. Реальный runner/HIL
остаётся следующим gate.
Официальные WireGuard ranges/ports вынесены в отдельный версионированный
[endpoint catalog](CLOUDFLARE_ENDPOINT_CATALOG_RU.md); undocumented registrar
endpoint не блокируется, но не считается официальным или рекомендуемым.
Контракт: [CLOUDFLARE_LOCAL_REGISTRAR_RU.md](CLOUDFLARE_LOCAL_REGISTRAR_RU.md).
TTL/score/cooldown получили непереносимый
[приватный health journal](CLOUDFLARE_ENDPOINT_HEALTH_JOURNAL_RU.md) с material
binding, атомарным commit и строгим startup recovery. Журнал прошёл ARM64 gate;
до появления изолированного runner этот state не подключается к UI или AUTO.
Для runner готов первый dataplane-слой direct/source-bound trace и strict service
Evidence. Изолированный runner теперь владеет временным `rz-cf-scan`, table 220,
source-only policy и cleanup под межпроцессной OS-блокировкой. Platform gate
прошёл на ARM64 с детерминированными системными адаптерами. Реальный Cloudflare
handshake/egress/Telegram HIL ещё обязателен; до него runner не подключается к
UI, AUTO или рабочему Apply.
Явно выбранный пользователем WireGuard-файл теперь можно передать в тот же
bounded Scanner как ephemeral candidate без записи в Store/health; passive
копия сама это право не получает. Hostname resolution реализован как
двухшаговый preview → pinned public
IP без повторного DNS во время запуска. Перед UI остаются его пользовательское
представление, live HIL и durable promotion/recovery contract.

## Этап 2 — `v0.20` Proxy Provider и Node Lab

1. Типизированный и fuzz-tested parser VLESS/Reality, затем Trojan/SS.
2. Quarantine store с trust tier, TTL, provenance, dedupe и diff.
3. Реальная цепочка Node Lab: handshake → egress → exact service probe.
4. Подписки пользователя с Conditional GET, jitter, LKG и review.
5. Goida/VLESS Checker только как выключенные Pro-шаблоны источников.
6. Истекающая оценка узлов, cooldown и запрет вечного статуса «работает».

Уточнение пользователя: [публичные источники резервных обходов](PUBLIC_PROVIDER_SOURCES_RU.md)
должны поддерживать автоматическое обновление списков и отдельную локальную
проверку узлов. Сначала NodeStore и exact-node evidence, затем opt-in расписание;
обновление списка не даёт разрешения менять рабочий маршрут.

## Этап 3 — `v0.21` Native NFQWS2

Продолжить `PR-NFQ2..NFQ13` после уже реализованных PR-NFQ0/PR-NFQ1:
golden baseline, inventory/ownership,
typed strategy compiler, adoption, NFQUEUE lease, Keenetic events, registry,
Strategy Lab, LKG state, restriction analyzer, resolver, gated adaptive mode,
updates и Lite/Pro UI. Автоматическое переключение запрещено до аппаратных
ворот и сохранения `legacy-stable`.

## Этап 4 — `v0.22` Lite/Pro

- один backend и API, простой Lite по умолчанию и диагностический Pro;
- typed API/client, frontend modules, design tokens и i18n;
- task-first Overview/Services/Devices, onboarding и symptom-first diagnosis;
- Pro: Routes, Engines, Providers, Sources, Labs, Evidence, Recovery и Audit;
- локальная работа без CDN, mobile 360 px, клавиатура и reduced motion.

## Этап 5 — `v0.23` Platform Core

Извлечь capability/platform contracts без изменения Keenetic-поведения, затем
добавлять Generic Linux/Entware, OpenWrt, GL.iNet и Asuswrt-Merlin. MikroTik
начинается только с read-only inventory/controller plan.

## Этап 6 — `v1.0`

Автопилот проходит режимы recommend → shadow → один AUTO-сервис с известным LKG
→ расширение после HIL. `v1.0` возможен только при route passports, Evidence с
TTL, автоматическом rollback, recovery после reboot/WAN/firewall, native/adopted
NFQWS2, local-key Cloudflare Provider, Lite/Pro и подтверждённых capability
матрицах Keenetic и OpenWrt.

Фактическая готовность каждого этапа фиксируется в
[CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md); номера версий не являются заменой
CI и аппаратным доказательствам.

</details>
