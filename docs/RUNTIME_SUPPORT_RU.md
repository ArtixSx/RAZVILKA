# Сборки и поддержка запуска

Состояние рабочих исходников на 09.11.2026 для готовящейся **0.20.0**. Сквозная приёмка режима
списков и исключений и часовая проверка Telegram через VLESS ещё не завершены.
Готовность выпуска фиксируется в [текущем статусе](CURRENT_STATUS_RU.md).

Исследовательская интеграция поверх `0e2db5ab` не расширяет платформенное
разрешение. Новые стадии VLESS и JSONL nodeeval диагностические: TCP/SOCKS,
engine delay, HTTPS и реальный LAN-маршрут остаются разными доказательствами.
Текущая [сверка API/AUTO/реализаций](RESEARCH_REVIEW_20261109.md) отделяет
регистрацию операции от live admission; [лабораторные результаты](measurements/2026-11-09/research/README.md)
отделяют Windows loopback, Linux namespace и физический роутер.

| Механизм | ПК / программное состояние этой волны | Что не подтверждено |
| --- | --- | --- |
| Exact VLESS/Xray/sing-box | Deadline SOCKS, отдельные startup/identity timings, строгий service gate и joined cleanup | Универсальное ускорение WAN и route-ready LAN |
| Mihomo | Изолированный probe и lifecycle API существуют; availability остаётся tri-state | Полный повторный Stop/Apply, recovery cuts и live readiness |
| Backup/StrategyLab | Парный snapshot3 и encrypted recovery уже реализованы; сохранены fences | Любые произвольные версии downgrade и аппаратный power-loss |
| DNS/NFQWS2 | Scope/exclusions/ownership ограничения действуют | Незавершённые full native workflows нельзя закрыть generic CI |

## Три бинарника Entware

ARM64, MIPS и MIPSel остаются обязательными целями сборки. Установщик выбирает
соответствующий бинарник; MIPS и MIPSel используют разные порядки байтов
и soft-float ABI. Команды установки приведены в [инструкции](INSTALL_RU.md).

Успешная сборка подтверждает компиляцию программы для выбранной архитектуры.
Для применения правил списка на роутере дополнительно нужны поддержанные
прошивка, системные утилиты и проверки их реальной работы. Запущенная панель
сама по себе не подтверждает, что выбранный обход применился к устройствам.

## Текущая матрица managed LIST

Managed LIST — управляемое применение правил активного списка через NFQWS2,
Xray или WireGuard. При запуске все три варианта используют один проверенный
штатный профиль NC-1812.

| Целевая система | Бинарник | Текущий запуск managed LIST |
| --- | --- | --- |
| Netcraze Ultra NC-1812 с точным проверенным штатным профилем | `arm64` | Путь запуска реализован; требует совпадения профиля и всех проверок. Сквозная приёмка ещё не завершена. |
| Другие ARM64-модели или прошивки вне этого профиля | `arm64` | Недоступен: текущие конструкторы отказывают. |
| Keenetic/Netcraze MIPS | `mips` | Недоступен: необходимые платформенные реализации отсутствуют. |
| Keenetic/Netcraze MIPSel | `mipsle` | Недоступен: необходимые платформенные реализации отсутствуют. |

Текущий профиль задаёт Netcraze Ultra NC-1812, ядро `4.9-ndm-5`, прошивку
`5.01.C.6.0-1` с обозначением `5.1.6` и конкретный проверенный набор утилит
Entware. Совпадения только архитектуры ARM64 или имени модели недостаточно.
При несовпадении запуск сообщает о недоступности и оставляет применение
правил списка закрытым.

## Что осталось для расширения поддержки

- Добавить проверенные профили конкретных устройств, прошивок и системных
  утилит для нужных платформ и подключить их к обычному запуску.
- Реализовать необходимые native-проверки MIPS/MIPSel: наблюдение системного
  окружения, работу с удерживаемыми дескрипторами и проверку ELF32, обоих
  порядков байтов, ABI, загрузчика и библиотек.
- На каждой заявленной целевой системе проверить обычный запуск, применение
  правил к выбранным устройствам, доступность сервисов, откат и завершение
  работы. Результаты сборки и аппаратной приёмки фиксировать отдельно.

Расширение поддержки должно сохранять проверки платформы, области применения
и отката. Выбор по одному `uname` не подтверждает поддержку.

## Уровни подтверждения на 31.10.2026

Повторная сверка startup и конструкторов на `a36f5343` не расширяет список
поддержанных устройств. Матрица выше описывает допуск конкретного managed LIST
профиля. Наличие обычного proxy/WG адаптера и Linux `dns-scoped` не означает,
что произвольный LIST scope разрешён на каждой Linux-платформе.

| Уровень | Что подтверждает | Что остаётся проверить |
| --- | --- | --- |
| Исходники и unit/model | Контракты, отказы scope/ownership, переходы модели | Фактические kernel/tools, процессы, правила и трафик |
| Полный Linux CI | Тесты, race/vet, shell/UI, четыре cross-build и Entware fixture точного SHA | Роутер, WAN и LAN-клиент |
| Isolated native | Реальные утилиты и cleanup в конкретной изолированной среде | Отличия прошивки и физического роутера |
| Роутер и LAN | Выбранный сервис/устройство, соседний домен на общем IP, исключения, штатный VPN | Длительная устойчивость, reboot/power-loss и аппаратная производительность |

Этот раздел фиксировал исходную сверку `a36f5343`. Результаты последующей
работы приведены ниже; они не расширяют аппаратную матрицу. Состояние
исходного аудита и ограничения обновления сведены в
[матрице обходов](BYPASS_REVIEW_2026-10-31_RU.md#повторная-сверка-контрактов-31102026).

## Сверка работающих путей на 02.11.2026

Матрица описывает регистрацию исполнителей в исходниках, а не готовность
сервиса на конкретном роутере. `/api/v1/engines` и инвентарь панели используют
одну структуру `lifecycle`: `registered` означает подключённый путь операции;
`available: null` оставляет проверки текущей области, профиля, владения,
журналов и маршрута обязательными. `absent/false` и `unknown/null` различаются.
Наличие установленного файла само по себе не даёт ни одного из этих допусков.

| Механизм | Фактически подключённый путь | Граница подтверждения и оставшиеся условия |
| --- | --- | --- |
| NFQWS2 | Управляемый пакет, supervised совместимость, настоящий scoped TLS probe и HTTP-подбор; история и ручной выбор привязаны к текущим исходным runtime/control владельцам. | Конечный probe и три HTTP-пробы проходят на isolated amd64. Полный managed LAN Apply → included/excluded traffic → Stop/recovery и race ещё не проходят. Сохранённый PASS после перезапуска остаётся историей; регистрация API и LIST executor не подтверждают этот полный сценарий. Актуальные SHA и результаты — в [общей очереди](ROADMAP.md). |
| Xray / VLESS | Реальный native конфиг, изолированный SOCKS checker, парный прямой/проксированный TLS контроль и обязательный cleanup; обычный startup сохраняет исходные маршруты и selected TCP consumer. | XHTTP допускается только для точной версии `26.3.27`, указанной production контрактом. Обычный TLS/RAW и XHTTP имеют разные ограничения. DNS capture/baseline и общий IP не дают права подменять сервисный scope; их сквозная приёмка отдельна. |
| Sing-box / USQUE | Существующие proxy/TUN адаптеры, scoped проверки, транзакции, наблюдение и recovery. | Нужны профиль сервера/сессия, точный маршрут и свежий сервисный результат; доступный процесс не означает доступный сервис. |
| WireGuard / WARP WG | Существующий adapter lifecycle, ограниченный общий бюджет handshake, отмена, проверка принадлежащего интерфейса и egress/trace. | Регистрация WARP, handshake и проверенный выход — разные результаты. Нужны поддержанный kernel/tools, профиль, WAN и текущие owner проверки. |
| AmneziaWG | Существующий профиль и адаптер для внешнего kernel/CLI пути. | Установщика userspace AmneziaWG нет. Нужны модуль под текущее ядро, совместимый `awg`, версия профиля и сервер; имя бинарника не подтверждает поддержку. |
| Scoped DNS | Исходные Manager/ScopedDNSAdapter, control epoch, резервирование и публикация DNS данных связаны с исходным capture владельцем. | Непубликованный источник не становится готовым от регистрации. Реальные capture, baseline, маршрутизация и исключения должны пройти свои проверки. |
| HEV SOCKS5 TUN | Доверенная установка закреплённого `2.17.1`, бинарник + receipt через CAS/журнал; пользователь выбирает HEV для следующего запуска вместо существующего TUN backend. Холодное recovery сохраняет этот выбор. | Это зависимость маршрутов Xray/USQUE, а не самостоятельный маршрут. При регистрации исходного parent + component owner API показывает `runtime_preflight`, `sidecar_runtime`, `sidecar_recovery`; доступность остаётся неизвестной до допуска. `--version`/receipt preflight не называется native проверкой конфига: отдельной такой команды у HEV нет. |
| Mihomo | Закреплённый `1.19.33`, installer/reinstall и binary/receipt/state CAS; конечная native проверка сервисов и HTTP review/probe с COMMON cleanup. Ручной preview/apply API/UI, config CAS и encrypted roundtrip выбора реализованы. Reader6/7/8/9 и cold retirement с пятью исходными private leases интегрированы. | Конечная проверка имеет `live_applied=false`. На integrated e87dd918 проверен actual post-CAS HTTP503→exact desired rollback: rollback_verified=true, original_pending=false (76.98с). Полный warm Check/Stop/repeat ещё не проходит; readiness не повышается от истории или отдельной фазы. Cold normal/race и CLI проходят; история старой загрузки моделируется, текущие source/process/kernel/lease наблюдения настоящие ([доказательства](validation/2026-11-02/mihomo-cold/results.json)). Isolated same-boot first-candidate cleanup после actual parent death прошёл normal99,70с; полный набор race/cuts/restart ещё не завершён. Cold reader9 сохраняет settled→retired header и проверяет fleet; actual CLI9 на2aa прошёл normal27,88с/race63,37с. Неизвестные состояния сохраняют отказ. |
| Binary + StrategyLab backup/restore | Совместимая snapshot3 пара, encrypted import/export, история и ручной выбор; восстановленная панель проверяется настоящим запуском. | На `9e2be03d` focused A, восстановленная панель и оба полных CI проходят. Unknown/finalizing и незавершённый runtime не разрешают раздельное восстановление или обновление. Power-loss/reboot на физическом роутере не проверены; [порядок аппаратной приёмки](ROUTER_ACCEPTANCE_RU.md) подготовлен. |
| Mihomo: постоянный маршрут и восстановление | На `4bcb7d0d` интегрированы исходный child/HEV/TUN lifecycle, ручной `mihomo:node-*` preview/apply API/UI, точные CIDR выбранного сервиса и приватные IPv4 sources, CAS и encrypted import с повторным чтением Store. Reader6/7/8/9 различает persistent intent, detached DNS и завершённые архивы health. Post-boot CLI удерживает все пять исходных private generations, неизменный config и current native sources. | В isolated `b1e7b10c` настоящий Apply впервые дошёл до committed (90,53с), включая HTTPS после CAS. Reader9 original Check/Stop custody исправляет переход журнала; isolated816 прошёл Apply108,098с, Check cut1 и Stop cut2 с сохранением исходного процесса/TUN и трафика, но повторный Stop ещё FAIL. Полный Check/Stop/repeat не прошёл; публичная live readiness остаётся false. Доменные, смешанные и whole-home маршруты этим путём не разрешены. Integrated cold normal/race41399878590 и health archive normal/race41399878588 PASS; в cold старая загрузка моделируется, в archive terminal probe rows моделируются. Isolated ff2 actual first-candidate same-boot recovery прошёл normal99,70с (job125285725205); race остановился на120с после двух terminal ACK, ACK cuts пропущены. Original cursor и minimum8/9 интегрированы; повторный native workflow и restart ещё не завершены. История/наличие пакета не дают service health. [Доказательства и очередь](ROADMAP.md#активная-очередь-исследования-и-реализации--09112026) |

Проекция HEV проверена регрессиями
[`sidecar_lifecycle_capabilities_test.go`](../internal/dataplane/sidecar_lifecycle_capabilities_test.go),
[`runtime_lifecycle_capabilities_test.go`](../internal/app/runtime_lifecycle_capabilities_test.go)
и тестом представления панели. Чистый lab constructor без исходного component
owner не выдаёт managed регистрацию; даже recovery constructor с отсутствующим
исполняемым файлом не выдаёт `available: true`.

Реальный HEV TUN→SOCKS→TLS и принадлежащий cleanup, а также установка/receipt
и crash recovery прошли в disposable Linux namespace:
[scoped-native, исходники 18b6c75b](https://github.com/ArtixSx/RAZVILKA/actions/runs/41249849526/job/124680887080).
Эта проверка подтверждает только изолированный стенд amd64. Она не подтверждает
Entware ARM64, выбранного LAN-клиента, физический WAN, длительную работу,
power-loss или готовность роутера к эксплуатации.

Полный native VLESS Check (включая validation, client, TLS/SOCKS, egress,
service и cleanup) измерен на том же изолированном типе стенда: N=12 повторных,
live p50 **502.681→396.741 мс**, p95 **506.826→398.146 мс**; физический счётчик
сервисных запросов **2→1**. Reference скрывает только локальную запись первой
literal пробы у текущего Check и не представляет исторический release.
Условия, все live/dead/cancel sample и границы cold/repeated приведены в
[native измерениях](measurements/2026-10-31/native-vless/README.md). Отдельный
успешный App queue/HTTP run использует те же настоящие native Checks и исходные
Store/dispatcher/history admission: N=12, enqueue→server completion p50/p95
733/748 мс для одного узла, 2582/2601 мс для selected batch из двух узлов,
2588/2603 мс для all-VLESS из двух узлов. Контролируемое ожидание admission
25 мс и такт dispatcher 10 мс описаны отдельно; HTTP получение не называется
браузерным paint и не смешивается с server completion.
Это подтверждает выигрыш одного контролируемого сценария с задержкой сервиса
40 мс, а не аппаратное ускорение или готовность маршрутизатора.

## Историческая первая проверка исследовательской ветки: 8c869c76

| Уровень | Фактически проверено | Не подтверждено |
| --- | --- | --- |
| ПК Windows | Xray/Toxiproxy: valid/bad UUID и задержка канала; Mihomo: HTTP503 при положительном delay; полный cleanup собственных процессов | Маршрутизация LAN и TLS этого компонентного HTTP опыта |
| Generic Linux CI | Push42559470926 и PR42559473824 SUCCESS: normal/race, vet, UI, cross-build, Entware | Физическая прошивка и весь native lifecycle |
| Native Linux namespace | Run42559470862 SUCCESS: одинаковый Xray26.3.27, full Check и App queue, service identity, failure/cancel и cleanup. N12: full Check p50 404.777→314.996мс, selected2 completion2615→1444мс. Mihomo actual service/common cleanup/HTTP handler PASS без SKIP | Минутные WAN задержки, полный Mihomo Apply/Stop/reapply, DNS GEN2 и managed NFQWS2 LAN workflow |
| Роутер/LAN | Подготовлен воспроизводимый сценарий; испытание не проведено | NC-1812 ARM64/KeeneticOS5.01.C.6.0-1/Entware: нужен выделенный роутер, LAN клиент и разрешение на изменение устройства |

[Сырые измерения, точные SHA, N и ограничения](measurements/2026-11-09/research/README.md).
Эти результаты не меняют admission и не повышают live readiness незавершённых путей.

Текущая lifecycle проверка и найденные ограничения по точным SHA: [результаты](measurements/2026-11-09/research/lifecycle/README.md). Новые private cleanup пути не повышают публичную live readiness до своей native приёмки.

## Дополнение по native2924cd74

| Возможность | Подтверждение | Оставшаяся граница |
| --- | --- | --- |
| VLESS full Check и durable queue | Повтор42566485696 attempt2 SUCCESS,182 строки; N12 live p50 403.157→312.937мс, selected2 2604→1423мс | Контролируемый Linux namespace; не медленный WAN и не router readiness |
| StrategyLab binary/state pair | Job128993971089 SUCCESS: реальные совместимые readers, native/race, восстановленная панель | Конкретные поддержанные переходы; не произвольный downgrade/power-loss |
| DNS original successor preparation recovery | Job128993971272 SUCCESS: genuine CUT, clean и2partialACK, joined cleanup и прежний alias; baseline отказывает | Diagnostic30/10; strict12/4 publication и generic GEN1 failure recovery ещё не завершены |
| DNS strict publication | Selected дошёл до capture-ready, но FAIL по12с; canceled-ready не запускался из-за asset504 | Полный GEN2 ready/cancel/retire/retry не подтверждён |
| Mihomo full lifecycle | Новые portable fixes проверены;2924 два native повтора не получили fixtures из-за504 | Apply/Check/Stop/fresh Apply требуется повторить с теми же проверенными бинарниками |
| Managed NFQWS2 | Production core/HTTP/closing checks PASS; свежий post-Add readback проверен адресно | LAN/manual/race этой ревизии остановились на asset504; старый activation/retirement отказ d5 остаётся открытым |

Generic PR CI d5fd9774 — SUCCESS. Более новые SHA оцениваются отдельно;
аппаратная матрица и публичный admission от этих результатов не повышаются.

## Последующая native приёмка b7261e9f

Mihomo full lifecycle42568035583 — SUCCESS: два Apply/Check/Stop, fresh Apply,
closing retry, failed Check settlement и post-CAS rollback; original bookends
normal/race PASS. Apply≈95.5с, Stop≈6.1с — функциональная приёмка, не ускорение.
StrategyLab pair/restored panel и DNS preparation clean/2partialACK повторно PASS.
Strict DNS12с оба сценария и managed NFQWS LAN/manual/race остаются FAIL.
Подробности и raw evidence: [lifecycle журнал](measurements/2026-11-09/research/lifecycle/README.md).
Эти стендовые результаты не меняют публичный допуск профилей или аппаратную матрицу.

## Актуальная сверка bfc96dd2 и последующая диагностика

| Уровень | Фактический итог | Граница подтверждения |
| --- | --- | --- |
| Generic CI bfc | Push42569258837 и PR42569263105 SUCCESS | Не заменяет native/router tests |
| Native probe bfc | VLESS paired и Mihomo service/HTTP PASS | N12, isolated Linux; отдельный LAN Apply |
| Native Mihomo bfc | Settlement/post-CAS PASS; полный lifecycle attempt2 PASS | Attempt1 material refusal сохранён как необъяснённая нестабильность |
| Native DNS bfc | Original successor recovery clean/2partialACK PASS diagnostic30/10 | Strict publication12/4 FAIL на GEN1, GEN2 не выполнен |
| Native NFQWS bfc | Core/HTTP production PASS | LAN/manual/race FAIL по budget/unknown cleanup; full workflow не принят |
| Аппаратный профиль | SSH read-only: NC-1812/ARM64/5.01.C.6.0-1/Entware подтверждены | Новая сборка не установлена; router/LAN scope не принят, нужен отдельный допуск к изменению устройства |

`0a72dfb8` сохраняет exact service/freshness при отображении stages и явный
unknown runtime в карточках; cleanup refusal не теряется. Эти изменения не
повышают публичный admission. [Точные результаты](measurements/2026-11-09/research/lifecycle/README.md)
и [профиль устройства](measurements/2026-11-09/research/router-readonly.md).


## Сверка следующей ревизии b5a5f58e

Mihomo full native lifecycle, settlement/post-CAS, StrategyLab pair/restored
panel, DNS preparation diagnostic30 и paired VLESS подтверждены повторно.
Strict DNS12/4 и managed NFQWS LAN/manual/race остаются FAIL; аппаратный
admission не повышен. Общий CI b5a FAIL из-за отсутствующего StartedAt в общем
fixture; однострочное исправление441e97e4 требует своего CI. [Evidence](measurements/2026-11-09/research/lifecycle/README.md#проверенный-b5a5f58e-и-продолжение-09112026).


## Проверенный интегрированный f842e4dd

| Уровень | Результат | Ограничение |
| --- | --- | --- |
| Generic CI | Оба push/PR SUCCESS: normal/race, vet, UI, четыре cross-builds, modeled Entware | Не аппаратная приёмка |
| VLESS/Mihomo probes | Paired182 rows и actual Mihomo handler SUCCESS; VLESS N12 p50 400.529→310.368мс, selected2 2549→1365мс | Один runner/binary, fixed order; не cold OS cache, не router/LAN |
| Mihomo полный native | Оба Apply/LAN/Stop, fresh Apply/closing retry, settlement и post-CAS PASS | Разделение fixture-cycle budgets не является ускорением; исторический material refusal не объяснён |
| StrategyLab и DNS preparation | Compatible pair/restored panel и diagnostic30 original recovery PASS | Не произвольный downgrade/power-loss; не strict DNS publication |
| Strict DNS / managed NFQWS LAN | FAIL на штатных deadlines; флаги неизвестного результата сохраняются | Это оставшаяся программная работа |
| Следующие изменения | STATX held-FD audits и original never-issued NFQ recovery прошли code review | Собственные CI/native ещё обязательны; на kernel4.9 fallback с дополнительной попыткой syscall, аппаратный выигрыш не заявлен |

[Измерения, первые/повторные samples, выбросы и raw](measurements/2026-11-09/research/lifecycle/README.md#интегрированный-f842e4dd-native-результаты).
