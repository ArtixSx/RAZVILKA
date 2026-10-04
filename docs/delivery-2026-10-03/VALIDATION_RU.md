# Проверка принятой рабочей копии — 03.10.2026

Это продолжение проверки поставки, а не новый релиз. `VERSION=0.19.3` и production `go.mod` не изменены. Рабочая ветка: `review/delivery-2026-10-03`; исходная папка владельца `current` сохранена.

## Интеграция и найденные ошибки

Проверены 1134 контрольные суммы manifest. Изменения владельца сохранены отдельным коммитом `cc63c03`, поставка объединена в `a7b8c0d`. Старые H00/IM-пакеты повторно не накладывались.

Исправления в проверяемом коде `ba18bc9`:

- Проверка узла сохраняет именно успешно проверенный IP и использует выделенный ей слот; DNS-поиск и TCP-измерение не дублируются.
- Тестовые часы параллельных проверок сделаны потокобезопасными. Первый Linux race-прогон действительно выявил эту гонку; обычный тест её не находил.
- Xray учитывает флаги включения TLS, REALITY и uTLS. Параметры, которые преобразователь не умеет сохранять, отклоняются вместо незаметной потери.
- Обновление компонента с неизменной или пониженной версией выполняет проверяемый откат. Ошибка записи результата отката больше не считается подтверждённым восстановлением.
- Неопределённый результат сохранения автопилота требует пригодного повторного чтения. Старые ответы после смены сессии и перезапуска не разрешают повторную запись и не стирают поля.
- Защищённые фоновые запросы ждут завершения входа. На настоящем первом запуске воспроизведена и исправлена подмена создания администратора формой входа.
- Несохранённые параметры сохраняются при переходах между страницами; добавлено предупреждение при уходе со страницы.
- При выходе фокус переводится в форму входа, фон становится `inert`: элементы прежней сессии не остаются доступны клавиатуре и экранному диктору.

## Исполнители

Реальные задачи: `/root/delivery_ui`, `/root/delivery_vless`, `/root/delivery_ops`. Каждый работал в отдельной ветке и передал коммиты с регрессионными тестами. Общие файлы и объединение — у `/root`; VM и роутером управлял только координатор. Подробности: [распределение](COORDINATION_RU.md).

## Автоматические проверки

Окружение: Ubuntu 26.04.1 в локальной VM, Go **1.26.5**, Node **24.19.0**, GCC 15.2. Использованы исходные `go.mod` и `go.sum`, `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`.

| Исходники | Команда | Результат |
|---|---|---|
| `a7b8c0d` | `go mod verify` | Успешно |
| `a7b8c0d` | `sh scripts/check.sh` | RC 1: race в тестовых часах |
| `64a2d46` | `go mod verify; sh scripts/check.sh` | RC 0, `RAZVILKA checks: OK` |
| `5c24dac` | `go mod verify; sh scripts/check.sh` | RC 0, `RAZVILKA checks: OK` |
| `ba18bc9` | `go mod verify; sh scripts/check.sh` | RC 0, `RAZVILKA checks: OK` |

Полный сценарий включает обычные Go-тесты, race detector, vet, проверки интерфейса и shell-скриптов, сборки Linux arm64/mips/mipsle/amd64, SHA-256 и тест установки/отката Entware. Сборка для архитектуры не означает аппаратную приёмку этой архитектуры.

Журналы координатора находятся локально в `.review-local/check-linux-01.log` … `check-linux-04.log`; рядом сохраняются коды завершения. Регрессии ассистентов сначала воспроизводили ошибки, затем проходили после исправлений. Windows-only прогон не выдаётся за Linux CI.

## Настоящий HTTP и браузер

Проверяемый код `5c24dac` собран штатным Go в настоящее приложение Windows, запущенное на `127.0.0.1:18841` с отдельными пустыми данными и Safe Mode. Поддельный API не использовался.

- Первый запуск до исправления: сервер сообщал `setup_required=true`, браузер показывал вход в существующую учётную запись. После исправления видна форма «Создайте администратора»; до неё отправлены только GET `/auth/status` и `/status`.
- 11 реальных HTTP-запросов: создание администратора без ключа отклонено (401), с ключом принято; вход/выход работают; неверный пароль и запрос после выхода отклонены; запись с чужим Origin запрещена (403).
- Проверены CSP `default-src 'self'`, `frame-ancestors 'none'`. Контрольная сумма сетевого config.json до и после проверки не изменилась.
- В браузере выполнены вход, переходы Главная → Автопилот → Сервисы → Автопилот. Введённое значение 150 сохранено при возврате, «Отменить правки» вернула 120. Наблюдение CDP за этим окном: 59 API-запросов, все GET; ошибок JavaScript в журнале нет. Это число с фоновыми опросами, не замер запросов одного открытия или производительности ARM64.
- На `ba18bc9` дополнительно повторены вход/выход: фокус после выхода на поле пароля, фоновая панель отсутствует в accessibility tree. До исправления фокус оставался на кнопке выхода и дерево включало скрытый фон.

## Проверка бинарника на AArch64

На настоящем Netcraze запущена сборка `5c24dac` из успешного Linux-прогона. После передачи сверена SHA-256; команды `-version` и `-check` завершились RC 0. Прочитаны чистый пример конфигурации, 6 сервисов, 8 источников и 35 community-определений. `migrated=false`: проверка не записывала конфигурацию и не запускала маршруты. Временная папка проверки удалена после сохранения результата на ПК. Это аппаратная проверка запуска и входных файлов, **не** HIL туннелей.

## Очистка флешки

Сначала на ПК сохранены и прочитаны до конца два архива: текущий проект (38068 записей) и старые тесты (92850 записей). Проверены TAR, GZIP CRC и SHA-256. Секреты и пользовательские настройки не публикуются в репозитории.

Удалены 92 подтверждённых старых элемента только из `/opt/tmp`: прошлые установочные папки, тестовые программы, журналы и временные состояния RAZVILKA. Перед удалением сверены повторная инвентаризация и отсутствие использования запущенными процессами. Entware, чужие файлы и текущие рабочие настройки сохранены. После очистки занято 589688 КиБ, свободно 6656844 КиБ (8% занятого раздела). Бинарник 0.19.3 и его init-скрипт совпадают по SHA-256 с копией до очистки.

Резервная копия на ПК: `C:/Projects/RAZVILKA-router-backup-2026-10-03`. В ней также лежат `cleanup-plan.json` и `cleanup-result.json`.

Действующая панель после очистки отвечает HTTP 200, версия 0.19.3. Её состояние `canary-failed`, `live_active=false`, `recovery_state=not-required`. Очистка временных файлов не исправляет эту старую неудачную проверку маршрута; работоспособность обхода по ответу панели не заявляется.

## Что результаты не подтверждают

D01 остаётся частично открытым: нужны измерения на ARM64 и полные сценарии ошибок настоящего HTTP. D02/D03 — точный per-node Xray и native end-to-end. D04–D09 — WG/AWG, общий сетевой исполнитель и DNS/LAN. D10 — холодный подбор и резерв. D11 — полный устойчивый к отключению питания журнал обновления. D12–D14 — оставшиеся сценарии UI, WARP/USQUE и аппаратная длительная приёмка.

Новая рабочая копия не установлена вместо действующей на роутере и не опубликована на GitHub. Локальная успешная проверка не доказывает работу туннелей, всего LAN, медиасервисов или автоматического восстановления после потери питания.

## Следующий проверяемый этап: Xray, WG и journal

После D00 объединены работы `/root/d02_xray`, `/root/d04_wireguard`, `/root/d11_recovery` и общая интеграция координатора.

- Точный checker Xray RAW/TCP TLS/REALITY и строгий канонический VLESS; неизвестные параметры не теряются. Доказательство имеет отдельный путь `xray:<node-id>`; подключение в приложение и NodeStore ещё требуется.
- Изолированный WG candidate с привязкой сокетов к собственному интерфейсу, инициирующим трафиком и сохранением исходных Sources. Отдельное приватное хранилище именованных Generic WG профилей с revision/CAS; app/API ещё не подключены.
- Persistent journal package/config обновлений, 40 fault boundaries и 5 subprocess crash-сценариев с дисковым симулятором пакетов. Исправлен повторный автозапуск пакетного Sing-box после отката. Native opkg и physical power cut пока не проверены.
- Приложение сохраняет fence при pending/corrupt component journal, предоставляет чтение причины и явный Stop. Обновление кандидата возвращает pending, а не ложный успех. **Matching repair API и принятие нового live runtime ещё не реализованы: это checkpoint разработки, не готовый релиз обновлений.**
- При удалении сетевой политики убран flush всей таблицы: удаляется точный записанный default с readback, чужие маршруты сохраняются. Создание через `route replace default` отдельно требует дальнейшего ownership-аудита.

Нативный запуск `native-round-03` на `043e62c` (Linux, Go 1.26.5) прошёл с RC 0:

| Сценарий | Подтверждено |
|---|---|
| WG IPv4 и IPv6 | Настоящие kernel WG client/server в отдельных namespace; live и candidate с одинаковым Address, инициирующий трафик, TCP/UDP и изоляция candidate |
| Xray TLS и REALITY | Настоящие server/client 26.3.27, парный HTTPS egress, сервис по имени/IP, остановка/возврат сервера, неверный UUID, kill/recovery клиента |

Первые запуски не прошли: AppArmor не разрешал `wg` читать временные ключи из `/tmp`; повторный WG сценарий оставлял устаревшую сессию live peer; REALITY fixture не дожидалась target discovery. Исправлены среда/fixtures, без отключения AppArmor, проверки TLS или production ownership. Временные ключи WG создаются в разрешённой приватной папке `/etc/wireguard/razvilka-native-*`, затем удаляются тестом. Логи сохраняют и неудачные, и успешный запуски.

`check-linux-05` на `dc7370a` выявил три непереносимые fixture в AWG/WARP: поддельные вызовы не были изолированы от настоящих `wg`/`wg-quick` в PATH. Этот прогон имеет RC 1 и не объявляется успешным. Дублирующий полный Windows-прогон остановлен координатором без результата; он не заменяет Linux gate.

Native fixtures не закрывают полный LAN executor, TUN selected/control, аппаратную AWG совместимость или D14. Итоговая аппаратная приёмка остаётся отдельной.

На `367ef14` повторены все три native группы: `native-round-04`, RC 0 для WG, Xray и новой kernel-проверки точной очистки policy. Настоящий iproute2 подтвердил сохранение foreign host routes в обеих семьях и отказ удалять default с чужим protocol. Первый запуск нового QA-теста не поднял loopback в пустом namespace; fixture исправлена до повторного успешного запуска. Это реальный kernel-тест, но не live endpoint lifecycle нового WG pin.

WG endpoint checkpoint `0357f4e` добавляет точные rule/host-route, mark, DNS lease/WAN revalidation и cleanup/rollback. Callback владения host-route подключён к Engine Lab в `367ef14`. Его native endpoint lifecycle и crash window ещё открыты; полный отчёт — D04_D05_NET_CHECKPOINT_RU.md. Отдельно не доказана доступность прежнего live WireGuard после candidate с тем же peer/key: remote Noise/endpoint state может измениться. Этот сценарий явно передан следующему NET чату и не скрывается перезапуском fixture.

Итоговый `check-linux-06` на `367ef14dc67750f6fb141e346f6d3508c492f01e` завершился **RC 0**, `RAZVILKA checks: OK`: штатный Go 1.26.5, go mod verify, обычные и race тесты всех пакетов, vet, UI/shell проверки, сборки Linux amd64/arm64/mips/mipsle с SHA-256, установка/обновление/откат/удаление в изолированном тестовом корне. Три fixture-регрессии предыдущего прогона устранены. Это проверенная общая база для чатов 6.1 sol; перечисленные функциональные и аппаратные ограничения остаются открытыми.

## Интеграция первых пяти чатов Sol

`check-linux-07` на `99ac304778f881bab24692f9d87f880d41da4d09`: **RC 0**, `RAZVILKA checks: OK`. Проверены Go 1.26.5/mod verify, обычные/race тесты всех пакетов, vet, UI/shell (включая новые auth actions и self-update receipt gates), все четыре Linux-сборки и SHA-256, изолированный Entware install/update/rollback/remove. Новый self-update модуль пока не подключён к реальному пути обновления: прохождение тестов не закрывает D11 и не разрешает установку промежуточной копии.

`native-round-05` на той же базе имеет **общий RC 1**:

| Проверка | Фактический результат |
|---|---|
| WG CandidateIsolation | PASS IPv4/IPv6: kernel WG, TCP/UDP, live после успешного и неуспешного отдельного кандидата; одинаковая client identity отвергается до создания canary |
| WG EndpointLifecycle | FAIL: IPv4 probe timeout, следующий IPv6 — неоднозначный WAN; NET получил журнал, семьи стенда затем разделены, добавлены снимки ядра для диагностики |
| Xray ExactNode / StoreConfigSyntax | PASS native Xray 26.3.27 TLS и REALITY, hostname/IP, остановка/возврат сервера, неверный UUID, kill/recovery клиента и компиляция engine-aware store material |
| PolicyCleanupPreservesForeignRoutes | PASS настоящее ядро IPv4/IPv6, foreign host routes сохранены, чужой protocol отвергнут; создание чужого default ещё требует исправления CORE |
| ComponentInstalledExecutableAcceptanceUsesKernelIdentity | PASS настоящий дочерний процесс и `/proc` inode, устаревший исполняемый файл не принимается за обновлённый |

Для native opkg собрана отдельная тестовая копия OpenWrt `80503d94e356476250adaf1f669ee955ec26de76` (revision из Entware), libubox `1aa36ee774c8db4d7a396903e0d2e1fb79ee8bf1`, в пользовательском каталоге Ubuntu. Системная база пакетов и роутер не использованы. `native-opkg-01` выявил неверное размещение compile-time lock внутри offline-root; среда исправлена. `native-opkg-02` выявил несовместимый формат синтетического IPK (`Malformed package file`); OPS получил дефект fixture. Успешного реального package update/rollback пока нет.

Readonly проверка Netcraze: Linux `4.9-ndm-5 aarch64`, opkg той же revision `80503d94`, `/proc/self/ns` содержит только `mnt`; PID namespace и cgroup interface отсутствуют. Обязательный PID-namespace supervisor здесь непригоден. OPS/CORE получили аппаратное ограничение до внедрения; нужна поддерживаемая supervision с доказательством завершения потомков. `/proc` scan без durable receipt не превращает unknown в успех. Настройки и установленная версия роутера этой проверкой не изменены.

## Следующая интеграция: настоящие пакеты, WG и scoped Xray

- `native-opkg-03` выявил две ошибки fixture: нужен экспортируемый `PKG_ROOT` и явная родительская запись каталога в IPK. После исправлений OPS `9bdf305` и `6523002`, **native-opkg-04 RC 0**: настоящий opkg в изолированной базе, postinst/config migration, rollback и interruption без повторной неизвестной команды. Это upstream OpenWrt opkg на revision Entware, не полная сборка с патчами Entware. Новый subreaper supervisor в этот прогон ещё не входил.
- На настоящем Netcraze отдельная временная программа Go/ARM64 подтвердила `PR_SET_CHILD_SUBREAPER`, adoption detached ребёнка и `wait4 → ECHILD`, RC 0. Файл перед запуском сверен по SHA-256, после проверки удалён. Это проверка возможности ядра, не готового package supervisor. Дополнительное чтение обнаружило отсутствие `/proc/PID/task/PID/children`; OPS получил требование совместимого завершения зависших потомков. Пакеты, настройки и сеть роутера не менялись.
- `native-wg-06` выявил реальную несовместимость чтения обычного IPv6 `from: "::"` и ошибку WAN fixture. `be5e399` исправляет parser и стенд. В `native-wg-07` реальный handshake/Activate/Health/Commit прошли, но assertion неверно сравнивал JSON table number и string. `e58bc32` добавляет строгое семантическое сравнение, включая отклонение чужой таблицы.
- **native-wg-08 RC 0** на интеграции `e58bc32`: `TestWGNativeEndpointLifecycle`, IPv4/IPv6. Проверены настоящий WAN control, отклонение неверного ключа, изолированный candidate с handshake, exact endpoint pin, lifecycle/revalidation/cleanup. Это Linux VM; router/app reboot и physical HIL не заявляются.
- CORE `dc17f55` завершает matching operation receipt после journal settlement; `b3bc486` проверяет обе таблицы до записи, отказывается занимать существующий default и сохраняет чужие tuple при частичном сбое. **native-scoped-01 policy RC 0**: foreign default, injected IPv6 refusal с настоящей IPv4 cleanup, конкурентный идентичный IPv6 tuple. Последующий adapter rollback по staged intent ещё требует durable addition receipt; primitive PASS не закрывает общий ownership.
- VLESS `0669514`, **native-scoped-01 Xray RC 0**: Xray 26.3.27 и Sing-box 1.13.3, настоящие TLS server/client, gVisor TUN, kernel RPDB/iptables и selected/control LAN clients в изолированных namespaces. Пройдены A, повторная загрузка adapter из состояния, kill/restart sidecar, B failure → verified rollback A и фактический трафик. Новая копия adapter не означает app restart/reboot. Production wiring, UDP/IPv6 и router HIL остаются открытыми.
- UI `2ba264e`/`988aebd` объединены: matching recovery read/review, устаревшие действия требуют нового чтения, неизвестный POST не повторяется. Координатор независимо повторил 14 UI unit scenarios (RC 0), просмотрел реальные desktop/mobile PNG исполнителя и принял исправление отступов и закрытого мобильного меню. Browser report исполнителя: 12/12 с настоящим HTTP и отдельно помеченными journal fixtures/transport faults; это не native acceptance пакетов.

Адресный интеграционный Windows Go-прогон после CORE/VLESS merge: app component HTTP/recovery, dataplane policy/scoped Xray и nodestore history compatibility — RC 0. Новые журналы сохранены в локальной `.review-local`; штатный полный Linux gate предыдущего checkpoint не переносится автоматически на эту интеграцию. VERSION не изменён, новая копия не опубликована и не установлена вместо действующей.

### Повторная общая проверка и аппаратная регрессия

**check-linux-09 на `7f5d5cc`, RC 0**, `RAZVILKA checks: OK`: Go 1.26.5, mod verify, все обычные/race тесты, vet, UI/shell gates, Linux amd64/arm64/mips/mipsle, SHA-256, Entware install/update/rollback/remove. До этого `check-linux-08` на `89c79c3` имел RC 1: новые Xray unit fixtures создавали временные каталоги с неподходящими правами. `169dade` задаёт им 0700; production guard не ослаблен. Последующие коммиты проходят отдельные проверки и автоматически этим общим PASS не покрываются.

`native-scoped-03` на том же тестовом бинарнике source-16: **Xray 26.3.27 + Sing-box 1.14.2 PASS, RC 0**, та же selected/control и rollback матрица. Промежуточный `native-scoped-02` не запустил тест из-за CRLF в одноразовом shell-сценарии координатора (`4m\r`); лог сохранён, скрипт нормализован перед повтором. Production код не менялся ради этого запуска.

После OPS `655d5f8`/`5f030de`/`ba99ef4`, `native-opkg-05` подтвердил race/process сценарии subreaper и настоящий opkg. Review выявил, что успешный exit родителя не должен скрывать принудительное завершение detached ребёнка. `39bbdc7` добавляет durable cancelled/nonzero outcome. **native-opkg-06 RC 0**: race тесты cancellation after successful parent, hung deadline, stat-only cleanup, detached/supervisor death, new-boot interpretation; затем два настоящих opkg сценария. Это Linux VM, локальная offline база, не system opkg и не physical power cut.

Тот же process-only набор `39bbdc7` на настоящем Netcraze ARM64 имеет **RC 1**: cancelled-after-parent PASS, stat-only cleanup PASS, detached/supervisor death PASS, new-boot PASS; hung deadline не получил durable reap. В отличие от VM, перед запуском потомка на USB возможны значительные задержки записи. OPS получил конкретный журнал и review установки SIGTERM handler после начала запуска/записи receipt. Тайм-аут нельзя объявлять успехом: unknown сохранён. Проверка не запускала настоящий opkg, не меняла network/config/packages. После завершения проверено отсутствие тестовых процессов; тестовый binary оставлен в точной временной папке до разбора. Полный D11 этим аппаратно не принят.

Координатор независимо запустил настоящую объединённую Windows-сборку с отдельным состоянием на 127.0.0.1:18852: **13 браузерных сценариев RC 0**, локальные артефакты `.review-local/ui-http-gCjLJg`. Auth/logout, реальный CAS/401/403/recovery 503, закрытое/открытое меню 390 px с фокусом и нижней навигацией прошли. Journal fixtures и transport faults явно отделены от настоящего HTTP; config не изменён, процессы стенда завершены. CORE `74b987c` затем добавил matching idle API/capabilities и private supervisor CLI; адресные app/CLI тесты координатора RC 0, полный новый Linux gate ещё предстоит.

### Повтор supervision на ARM64 и новая схема recovery UI

OPS `93be1a4` устанавливает обработчик сигнала до длительных записей и запуска потомка. `native-opkg-07` при этом имел RC 1 из-за ошибочного теста: fixture сама завершалась раньше нового deadline. Исправление `3daf179` отменяет операцию только после наблюдаемого запуска действительно зависшего потомка; дополнительный тест отмены до запуска проверяет отсутствие command receipt.

**native-opkg-08, RC 0** (source-22): race-проверки supervisor, отмены, detached child, supervisor death и new-boot; затем оба настоящих offline opkg сценария. На этой же исходной версии собран ARM64 test binary. **Netcraze process-only повтор RC 0**: шесть выбранных сценариев, включая отсутствие children interface, отмену до запуска и durable завершение зависшего потомка. Последний сценарий занял 10,25 с на USB, запуск потомка наблюдался через 652 мс. Отсутствие процессов и точечная очистка обеих собственных временных папок проверены; прежний неудачный журнал сохранён на ПК. Пакеты, сетевые настройки и установленная панель роутера не менялись. Реальные service-autostart hooks при обновлении пакета и self-update ещё требуют отдельных проверок; D11 не закрыт.

CORE `0c99bf0`: независимый адресный HTTP regression RC 0. Старый terminal journal завершает свой scheduler checkpoint, сохраняя точные байты более новой operation receipt; package/live действия повторно не выполняются.

UI `d634ebd`: независимые 18 recovery UI сценариев RC 0. Повтор настоящего интеграционного HTTP/browser на 18852 — **14 сценариев RC 0**, `.review-local/ui-http-BOLsLj`. Проверены schema 1/2, серверные available actions и нейтральный статус accepted-installed-idle; новые неизвестные схемы не считаются поддержанными. Конфигурация не изменена, временный сервер и браузер завершены. Это всё ещё отдельный desktop gate, не замер ARM64 UI.

AWG prerequisites: pinned tools `ee0f0a9` и module `4569c4c` собраны в Ubuntu kernel `7.0.0-34-generic`, build RC 0. Собственный модуль установлен в отдельный VM-only каталог и штатно загружен без force, load RC 0. Loaded version `3.1.20260906`, srcversion `8B43245B4272244B0CB9617`, initstate live, unsigned taint E. При review выявлено, что исходная проверка требовала ровно 24 символа srcversion, тогда как настоящая сборка даёт 23. NET готовит исправление формата; соединение AWG на этой точке ещё не проверено. На роутер модуль не переносился.

### AWG, журнал правил и интерфейс — 04.10

NET `2c3d8b8` принимает настоящий 23/24-символьный srcversion. Первый запуск `native-awg-01` выявил другую несовместимость: разрешение symlink `/usr/sbin/modinfo` в `kmod` изменяло команду multicall, поэтому чтение module metadata отказывало. `c334eee` сохраняет путь вызова утилиты; проверка точного пути и SHA самого AWG не ослаблена. **native-awg-02, source-24, RC 0**: actual CLI/module inventory, race и regression multicall; настоящий AWG 3.1 server/client — TCP/UDP IPv4/IPv6, live-after, отклонение того же ключа и неверного peer. Затем повторены native WG candidate isolation и endpoint lifecycle обеих семейств. Это VM с указанным выше модулем, не AWG на Netcraze, не reboot/полный D06.

VLESS `0d49f3e`: **native-policy-receipt-01, source-25, RC 0**. Race проверяет общий durable журнал добавленных правил; отдельный пустой netns — 12 настоящих subprocess crash boundaries до/после add/ack и cleanup/delete/absence. Новый читатель не повторяет неизвестный effect и не присваивает чужие правила. Root review дополнительно обнаружил повторный promotion в уже удалённое/перенесённое поколение; `7253153` запрещает это, адресные Windows regression RC 0. Полное подключение proxy/WG, startup и CommitRollback ещё не покрыты этим PASS.

UI `61a823f`: независимый **настоящий HTTP/browser 17/17 RC 0**, `.review-local/ui-http-5zBTmC`; 11 card-flow unit scenarios RC 0. Переходы между шагами выбранного движка не отправляют записи и сохраняют dirty draft. Отдельные фиктивные каталог/узлы проверяют ИИ-группу, область all-VLESS, защищённый резерв и отсутствие повторного commit после потерянного ответа. Auth/CAS/recovery/mobile регрессии пройдены. Конфигурация и mutable состояние изолированы; installed inventory читает бинарники host (в том числе существующий Windows `awg.exe`), что не доказывает native совместимость. Процессы стенда завершены.

UI `b270592`: принят измеритель существующего HTTP сервера, root boundary tests 6/6 RC 0. Его метрики относятся к браузеру; CPU/RSS ARM64 измеряются отдельно. Этот checkpoint ещё не содержит аппаратного performance PASS.

Исследовательский чат передал `48b3ab0` с закреплёнными upstream revisions и лицензиями. Важное ограничение D11: stock NFQWS2 hooks запускают daemon/firewall и не поддерживают общий ENABLED guard. Для обновления требуется отдельный проверенный lifecycle contract; offline opkg с PKG_ROOT сам по себе не изолирует абсолютные `/opt` paths. CORE `7b8db16` пока не принят в integration: независимый durable Stop и остановка старого процесса до замены файлов остаются условиями приёмки. Исследовательские выводы не считаются runtime PASS.

### Новый Linux gate и измерение интерфейса на Netcraze

`check-linux-10`, source-26 / `bb64686`: Go 1.26.5 mod verify, весь `go test ./...`, весь `go test -race ./...`, vet, Node/shell gates и ARM64 build/checksum прошли. Скрипт целиком имеет **RC 1** на последнем Entware fixture: режим `RAZVILKA_BUILD_TARGETS=arm64` не создаёт native amd64 бинарник, который этот VM-тест устанавливает. Проверку не пропустили: в том же source-26 собран только дополнительный amd64 binary с VERSION 0.19.3, обновлены тестовые checksum; **`check-linux-10-install` RC 0**, `Entware transaction test: OK`. MIPS/MIPSel в этом повторе не собирались. Это две проверенные стадии, а не выдуманный RC 0 первого скрипта; composition общего gate требует небольшого исправления.

D09 `d64ac97` и D13 `8821fd1`/`c44ffee` приняты после review как библиотечные порции. **`cloud-nfqws-01`, source-27 / `549308b`, RC 0**: Linux race для strategylab/warp/usquediag/sources, адресные app-регрессии и vet. NFQWS native assets/пробы, новые USQUE transport receipts и подключение worker остаются открытыми. Новый enrollment root из handoff — только предложение: до доказанной необходимости миграция не согласована; сохранение нынешних immutable facts вне mutable restore рассматривается первым.

На Netcraze запущен ARM64 source-26 на отдельном порту **18854**, Safe Mode, собственные private paths, без probes/Apply. После измерений процесс завершён, обе созданные временные папки проверены на отсутствие работающего executable/symlinks и удалены. Основная установленная панель 8787 не заменена.

- Пустая библиотека: `.review-local/ui-perf-RDZm6u`, все 14 измерительных фаз завершены, но **итоговый RC 1**: первоначальный измеритель ошибочно считал 14 автоматически обнаруженных LAN устройств заполненной пользовательской библиотекой. `cf0796d` исправляет классификацию и отдельно сохраняет discovery counts; root 7/7 boundary tests RC 0. Исходный failed отчёт сохранён без изменения результата.
- Загружены **100 фиктивных VLESS `.invalid`**, только в изолированную библиотеку; подключения не проверялись и не применялись. `.review-local/ui-perf-jeW3r9`: **RC 0**, 14 измеренных фаз; background-tab честно skipped, так как headless Chromium не сообщил hidden. Нет запрещённых запросов, browser errors или горизонтального переполнения. Запросы страницы только GET; отдельные setup/import до замеров не считаются read-only действиями измерителя.
- Через SSH `/proc` получены 77 samples за 76,58 с загруженного сценария: mean CPU самого процесса **10,98% одного ядра**, reaped children отдельно **12,63%**, RSS **27,13–30,48 МиБ**. Единицы взяты из настоящего auxv: CLK_TCK 100, page size 4096. Это не общая нагрузка роутера, не непрерывный пик и не оценка пользовательского браузера. Браузерные CDP метрики и серверные значения не смешаны.
- Baseline выявил hidden editor GET NFQWS2 и периодические `/connections` на Home/Nodes; переданы UI для исправления. Холодное открытие выполнило 40 API reads; полученные числа — до оптимизации.

Оговорка окружения: правила IPv4/IPv6 в начальном и конечном снимках совпали, но hash **основной** конфигурации за время теста изменился. Её рабочая автоматика выполняла старую транзакцию `dp-763dbbc4cb16a3f8`, начатую **21:31:39 UTC**, до запуска временной копии **21:32:25 UTC**; application timestamp основной конфигурации 21:32:27, transaction committed 21:32:29. Затем старая панель выполнила ещё одну транзакцию. Read-only аудит CORE не нашёл startup writer из isolated Store в production config. Поэтому неизменность основной конфигурации и полностью свободный роутер не заявляются; измерения проведены рядом с действующей автоматикой. Старые пользовательские настройки не откатывались.

### Старый экземпляр отключён для испытаний — 04.10.2026

По явному разрешению владельца root остановил установленную 0.19.3 и отключил её автозапуск: `S99razvilka` имеет mode 0644, установлен штатный `boot-disabled`. Перед остановкой сохранены исходные настройки, binary и init; после остановки — полная копия состояния, предыдущих backups, cache и logs. Архивы находятся вне Git в `C:\Projects\RAZVILKA-router-backup-2026-10-04`; SHA-256 локальных файлов сверены с архивами на роутере. Это приватная резервная копия, не публикуемый артефакт.

Установленная CLI выполнила `recover-private-restore` (`ok=true`) и `deactivate-dataplane` (все восемь adapter steps — `deactivated`, RC 0). Отдельный пакет NFQWS2 сначала сохранил собственные списки, поэтому для чистых испытаний его конфигурация также скопирована, сервис штатно остановлен, автозапуск отключён mode 0644. Сам пакет сохранён. Первое выполнение его stock init внутри длинной SSH-команды столкнулось с `pgrep -nf`, совпавшим с parent argv; короткая самостоятельная команда stop завершилась RC 0. Это не ошибка ownership-доказательства RAZVILKA, но ограничение upstream init при испытаниях.

Итоговая проверка: процессы RAZVILKA/NFQWS2/Sing-box/Xray/USQUE отсутствуют; порты 8787 и 18854 закрыты; таблица 203 пуста для обеих IP-семейств; цепочки RAZVILKA/NFQWS отсутствуют. Контрольный HTTPS с роутера вернул 200. Entware и остальные системные сетевые правила сохранены. Временные копии архивов удалены с роутера после проверки PC backups. Новая рабочая копия ещё не установлена как основной сервис; для следующих тестов разрешено отдельное контролируемое окно.

### Повтор UI и CLOUD после отключения старой автоматики

Приняты UI `a31f505`/`af7db65` и CLOUD `4d15788`; integration `59232dd`. Независимый review CLOUD не выявил конкретных дефектов. Root Windows Go1.26.5: warp/usquediag/privaterestore RC 0, opt-in native localhost H2/H3 включён; UI lifecycle/cards/generated CSS RC 0. Linux `cloud-native-02`, source-28, RC 0: семь реальных localhost TLS/H2/H3 сценариев и race трёх пакетов. Первый `cloud-native-01` имел RC 1 из-за CR в последнем аргументе локального launcher; его native transport часть прошла, ошибку launcher исправили и повторили весь адресный прогон. Это не доказательство реального WARP/MASQUE сервиса и не завершённый installer retention gate.

ARM64 UI вновь запущен из изолированного каталога на 18854, Safe Mode. Пустая библиотека и 100 фиктивных `.invalid` nodes: **оба browser measurements RC 0**, по 14 выполненных фаз; background скрытая вкладка по-прежнему skipped в headless. Артефакты `.review-local/ui-perf2-empty/ui-perf-8e7Tew` и `.review-local/ui-perf2-loaded/ui-perf-cUAdmR`. Browser errors/blocked requests/горизонтальное переполнение — 0. Нежелательные `/connections` и guided editor reads на проверенных посторонних страницах отсутствуют. Cold API reads: 39 empty, 40 loaded; снижение общего числа cold reads не заявляется.

58 loaded samples за 57,35 с: mean CPU процесса 10,13% одного ядра, reaped children отдельно 10,92%, RSS 27,43–31,12 МиБ. Это часть окна measurement; при старом повторе была включена production автоматика, поэтому прямую причинную оценку ускорения из двух CPU чисел делать нельзя. Hash основной config и IPv4/IPv6 rules теперь сохранились точно. Тестовый процесс и каталог удалены после проверки его отсутствия; временные credentials удалены вместе с ним, локальный session password redacted. Старый основной сервис и NFQWS2 остаются отключёнными.

Независимый review следующих NET/VLESS порций обнаружил два незавершимых retry после определённого сбоя rollback (proxy phase `restoring`; WG publication до отдельного rollback marker). Они переданы владельцам, порции пока не приняты. Результаты ранее принятых native тестов эти новые изменения не покрывают.

### Объединение исправлений повторного отката и независимого Stop

`check-linux-11`, source-30 / `395ddbf`, **RC 0**: Go 1.26.5 mod verify, полный обычный/race/vet прогон, UI/shell проверки, ARM64 и дополнительный native amd64 бинарник, проверки архитектуры/checksum и полный Entware fixture установки/обновления/отката/удаления. Исправление build composition `53bcc93` не пропускает installer gate и не собирает MIPS/MIPSel в промежуточном ARM64 прогоне.

NET `ef2d7b5` и VLESS `7ce1f0c` исправили указанные выше retry: сохранённая привязка исходной транзакции к восстанавливаемому поколению предшествует публикации. Независимый review committed code не нашёл новых конкретных дефектов; integration приняла полную ancestry с общими receipts, proxy/WG lifecycle и библиотечным first-usable/refill. Неизвестные результаты kernel effects не переименованы в успешный rollback.

CORE `46da168` с предшествующим `3c3a6a`: независимая durable команда Stop подключена к HTTP и раннему startup, до создания обычных файлов/восстановления mutable config. Stop не должен ждать installer lease. Состояния requested/corrupt/incomplete блокируют эффекты. Полный provider, остановка/join старого процесса, cleanup и явный Resume пока не приняты: capability остаётся 0, Resume — 503. Это промежуточная работа D11, не завершённое самообновление.

`native-integration-12`, source-31 / `d010e13`, имеет **общий RC 1**. В race-прогоне выявлены два несовместимых dataplane regression fixtures и два отказа retained node history; переданы CORE/OPS. В launcher также ошибочно указан несуществующий `internal/dnsmanager` вместо `internal/dnscontrol`; DNS этим запуском не проверен. Ошибки и исходный журнал сохранены, общий PASS не заявляется.

Успешные независимые стадии того же запуска: race nodestore/providerfeed/operationgate/warp/usquediag/netresolve/config; выбранные настоящие HTTP Stop и startup subprocess проверки; vet; компиляция Linux dataplane test binary. CLOUD `f860c3d`: все три opt-in retention сценария **RC 0** — timeout/pending, subprocess crash после durable response, отказ whole-root manifest до Stop/замены binary. В сценариях используются реальные production file selectors/prune/rollback script и файловые hashes/modes/inodes, но удалённая регистрация и runtime представлены описанными test fixtures. Это не регистрация Cloudflare и не native provider acceptance. Секреты/логи остаются в игнорируемой `.review-local`.

`native-kernel-12`, тот же source-31, **RC 0**: 12 subprocess crash boundaries общего kernel receipt; foreign defaults/host routes и отказ частичной IPv6 операции; WG cold candidate, одинаковые Address, неверный/same peer, live-after, TCP/UDP IPv4/IPv6; endpoint lifecycle для обоих семейств. Новые WG rollback cut проверены на настоящем kernel: сбой очистки operation и отдельной записи final marker завершается retry с тем же интерфейсом/поколением, прежний peer снова передаёт трафик. AWG 3.1 и scoped Xray TUN с Xray26.3.27/Sing-box1.14.2 также прошли; Xray selected/control A, новая adapter instance, sidecar restart, неудачный B и verified возврат A. Условия и pinned runtimes те же, что указаны выше; Интернет и роутер этими namespace тестами не менялись.

После независимой сверки собственного DoD этап **D04 закрыт**: его native isolation/cold-start требования проверены. Это не закрывает named WG app CRUD/резервы D05, AWG production D06, общий LAN/DNS D07/D08 или аппаратную/длительную матрицу D14. Библиотечный D02 RAW/TCP Reality уже имеет native evidence, но отдельный XHTTP остаётся открытым. D00 обозначает завершённую исходную интеграцию; найденные новым source-31 regression failures всё равно должны быть исправлены до следующего общего release gate.

### Интеграция общего исполнителя, повтор UI и новые отказы CI — 04.10.2026

`dns-race-01`, source-31, **RC 0**: исправлен путь launcher на `internal/dnscontrol`; DNS/netresolve race и vet прошли. `check-linux-12`, source-32 / `b5357b4`, **RC 1**: два dataplane fixtures ещё не соблюдали строгий receipt/private-directory контракт. CORE `3a36b76` исправляет именно fixtures, не ослабляет production. CLOUD `4fd37fb` retention test прошёл пять leaf scenarios, включая отказ несовместимой retained node history до Stop.

`check-linux-13`, source-34 / `bdb235f`, **RC 1**: исправленные dataplane cases, весь обычный Go-прогон, race, vet, shell syntax, bootstrap/build-targets/uninstall прошли. Затем DNS rollback shell fixture не ответил на новый обязательный `-check-node-history-state`, и gate остановился до UI/финального installer transaction. Следом такой же fixture defect найден в autonomy rollback и записи числа CLI-вызовов architecture test. Полный PASS этого запуска не заявляется; исправления переданы OPS.

DEFAULT `16c877e`: первый guarded compiler/Manager consumer для общего default и сервисных CIDR overrides принят. `default-01`, source-33 / `a3a7944`, **RC 0**: Linux race адресного app-набора и vet. Это библиотечная проверка plan/CAS/Stop/rollback, не факт прохождения LAN packets. Domain-aware путь и единый LAN gate остаются обязательными незавершёнными зависимостями. `NETWORK_POLICY_EXECUTOR_REQUIRED` не удалён ради приёмки.

CORE `ab9d769`: атомарная запись applied NetworkPolicy/services с полной проверкой прежнего образа и точным undo. `config-default-03`, source-35 / `d37246f`, **RC 0**: реальные Store/CAS tests, default consumer tests, race и vet. Случаи включают незаметную смену AppliedServices при той же revision, external file replacement, Stop/SafeMode, поздний undo и сохранение редакторских изменений. Первоначальный `config-default-02` использовал неверный фильтр имени config tests и не засчитан как их проверка; повтор `03` действительно выполнил их. Последующий `47a222b` объединяет расчёт postimage с production Store, адресный повтор после следующей порции ещё нужен.

UI `2314508` и `2c6e239`: coalescing/read cache плюс защита aggregate read от устаревшего epoch. Настоящий HTTP/browser на source `549384f`, `.review-local/ui-http-7umcNQ/result.json`, **19/19 RC 0**. Проверены auth/CAS/recovery/dirty/mobile, cold shared API читаются один раз, explicit refresh получает свежие данные; config не менялся. Временные desktop server/browser остановлены.

ARM64 `ui-perf3-empty/ui-perf-uTo343` **RC 0**. `ui-perf3-loaded/ui-perf-1DcZei` **RC 1** после девяти успешных фаз: rapid-tabs-return-home не завершил assertion; исходный harness сохранил только тип ошибки, поэтому точная причина ещё уточняется UI. Это не общий loaded PASS. Ошибок браузера и запрещённых запросов не зафиксировано. Настоящее hidden-tab измерение также пока не принято: отдельные попытки через browser focus/minimize/CDP продолжали возвращать visible; подмена document.visibilityState не использовалась. Тестовый ARM64 PID/каталог удалены, private session отредактирована с удалением пароля, основная config и IPv4/IPv6 rules неизменны. Старый основной сервис остаётся выключенным.

DEFAULT `6a4bfb7` сохраняет selected-device/excluded-device MAC authority при появлении нового IPv6 privacy address и при отсутствии lease. Принят после root review; его новые regressions ещё требуют следующего Linux повтора. RESEARCH `b0f043b`/`477d411` приняты как проектные материалы по LAN/DNS/domain-flow и production Xray TUN verifier; сами документы не являются runtime evidence.

### LAN admission, DNS publication и supervised update: проверка объединённых частей

LAN `7e31331` сначала не принят: отрицательная метка очищала незарезервированный firmware bit, а symbolic `rt_tables` names обходили проверку старых selectors. `7032721` исправляет оба случая; `416a14e` добавляет реальный readback token `proto`, MAC whitelist и зависимости порядка удаления. Root принял только исправленную ancestry. `policy-review-04`, source-36 / `2df4f74`, **RC 0**: config CAS/postimage, DEFAULT MAC/classification/rollback, LAN compiler/readback collision tests, race/vet. Это ещё не native LAN packet acceptance и не общий Manager с подключённым gate.

OPS `5ff37c3` сначала задержан: caller возвращался после cancellation без join собственного worker. `8f96be6` добавляет bounded join и проверку durable ECHILD/identity; неподтверждённое завершение остаётся unknown. С ним приняты `0839f56` (правильные installer fixture ответы) и `a160a54` (перезапуск неизменённой старой панели при отказе после Stop, если не появился пользовательский Stop/control fence). После повторного review конкретных дефектов не осталось. Capability production не открыта автоматически; actual main/HTTP/provider wiring и full app acceptance остаются CORE.

NET `5a13285`/`5778aa4`: существующий scoped DNS listener передаёт ответ через проверку владельца; combined Exchange даёт окончательные bytes внутри одной generation/device lease, без повторного Resolve. DEFAULT/CORE должны предоставить настоящий owner, callback сам его не создаёт. CORE `2313e00` сначала задержан из-за возможности alias `203 main`; принят только вместе с `89966b3`, требующим числового чтения RPDB и отказа при недоказанном формате.

`ops-dns-native-14`, source-37 / `87a756b`, **RC 0**: DNS/autonomy/history rollback, выбор архитектуры/mandatory checksum, history/legacy update consumer, native self-update worker/child cancellation и файловые CAS/rename tests, DNS race, default dependency race, vet. Native update запускает реальные синтетические дочерние процессы и kernel/file operations внутри TempDir; не использует opkg, настоящие tunnels/accounts или рабочую сеть. DNS live Quad9/client canaries в этом запуске явно SKIP. Это независимая native проверка механизма, не доказательство всего обновления работающей панели.

UI `415e266` меняет только measurement diagnostics. Root boundaries suite **10/10 RC 0**. Повтор на ARM64 с тем же binary `549384f`, новой отдельной библиотекой из 100 `.invalid` nodes: `.review-local/ui-perf4-loaded/ui-perf-oBLAA2/result.json`, **RC 0**, 14 измеренных фаз. Rapid navigation завершилась overview; исходный intermittent RC1 не воспроизведён, причина не объявляется исправленной. Background по-прежнему skipped, поскольку браузер не сообщил hidden. Тестовый процесс/каталог удалён; production config/rules неизменны. Независимый sample window предыдущего неуспешного perf3: 75 samples / 74,46 s, mean CPU 8,85% одного ядра, reaped children отдельно 8,69%, RSS 27,32–30,87 MiB; этот неполный участок не является общим performance PASS или доказательством ускорения.

VLESS `76d817b`/`76a3cd0` приняты после независимого review: отказ пересекающихся exits в destination-only backend и одноразовый source-bound LAN HTTPS producer. Producer не выдаёт самостоятельный NodeTUNObservation/router proof. Независимый Linux повтор включён в следующий полный `check-linux-14`, source-38 / `4518a40`; на момент записи ещё выполняется.

### Linux, настоящий браузер ARM64 и genuine NFQWS — продолжение 04.10

`check-linux-14`, source-38 / `4518a40`, завершился **RC 1**: обычные Go/race/vet и shell checks прошли, старый изолированный `test-ux-stage1.mjs` не включал новый `invalidatePanelReads`. UI `c8c7ca5`/`58661793` исправляют fixture реальными shared-read helpers, проверяют epoch/abort и отбрасывание позднего ответа. `48b31cc` отображает durable Stop как «Остановка запрошена», не утверждая, что cleanup уже завершён.

`check-linux-15`, source-40 / `642124f`, **RC 1**: Go1.26.5 mod verify, все обычные/race/vet, UI (включая stage1 53/53), shell, ARM64+native amd64 build и SHA прошли. Финальный Entware transaction fixture отказал `Target binary cannot read all retained node history; installation unchanged`; передан OPS. Весь gate не считается пройденным.

Независимый ARM64 browser cycle на временной панели `18854`: `.review-local/ui-visibility-arm64/ui-visibility-cdp-RbESS8/result.json`, **RC 0**. Собственное окно Chrome минимизировано настоящим CDP window operation; document оставался hidden 16 секунд, UI API requests **0**. После native restore — visible и **9** свежих завершённых чтений. Visibility/lifecycle не подменялись; ошибок/заблокированных мутаций нет. Отдельный temporary server и проверенный private каталог удалены, credential redacted, production config и обе семьи rules неизменны. Основной сервис остаётся выключенным по разрешению владельца; этот тест не подтверждает работу обходов.

`nfqws-kernel-39`, точный `9cdcbff`, **RC 0**: 13 реальных subprocess/subreaper cases и controller cancel/crash/Stop/foreign epoch. `f7a46bf` дополнительно исправляет CAS/cancellation публикации; atomic rename→Stop/crash окно требует общей admission, поэтому capability остаётся закрытой.

`nfqws-genuine40` и `nfqws-genuine-root41` — **RC 1**, не скрыты: непривилегированный NFQWS не мог выполнить setpcap; private `/root` Lua path недоступен после штатного UID drop. Первый negative fixture ложно засчитывал любой nonzero как Lua rejection; передан NFQWS owner для исправления oracle. В `nfqws-genuine-root42` public upstream payload помещён в защищённый root-owned `/opt` (755/644), controls/helper/tmp сохраняют private modes. Точный официальный AMD64 v1.0.5.2 binary, ordered Lua и blobs сверены с pinned manifest. В отдельных пустых netns, `intercept=0`, **normal dry-run и Lua-init RC 0**. Отдельный намеренно изменённый `circular=nil` Lua даёт **exit 1** с framed `LUA ERROR ...: missing circular`; supervised test подтверждает обе exact ACK/ECHILD receipts. Это genuine CLI/Lua compatibility, не NFQUEUE/media/voice/runtime activation. Строгий negative test будет повторён после исправления fixture.

LAN `180b231` сначала удержан: mandatory IP-direct мог обойти конфликтующий domain-bypass, CNAME→NODATA мог продлить отрицательный DNS TTL. Принят только с `4c3a536` и `ca0b3e7` после повторного review. CORE `5454c3a` принят с mark readback fix `788ea34`/fixtures `7745a0b`; отдельный numeric endpoint text correction `b6f4f21` и NET JSON correction `8837583` сохраняют точные proto/scope semantics без adoption чужих rules.

`policy-native41`, source-41 / `0755118`, **RC 1**. Linux race DNS/domain/LAN/mixed tests прошли. Native mixed crash fixture все 30 случаев остановил на near-match firewall oracle; unknown cases перед этим сохранили полный kernel snapshot и ноль RPC. LAN packet fixture остановился при initial Activate/readback, до packet proof. Оба отказа переданы владельцам; native LAN/mixed приёмка не объявляется. VLESS mixed schema2 journal остаётся принятой проверенной реализацией без подтверждения этих native сценариев.

CLOUD producer выявил два реальных дефекта: потеря deadline в `http.Transport` и повышение обычного TLS2xx до semantic service PASS. `a5d168b` исправляет первый; второй остаётся отдельной pending правкой. Аналогичный semantic issue найден в VLESS RouterTUN HTTPS producer; production consumers пока не подключены. OPS `a1755dc` file-only managed NFQWS installer принят статически; native file/retention/HTTP dial проверки идут отдельно. Ни один новый runtime capability не включён только по этой записи.

### Повторная приёмка native LAN/mixed и установка

`cloud-bundle-native42`, source-42 / `8a3ade8`, **RC 0**. Настоящие localhost HTTP/DoH→SOCKS→TLS tests: 17 случаев, включая cancel/deadline обеих стадий SOCKS, wrong-name/trust и отдельный трёхсекундный DNS deadline. Cloud retention native subprocess/filesystem сценарии прошли без relevant SKIP: timeout, crash, retained file/helper/control refusal, unsafe manifest и несовместимый history reader. Managed NFQWS file bundle race/native Stop-before-rename и локальный официальный ARM64 IPK как данные также прошли. Это не запущенный USQUE/WARP и не NFQWS runtime.

`native-and-install43`, source-43 / `d3d7823`, **RC 0**. Сначала Linux race app self-update order/default executor, DNS/WG/mixed прошёл. Затем:

- Все **30 actual os.Exit crash boundaries** mixed receipt прошли на настоящих IPv4/IPv6 rules; unknown сохраняет целый kernel snapshot и ноль runtime RPC, known cleanup сохраняет чужие near-match tuples. Исправление `408f9f5` меняет только oracle: kernel `-C` проверяет исходный tuple, сравнивается реальный canonical baseline, не порядок argv.
- Настоящий LAN netns packet/MAC/IPv6 gate прошёл. `78ac1b9` читает bridge через netlink текущего namespace: прежний sysfs mount относился к другому netns. Production scope guard не ослаблен. Исключённый и неизвестный MAC продолжают foreign firmware-like route; выбранный получает own positive selector.
- WireGuard native candidate isolation, неправильный peer, TCP/UDP обеих семей и endpoint lifecycle прошли после numeric protocol/scope fixes. B fail→A verified rollback, оба previous cleanup/marker cut retry и новая adapter instance остаются успешны.
- ARM64/native amd64 сборки и SHA прошли. Полный Entware transaction install/update/conflict/rollback/remove **OK**. `c452428` отделяет проверку retention чужой symlink от намеренно строгого history admission; production guard сохранён.

Успешный installer replay не переименовывает предыдущие fullcheck14/15 RC1 в PASS. Свежий полный gate объединённого дерева остаётся обязательным. CORE `8dea1e5` actual app/HTTP pre-file action ordering принят, но main adapter/capability и stopped repair/Resume ещё не подключены. DEFAULT `7d0a51f`/`ecd06ae`/`9042da5` сохраняют точный config CAS и frozen LAN/generation/ingress route bindings; общий Manager participant ещё готовится.

Проверенный ARM64 perf4 sample window: **85 samples / 84,51 s**, средний CPU **9,76% одного ядра**, reaped child CPU отдельно **10,6%**, RSS **27,22–31,48 MiB**. `.review-local/router-ui-perf4-summary.json` содержит покрытие отдельных фаз. Browser прошёл 14 измеренных фаз; skipped background подтверждён позднейшим отдельным native visibility cycle. Это один window, не сравнение ускорения и не долгий нагрузочный тест.

CLOUD semantic fix `34074f5` принят после независимого review: reachable/challenge/confirmed разделены; service confirmation требует trusted full predicate на фактическом ответе внутри owned identity bracket, старые receipts не получают новый semantic grade. Актуальный Transport repeat и actual production consumer ещё нужны. NFQWS adaptive `ef0b959` удержан из-за same-second delete/re-add ABA; OPS traversal `609385a` удержан до исправления ancestor ownership/write и crash между chmod/rename. Эти findings не скрыты успешными предыдущими native runs.
