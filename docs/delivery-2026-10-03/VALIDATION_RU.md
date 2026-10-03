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
