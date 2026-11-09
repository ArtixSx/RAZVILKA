# Совместимость и состояние разработки 0.20.0

Стабильная 0.20.0 ещё не опубликована. Инструкция установки и приведённые
в ней команды закреплены за [Test v0.20.0-rc.73](releases/0.20.0-rc.73.md).
Этот номер обозначает версию инструкции, а не актуальное состояние всех
рабочих веток или версию, установленную на конкретном роутере.

Более новые исправления исходников проходят отдельные проверки. Наличие
коммита, чернового PR или успешной сборки не обновляет установленную программу.
Для испытаний нужно сопоставить точный исходный commit, контрольную сумму
бинарника, профиль роутера и результат проверки этой сборки на устройстве.

Этот Test устанавливается начисто. Обновление с 0.19.x или другой RC
не поддерживается; [порядок перехода](INSTALL_RU.md#обновление) описан отдельно.
Наличие механизма обновления со снимком и откатом не подтверждает совместимость
конкретной пары версий: такой переход требует отдельной приёмки. Если результат
неизвестен, откройте журнал и проверьте причину перед повторной попыткой.

## Роутеры

- Основная целевая конфигурация — Netcraze Ultra NC-1812, ARM64,
  KeeneticOS 5.01.C.6.0-1 с Entware.
- Сквозная аппаратная приёмка выбранных маршрутов, обновления и отката
  ещё не завершена; ограничения описаны в [матрице поддержки](RUNTIME_SUPPORT_RU.md).
- Для других моделей нужен совместимый профиль платформы. Запуск панели
  сам по себе не означает, что доступны управляемые маршруты.
- Сборки MIPS/MIPSel доступны, но управляемые маршруты на этих архитектурах
  пока недоступны. Аппаратная совместимость не подтверждена.

## Маршруты и исключения

- Основной режим — обход выбранных сервисов для всей сети. Остальной трафик
  сохраняет обычный маршрут роутера, включая ваш собственный VPN.
- Выбор отдельных устройств экспериментальный: только точный профиль NC-1812
  и один сервис с IP-сетями. Исключения устройств NFQWS2 задаются штатной
  политикой доступа Keenetic.
- Сервисы из доменных списков обслуживает NFQWS2. Прокси и VPN требуют
  определения сервиса IP-сетями; общий адрес CDN нельзя перенаправить
  по одному домену, не затронув другие сайты.
- Исключённые домены и их поддомены не обрабатываются NFQWS2. Для VPN и прокси
  используйте исключения IP-сетей или сервисов. Пересечение исключения с
  маршрутом остановит применение с объяснением.

## Компоненты

- Первая установка NFQWS2 не включает широкие штатные правила: рабочий профиль
  запускается после выбора сервисов и проверки. Обновление уже управляемого
  пакета пока недоступно, в том числе по расписанию.
- USQUE не устанавливается и не обновляется при пересечении диапазона
  `172.16.1.100–172.16.1.200` с локальными интерфейсами или сетями. Уже работающий
  штатный USQUE тоже может вызвать этот отказ. Проверьте настройки пакета.
- WireGuard, WARP и AmneziaWG остаются экспериментальными: доступность
  конкретного режима зависит от прошивки, ядра и конфигурации роутера.
- Публичные VLESS нестабильны. Импорт подписки не подтверждает доступность
  узлов; проверяйте соединение в своей сети. Автоматический резерв пока
  экспериментальный и не гарантирует непрерывный доступ.
- При неоднозначной ошибке восстановления Автопилот останавливает изменения
  сети. Причина и следующее действие показываются в журнале.

## Панель и оставшиеся этапы

В рабочих исходниках панель показывает [этап текущего раунда автопилота](PANEL_AUTONOMY_PROGRESS_RU.md).
Этот прогресс описывает выполнение операции. Свежесть данных сервиса и
подтверждение его доступности учитываются отдельно.

Полное ускорение подбора, история заданий с конечными результатами,
автоматический прокси-резерв для доменных сервисов и проверка функций
приложений с реального LAN-клиента остаются незавершёнными этапами.
Успешная HTTPS-проба сама по себе не подтверждает видео, голос или MTProto.

В исходниках после PR #21 начато устранение подтверждённых проблем обходов:
короткое продолжение продвигающегося первого поиска, параллельный контроль
выхода, полный учёт времени checker, актуальность результатов StrategyLab
и точная классификация отказов WARP. Объём исправлений, ограничения каждого
механизма и дальнейшая работа описаны в [аудите обходов](BYPASS_REVIEW_2026-10-31_RU.md).
Это изменения рабочей ветки; их наличие не обновляет установленный Test.

Ручной режим приостанавливает автоматическое применение сервисов.
Обслуживание, подписки и запланированные обновления имеют отдельные настройки;
переключение в manual не означает остановку всех фоновых задач.

[Матрица поддержки](RUNTIME_SUPPORT_RU.md) · [Установка](INSTALL_RU.md) ·
[Изменения Test v0.20.0-rc.73](releases/0.20.0-rc.73.md) · [Помощь в Telegram](https://t.me/RAZVILKA_UI)

## Исходники и приёмка на 09.11.2026

Актуальная исследовательская ветка основана на `0e2db5ab`, включая четыре
локальных коммита после опубликованного `a2d1c3c7` (draft PR #23).
Это не новый стабильный выпуск и не изменение установленного роутера.

В исходниках уже реализована совместимая snapshot3 пара бинарника и StrategyLab,
encrypted export/import, сохранение истории и ручного выбора. Старый guard-only
этап ниже описывает историю, а не полный текущий механизм. Unknown/finalizing,
владение ресурсами, CAS и проверка совместимости остаются обязательными;
старый успех не переносится на новую generation. Поддержанные переходы имеют
отдельный focused native PASS для `a2d1c3c7`, но не универсальное разрешение
downgrade и не доказательство сохранности при отключении питания роутера.

На `a2d1c3c7` generic CI SUCCESS; специализированные DNS/Mihomo lifecycle
проверки имеют FAIL/SKIP. Поэтому весь выпуск не объявляется готовым.
Причины, новые измерения, текущие владельцы и критерии приведены в
[roadmap](ROADMAP.md), [лабораторном журнале](RESEARCH_LAB_20261109.md) и
[результатах текущего прохода](measurements/2026-11-09/research/README.md).

Первая новая дельта разделяет запуск движка, готовность SOCKS и проверку
идентичности, ограничивает готовность приватным deadline и сохраняет стадии
в nodeeval/API/UI. Новые стадии диагностические; исправление deadline не заменяет
проверку сервиса. Положительный TCP/SOCKS/delay
не становится доказательством HTTPS, MTProto или рабочего LAN-маршрута.

На исследовательском `8c869c76` дополнительные первые readiness polls и
продолжение успешного node-check через обычный scheduler убирают подтверждённые
простои. В парном Linux опыте N12 full VLESS Check p50
404.777→314.996мс, selected2 enqueue→server completion2615→1444мс.
Scope, Stop/recovery, history/CAS/ownership, cancellation и joined cleanup
сохранены. Это результат контролируемого стенда; аппаратная готовность и
полный Mihomo/NFQWS/DNS lifecycle по-прежнему требуют отдельного завершения.

Повтор `2924cd74` подтверждает сокращение full VLESS Check p50
403.157→312.937мс и selected2 completion2604→1423мс на одном runner, N12.
На этой же ревизии native snapshot3/StrategyLab и restored panel PASS;
original DNS successor preparation recovery впервые проходит clean и два
частичных ACK с проверкой прежнего alias. Это диагностический бюджет30с/10с;
строгая DNS publication12с ещё не проходит. Mihomo lifecycle и managed LAN
частично остановились до тестов на HTTP504 загрузки pinned fixtures.
Подготовлен официальный Release Assets API fallback с неизменными SHA256;
он не изменяет production downloader. Точные результаты и следующие проверки:
[lifecycle журнал](measurements/2026-11-09/research/lifecycle/README.md).

На следующем `b7261e9f` Mihomo native lifecycle прошёл все три jobs:
два Apply/Check/Stop с fresh Apply и closing retry, failed Check settlement
и post-CAS rollback. Preparation recovery и StrategyLab pair повторно PASS.
Strict DNS12с и managed NFQWS LAN остаются программными незавершёнными задачами;
подробные причины и владельцы указаны в едином roadmap.

Финальный программный bfc96dd2 прошёл оба общих CI. Его специализированные
результаты учитываются отдельно: VLESS и DNS successor recovery PASS, полный
Mihomo lifecycle PASS на повторе с сохранением первого необъяснённого отказа,
strict DNS и managed NFQWS LAN FAIL. Последующая0a72dfb8 исправляет отображение
чужой/устаревшей telemetry и неизвестного process state; новые CI проверяются
для её SHA отдельно.

SSH-профиль реального NC-1812 подтверждён только чтением. Установленныйrc106
и действующий NFQWS2 не менялись; наличие SSH не является аппаратной приёмкой
текущего кода. [Фактический профиль](measurements/2026-11-09/research/router-readonly.md).

На `b5a5f58e` Mihomo полный native lifecycle, StrategyLab pair/restored panel
и paired VLESS повторно PASS. Общий CI нашёл два невалидных тестовых результата
без StartedAt; fixture исправлен в `441e97e4` без изменения production guards,
его CI проверяется отдельно. Strict DNS12с и managed NFQWS2 LAN остаются
незавершёнными программными сценариями. [Подробности и сырые результаты](measurements/2026-11-09/research/lifecycle/README.md#проверенный-b5a5f58e-и-продолжение-09112026).

## История интеграции 31.10.2026: первоначальная защита обновления

Рабочая ветка `work/bypass-integration-20261031` основана на `a36f5343`
(PR #22); локальная ветка очистки и её незакоммиченные изменения сохранены отдельно.
Состав private images прежних схем не меняется. При наличии `strategy-lab.json`
обновление и откат теперь отказывают до замены контроллера; повторные проверки
сохраняются на границах подготовки и применения. Неизвестное, повреждённое и
finalizing-состояние не удаляется. Очистка собственных ресурсов остаётся разрешённой.
Нестандартный путь StrategyLab закрывает автоматическое обновление даже при
отсутствии файла. Прямые shell-команды проверяют штатный путь и переменную среды;
они не обнаруживают произвольный путь, ранее заданный другому процессу через CLI.

Это ограниченная защита, а не завершённая миграция: совместимая пара бинарника и
состояния и проверенный old → new → restore пока
остаются блокерами выпуска. Не удаляйте состояние ради обхода отказа.

Матрица lifecycle и уровни доказательств уточнены в
[аудите](BYPASS_REVIEW_2026-10-31_RU.md). Ускорение в этом проходе не заявляется:
сопоставимых измерений живых/недоступных узлов до и после нет. Нужны отдельные
холодные/повторные замеры очереди, checker, cleanup, UI и LAN на одном стенде.
Аппаратная приёмка, WAN/reboot/power-loss и длительная устойчивость не выполнены.
Источник отдельного сайта не установлен; публикация и роутер не изменялись.
В следующем интеграционном изменении encrypted backup включает StrategyLab:
архив сохраняет точные байты, идентичности, историю и ручной выбор. Обычное
состояние восстанавливается через CAS и существующий журнал, заменяя текущее
состояние StrategyLab. Validation authority снимается без перепривязки старого
evidence к новой generation; требуется реальная повторная проверка кандидатов.
Неоднозначное назначение не перезаписывается; replay supervised ownership
запрещён. Старые четыре поколения recovery journal удерживаются вместе с новым
`private-restore-strategylab-v1`. Неизменённый старый бинарник не умеет читать
новый журнал: произвольный ручной downgrade не является поддержанным переходом.
Парное обновление бинарника/состояния остаётся отдельной незавершённой задачей.

Адресные Windows-тесты encrypted export/import, CAS/conflict, rollback, crash
recovery и startup пройдены. Более широкий Windows набор recovery обнаруживает
исходный платформенный отказ в NFQWS2 fixture: `/opt/...` не absolute Windows
path; дефект воспроизведён также на 577ebe54. Runtime-проверки не ослаблялись.
Полный Linux gate остаётся обязательным для каждого интегрированного commit.


Последняя полностью проверенная исследовательская ревизия `363f4336`:
оба generic CI и Mihomo isolated native lifecycle, StrategyLab pair/restored
panel PASS; строгий DNS и полный managed NFQWS LAN ещё FAIL.
Следующие исправления проходят собственную приёмку; [текущий журнал](measurements/2026-11-09/research/lifecycle/README.md)
содержит конкретные SHA, ограничения и сырые результаты. Готовность релиза
и физического router/LAN этим не подтверждается.


### Проверенный результат e685eb75 и следующий ручной workflow

На e685eb75 оба общих CI42618633125/42618642475, paired probe42618632990
и три original Mihomo native job42618633097 завершились SUCCESS.
Cleanup на одном стенде101→11мс, полный VLESS live Check p50309→217мс;
[данные, границы и оставшиеся FAIL](measurements/2026-11-09/research/README.md#изолированная-проверка-cleanup-на-e685eb75).
Strict DNS и полный managed NFQWS не прошли; это открытые программные задачи.

Следующий58becdc9 соединяет специальный ручной Mihomo preview/token/apply/stop
с оригинальным runtime для одного поддержанного service/client scope.
Source review и Node UI PASS; новый native HTTP/LAN сценарий требует собственного
результата CI. Ни registration, ни preview не объявлены service proof;
общий planner/AUTO не получают этот допуск. Физический роутер не изменялся.


### Проверка b9bb3c13 и последующие исправления

Оба generic CI42623923398/42623932233 SUCCESS: normal/race, UI, vet,
четыре crossbuild и modeled Entware. Три исходных native Mihomo сценария
также SUCCESS. Новый actual manual HTTP дошёл до commit/replay refusal/LAN,
после чего Stop вернул401 из-за отсутствовавшей тестовой авторизации;
3810bec исправляет fixture и сохраняет anonymous Stop refusal.
[Точные результаты и журналы](measurements/2026-11-09/research/lifecycle/b9bb3c13/).

На1a50bf07 парные VLESS/очередь и исходный двухцикловый Mihomo lifecycle PASS.
Ручной HTTP Apply/LAN подтверждён, но Stop202 пошёл по self-update recovery
из-за пустого Directory в fixture;0f043902 исправляет тестовую конфигурацию,
не обходя production guard. Новый полный manual workflow ещё требует PASS.
NFQ original quarantine и cleanup-only повторный Stop подтверждены;
полный fresh Apply и strict DNS12/4 по-прежнему FAIL по времени.
Fresh Fstat normal/race parity и microbenchmark прошли; end-to-end выигрыш
не следует из уменьшения allocations. Classic-save работает в DNS fixture,
но отдельный6pair parity setup исправленe9 и должен пройти новый запуск.
Generic1a50 focused PASS, полный запуск CANCELLED; dee compile FAIL и его
исправления сохранены в журнале. Это не заменяет последнего полного b9bb PASS.
[Точные результаты](measurements/2026-11-09/research/lifecycle/1a50bf07/).


### Завершённая общая проверка: 0f043902

Оба generic CI42630488148/42630498206 SUCCESS: normal/race, actual nonroot
permission refusal, UI, vet,4crossbuild, modeled Entware. Native Mihomo
lifecycle/settlement/postCAS PASS; manual HTTP отказал в Acquire до preview,
диагностикаd590 ещё требует следующего запуска. StrategyLab pair/restored panel
повторно PASS, но публичный executable paired restore ещё не был выбран workflow:
готовится отдельный isolated harness с настоящим producer и old193 бинарником.
Strict DNS и full NFQWS остаются FAIL; release/router admission не изменён.
[Raw](measurements/2026-11-09/research/lifecycle/0f043902/).

Следующая волна включает reviewed App API/UI timing eb1, pathname scratch1af9,
fair save comparison/lock fixture d762, baseline observation7c3 и отдельные
measurement-only stack/mountinfo benchmarks. Собственный CI ещё обязателен.


### Последняя завершённая интегрированная проверка: 6df3d753

Оба generic CI42634856758/42634845807 SUCCESS, включая полный normal/race,
UI, vet,4crossbuild и modeled Entware. API network timing прошёл actual TLS503,
чужие/устаревшие/canceled результаты и независимость снимков; timing не повысил verdict.
Все4 Mihomo job42634845791 SUCCESS: manual preview/token→Apply→LAN→HTTPStop
дважды, повторный closing retry, lifecycle, failed-check settlement и post-CAS rollback.
Manual Apply90.281/90.219с, Stop5.539/5.551с; оба физических baseline восстановлены.
Это проверка изолированного Linux namespace, не изменения/приёмка действующего роутера.

Classic save на actual1.8.10: normal/race parity,lock,source mutation/cancel PASS,
одинаковые74строки,20→4 children; steady N5 median80.696→28.465мс normal,
108.845→38.093мс race. First sample сохранён отдельно. Strict DNS12 и полный NFQ
LAN/manual ещё FAIL; на6df fault-cut NFQ не достигнуты из-за раннего deadline,
прежние0f recovery PASS не переносятся автоматически на6df.
[Отчёты и raw](measurements/2026-11-09/research/lifecycle/6df3d753/).

Следующие reviewed изменения требуют собственного CI: stack pathname scratch
устраняет измеренную race pool allocation; bounded child output ReaderFrom
сохраняет все Start/Wait; coordinator readonly scope сохраняет все Current;
actual1.8.11 и genuine configured-old193 public paired CLI получают отдельные
native jobs. Ни новый harness, ни source review не являются native PASS.


### Последняя полная проверка:4cc9f869

Оба generic CI42642213704/42642229628 SUCCESS. Все4 Mihomo native job PASS,
paired182rows PASS (live p50 320→229мс, selected2 1497→1300мс). Это собственные
результаты4cc, не перенос предыдущего CI. Sameboot normal96.53с/race113.13с PASS;
normal retirement/history/completed ACK cuts PASS, остальные7cuts FAIL120с.
Strict DNS12 и полный NFQWS2 ещё FAIL; DNS diagnostic30 и production NFQ
intent/sync/quarantine cleanup-only retry PASS. OutputReader снижает allocations
actualchild83→28КБ, но его скорость6.424→6.589мс не улучшена.

Public paired fixture остановился доproducer из-за BusyBox -O; actual1.8.11
preflight корректно отказал при несовпадении установленных байтов. Reviewed
1e4/af305 исправляют лабораторные prerequisites, сохраняя original guards.
Следующая e75/a6fe серия проверяет original readonly absence и fresh fullSHA
scratch. Дополнительные parser/audit capacity варианты пока только test-only.
Новый commit требует собственного CI; router/release admission не изменён.
[Доказательства](measurements/2026-11-09/research/lifecycle/4cc9f869/).


### Следующая проверка60e0d4ba: отказы сохранены, исправления подготовлены

Generic обаFAIL в новом NFQ тесте: t.TempDir имел0755 вместо required0700;
d4dace94 исправляет только test fixture. Full gate на60e не достигнут.
Native managed core не запускался из-за отсутствующего dataplane.test; build
script исправлен. Отдельные fullLAN/manual запускались и превышают deadline,
production intent/sync/quarantine cleanup-only retry PASS, freshApply FAIL.

Actual1.8.11 archives прошлиSHA, но apt отказал downgrade без явного флага;
разрешение ограничено четырьмя exact local.deb в disposable26.04. Public bootstrap
запустил настоящую старую панель, затем обнаружил fingerprint исходного schema1
против мигрированной schema2 формы. 7fb32e53 связывает header с actual source config,
не переписывая исходник; semantic/staged migration и все строгие checks сохранены.

Sameboot normal/race отказали в первом absence: observed ABI не включал четыре
исходных readonly table207 query. 0cc85f3a сохраняет именно эти argv, все SHA/Start/
Wait и проверки результата, с actual bytes+exit-status parity тестом. ACK cuts не
достигнуты. Warm Mihomo lifecycle/manual на60e тоже превысили110с; settlement и
postCAS PASS. Это не доказанная причинная связь со sameboot изменением; следующий
CI сравнивает actual lifecycle с preserved4cc на том же runner, deadline unchanged.

Paired probes182rows PASS: live p50/p95307/329→221/287мс, selected2 1364/1521→
1200/1467мс. У all2 p95 ухудшился1521→1568мс при p50 1384→1214; universal tail
speedup не заявляется. Последняя полная generic и4Mihomo PASS остаётся4cc.
[Raw/исправления](measurements/2026-11-09/research/lifecycle/60e0d4ba/).

### Проверка 35797378 и продолжение 3b27bd6e

Общий CI 35797378 остановился на gofmt после успешных адресных тестов;
полные normal/race не запускались. Форматирование исправлено в 3b27bd6e,
его CI оценивается отдельно. Последняя полная общая проверка — 4cc9f869.

- Парная проверка VLESS (182 строки, один стенд): live p50/p95
  313.900/320.086→223.606/227.777 мс; selected-batch 1454/1465→1250/1263 мс.
  Verdict, identity, отмена и joined cleanup проверены. Это не WAN/LAN-приёмка.
- Настоящий iptables 1.8.11-2ubuntu3: public AcquireUbuntuLegacy, normal/race,
  74 одинаковые строки, lock/mutation guards PASS. Медиана пяти повторов
  57.252→20.439 мс (race 102.467→37.297), процессов 20→4. Все четыре архива
  и установленные байты проверены. Entware stock1.4.21 этим не подтверждён.
- Mihomo lifecycle, два Apply/Stop, восстановление baseline и normal/race
  bookends PASS. На одном runner кандидат 214.56 с, preserved4cc 210.61 с:
  ускорения нет. Manual/settlement превысили deadline, post-CAS остановился
  на sidecar-start до намеченного сбоя. В 3b27 добавлены фиксированные стадии
  диагностики без изменения ошибок, владения ресурсами и deadline.
- Same-boot parent normal/race и все пять normal ACK cuts PASS; race
  retirement/history PASS. Race completed.json не дошёл до ACK из-за
  route-process-unavailable; terminal transaction/global достигли 120 с
  при повторной проверке отсутствия ресурсов. Полная матрица не принята.
- NFQWS2 consumer и closing guards normal PASS; full-copy normal/race PASS:
  1 MiB normal 32952→184 B/op при близком времени полного SHA. Полный LAN/manual
  и race consumer FAIL. Quarantine и cleanup-only retry normal PASS; новое
  Apply не прошло. Защитные fences сохранены.
- StrategyLab pair/restored panel PASS. Public configured-old193 прошёл
  preparation, затем отказал на quiesce-network-provider. В 3b27 исправлен
  скрытый второй /proc mount частного стенда; production provider не менялся.
- DNS strict12 selected/canceled-ready FAIL; diagnostic30 все три recovery
  PASS. Новая проверка измеряет полное чтение pinned Xray блоками
  32/64/128/256 KiB. Production размер не изменён до измерения и ревью.

[Исходные результаты и SHA256](measurements/2026-11-09/research/lifecycle/35797378/)
и [парные измерения](measurements/2026-11-09/research/ci-35797378/) сохранены.
Аппаратная приёмка, выпуск и изменение действующего роутера не выполнялись.

### Проверка 3b27bd6e и следующая исправленная интеграция

Оба generic CI завершились: полный normal и race PASS, затем go vet обнаружил
копирование mutex в тесте structural input identity. Это исправлено созданием
отдельного объекта с теми же полями; assertion сохранён. Shell/UI/cross-build
шаги на 3b27 не запускались. Следующий gate выполняет тот же go vet раньше
полных тестов, сохраняя весь набор проверок.

VLESS paired182 PASS: live p50/p95 317.644/321.353→228.483/230.573 мс;
selected-batch 1465/1487→1285/1302 мс. Dead-node slightly worse
8.905→9.114 мс, поэтому универсальное ускорение не заявляется.
Mihomo lifecycle/settlement/postCAS PASS, manual HTTP FAIL на прежних110с.
Lifecycle same-host candidate251.58с против4cc247.97с, ускорения нет.
Следующая проверка отдельно сравнивает manual-http с4cc на том же runner,
с теми же бинарниками и бюджетами; порядок candidate→baseline диагностический.

Public configured-old193 всё ещё отказал до restore. Исправлена реальная
ошибка классификатора: он не распознавал уже допустимые составные DNS причины.
Добавлены actual pipe cap regressions и отдельный opt-in empty/draft matrix:
настоящий старый HTTP API создаёт draft, после публичного restore проверяются
исходный SHA состояния и нынешний production reader. Это не доказательство
старого live reader, сохранения ручного выбора или default legacy-layout.

Full managed NFQWS2 LAN/manual остаётся FAIL; original core normal и
cleanup-only retry PASS. DNS strict12 FAIL, diagnostic30 все3recovery PASS.
Увеличение Xray ReadAt блока отклонено: actual36577406B file,32KiB29.450мс,
256KiB28.966мс (~1.64% warm), больше allocation и хуже отмена. Production32KiB
сохранён. Новый names benchmark проверяет только стоимость полного прежнего
metadata traversal с bounded backing slice; production алгоритм не менялся.

[Raw и SHA256](measurements/2026-11-09/research/lifecycle/3b27bd6e/),
[paired182](measurements/2026-11-09/research/ci-3b27bd6e/).
Новые исправления и сценарии требуют своего CI; router/LAN не подтверждены.

### Проверка 8434e9ae и следующая интеграция

Оба общих CI (PR42655707310, push42655695807) SUCCESS на точном
`8434e9ae2183ef926a123b1fe4217bc0114d214a`: normal/race, go vet, shell/UI,
четыре Linux cross-builds. Это не закрывает отдельный native lifecycle workflow.
В минимальной обвязке build-targets обнаружен скрытый лишний UI-вызов;
его перенос в общий Node-блок и fail-fast дочернего shell проверены отдельно.

- Paired baseline363f →8434: 182 строки, verdicts, identity, полная cleanup PASS.
  Повторные N12, p50/p95: live315.190/317.779→228.505/236.826мс;
  selected2 1456/1463→1287/1323мс; all1473/1489→1304/1341мс.
  Dead-node8.232→9.079мс: общего ускорения всех сценариев не заявляем.
- Все4Mihomo native jobs SUCCESS. Manual на одном runner: candidate288.01с,
  preserved4cc287.93с; Apply~100с у обоих при прежнем110с deadline.
  Lifecycle254.40с против251.50с. Ускорения нет, запас времени ограничен.
  Отдельная полная same-boot/race/ACK-cut матрица остаётся незавершённой.
- DNS strict12 FAIL; diagnostic30 все3recovery PASS. Actual iptables1.8.11
  normal/race PASS. NFQ normal core/recovery/cleanup retry PASS, fullLAN/manual
  и race FAIL. Сетевые ограничения и исходные deadlines сохранены.
- Public empty bootstrap теперь даёт точную причину: 2с scoped DNS inactivity,
  proc.installer-role-close. Draft достигает настоящего old193 HTTP writer,
  затем корректно отказывает на обычном StrategyPair admission.

Следующая интеграция прошла независимое source review, но ещё требует своего CI:
первая SHA + повторные полные чтения executable внутри одного bootstrap-role call;
отдельное offline сохранение неизменных schema1 StrategyLab bytes без приписывания
old193 нового reader ABI; резервирование ограниченного names slice.
Последнее экономит~4.4KiB/6–7alloc на обходе, wall ускорение не подтверждено.
Offline proof не разрешает live downgrade или private replay; история/manual
selection и восстановленный старый live panel не объявлены проверенными.
Полный Xray image compare пока только измерительный тест: retained~37MB,
первый capture/SHA/clear учитывается отдельно; production cache не добавлен.

На действующем роутере только read-only: SHA256 установленного30.3MB бинарника
занял0.58/0.59/0.59с, stat неизменен. Это внешний sha256sum прежнего rc106,
не Go/candidate benchmark и не подтверждение нового LAN маршрута.
[Профиль и raw](measurements/2026-11-09/research/router-readonly.md).
[Native raw/review/SHA256](measurements/2026-11-09/research/lifecycle/8434e9ae/),
[paired182](measurements/2026-11-09/research/ci-8434e9ae/),
[offline-контракт](measurements/2026-11-09/research/bootstrap-offline-strategy-contract.md).

### Проверка 344912c1 и следующая интеграция

Оба generic CI (PR42660413364, push42660394238) полностью SUCCESS на
`344912c11f285a4c2dc0ac0eadd8ab64e6110160`: normal/race, vet, shell/UI,
четыре cross-builds. Исправленная обвязка build-targets больше не печатает
скрытые MODULE_NOT_FOUND. Все4Mihomo native SUCCESS; совместимая StrategyLab
пара, encrypted backup/restore и изолированный restored-panel boot PASS.
Public configured-old193 update→restore остаётся отдельным FAIL в empty/draft.

- Paired182 PASS. Repeated N12 live p50/p95 316.126/463.944→226.614/228.495мс;
  selected2 completion1445/1461→1263/1286мс; all1468/1485→1287/1321мс.
  First engine runs сохранены отдельно; это не cold page-cache или WAN proof.
- Mihomo same-runner lifecycle311.41с против preserved4cc310.16с;
  Apply~107с у обоих, только~3с запаса к прежним110с. Manual212.89с против224.05с.
  Порядок candidate→baseline фиксирован, мало повторов: causal speedup не доказан.
- DNS selected впервые в этой паре дошёл до GEN1 publication, точной mapping,
  исключённого клиента и единственного child, затем selected TLS timeout4с.
  Canceled-ready не дошёл до GEN1 за12с. Diagnostic30s recovery все3 PASS.
  CPU в разных jobs/runs различаются; продвижение нельзя приписать names reserve.
- NFQ consumer normal/lateWait PASS; fullLAN/manual FAIL. В этой волне все3
  recovery cuts не достигнуты: forward inventory-open deadline ещё до эффекта.
  Прежний8434 recovery PASS не переносится. Race consumer/full также FAIL.
- Names reserve повторно проверен normal/race:~4.4KiB меньше на обходе,
  без заявления об ускорении всего маршрута. Exact1.8.11 обаnative PASS.
- Bootstrap image actual13.89MB:16полныхчтений/8occurrences; медианы трёх
  alternating samples empty186.38→49.46мс, draft146.79→42.93мс; retained14.02MB.
  Full public flow пока FAIL, restore не достигнут. Отдельный opt-in ordinary
  actual-fact test пропущен без env; его не считаем пройденным.

По измерениям выбран следующий Xray outer-observation consumer: первый capture
с SHA, затем полное побайтовое закрывающее чтение; данные не доступны callback,
derived views или handoff. Storage один на процесс, nonwaiting, первая аллокация
фиксирует capacity<=64MiB; больший файл/конкуренция используют прежний SHA путь.
После начала capture fallback нет; clear и отказ по отмене/абсолютному deadline
выполняются до успеха. Source review67f4557c пройден, runtime этой реализации
ещё не подтверждён. Primitive37MB measurement: SHA18.08мс, повторное чтение/
comparison2.89мс, первый capture+SHA+clear20.54мс; это не full-route speedup.
Удерживаемая память и RSS не тождественны. Сравнение полного сценария планируется
на одном runner с исходными12/4с и свежим процессом каждого запуска.

Дополнительно исправлено окно отмены после bootstrap image clear; новый закрытый
словарь стадий и ограниченное чтение receipt локализуют следующий public отказ.
Ни один запрет scope/ownership/freshness не ослаблен. IP version child сохранён:
в отличие от двух статических xtables strings, iproute2 может читать runtime
libbpf сведения. Новые счётчики actual child starts и полного startup image
payload проверят дальнейшие гипотезы; speculative production patch не добавлен.

[Все raw/review/SHA256](measurements/2026-11-09/research/lifecycle/344912c1/),
[paired182](measurements/2026-11-09/research/ci-344912c1/).
