# Дальнейшая работа

## Текущая очередь завершения — 16.11.2026

Одна рабочая ветка, общие файлы и интеграция — Root. Более старые очереди ниже
сохраняют происхождение решений; приоритет имеет эта таблица.

| Приоритет | Владелец | Рабочий сценарий / доказательство | Следующее действие и условие завершения |
| --- | --- | --- | --- |
| P0 DNS | catalog_lifecycle_review; Root integration | 45690b07 GEN2 guard: identity normal/race PASS; selected доходит до HTTPS, но4с FAIL; GEN2 witness12с FAIL; diagnostic30PASS | FD-read принят8ab после review: same-host median normal−4.54%, race−18.79%; full strict8ab12/4с всё ещё FAIL. Продолжить полный trace и устранить задержку без изменения сроков |
| P0 Mihomo | Root; external research + product review | 374bbd46 HEV actual HTTP replacement/crash/rollback normal/race PASS. ABBA42b: two-SHA устранил race120с timeout, normal+11.34% медленнее; принятdc5829fd | Exact dc normalFAIL остаётся intermittent; e2fb normal parent+5ACK PASS. Race60bd3/5 ACK cuts FAIL120с. Исправить подтверждённый пропуск Z-лидера с живыми потоками (lifecycle owner, product independent review), затем доставка vendor asset/default-path |
| P0 NFQWS2 | catalog_network_analysis; product review | 66f forward deadline сохраняется, failed Apply rollback independently_empty=true; equal-counter graph native PASS. Identity fixture0700 исправлен456 и PASS | Typed original inventory readerf154 прошёл review/targeted при сохранении всех14 captures; полный native60bdLAN/manual/race FAIL, cleanup verified. На8ab race manual уже rollback-failed/verified=false. Локализовать SOURCE_MISSING, проверить scope counters6818 и обеспечить фактический откат. Telemetryef7 и identity8ab PASS |
| P0 update/restore | Root; product/lifecycle review | `492e813b` bound retry normal/race, plan-only cut, actual public history и modern rollback PASS | Историческая reader4 normal/race уже PASS на9da; полный CI текущего итогового SHA; аппаратные прерывания отдельно |
| P1 панель/API/AUTO | Root | Новое меню и21 страницы,118 Node commands и Chromium desktop/mobile PASS | Полный backend flow на принятом LAN-профиле после P0; неизвестное состояние не превращать в availability |
| P1 роутер | Root после P0 | Старый NC-1812 профиль сохранён; отдельный отчёт16.11 сообщает переустановку Entware, тесты и удаление Z2K/stock NFQWS2/Xray. Текущий candidate не установлен | Новый профиль/backup, отсутствие внешних200/210/300 отдельно от NDMS64511/64512; текущие TCP-буферы4МиБ не имеют исходного снимка. Проверяемый откат, установка точного SHA, service/device Apply/Stop/recovery |
| P1 GitHub | Root; network backup verification | 51 tags/14 releases/140 assets сохранены и проверены; README подготовлен | После готовности: финальный refs/local backup, перенос CI на pinned source archives, delete_repo OAuth scope, пересоздание и сверка нового репозитория |
| P2 новые платформы | Root после выпуска | Сборки не равны готовности маршрута | Конкретные MIPS/MIPSel/OpenWrt устройства и профили; отсутствие оборудования блокирует только их аппаратную приёмку |

Неуспешные программные тесты не являются внешним блокером. Внешние препятствия
для следующей операции указаны отдельно: `delete_repo` отсутствует в OAuth;
физический power-loss и иные модели требуют отдельного стенда. Статусы и точные
run IDs: [текущая контрольная точка](CURRENT_STATUS_RU.md#current-release-checkpoint).


Приёмка кандидата 0.20.0 продолжается. Состав и ограничения описаны в
[примечаниях к выпуску](releases/0.20.0.md); результаты проверок и оставшиеся
условия выпуска — в [текущем статусе](CURRENT_STATUS_RU.md).
Этот план не подтверждает готовность выпуска или завершение аппаратных проверок.

Текущая карта механизмов, подтверждённые исправления и приоритетная очередь
завершения находятся в [аудите обходов от 31.10.2026](BYPASS_REVIEW_2026-10-31_RU.md).
Главные зависимости — управляемый сетевой подбор NFQWS2, точная маршрутизация
доменных сервисов и единое представление фактических возможностей исполнителей.

После текущей приёмки:

- Проверить MIPS и MIPSel на физических роутерах. Сборка бинарника не заменяет
  проверку установки и сетевой работы на устройстве.
- Развить обход NFQWS2 для отдельных устройств через нативную обработку
  соединений и connmark. До реализации и проверки действуют ограничения
  [матрицы платформ](RUNTIME_SUPPORT_RU.md).
- Развить совместную работу двух DPI-обходов с явными границами управления,
  проверкой результата и восстановлением после сбоя.
- Расширять поддержку доменных сервисов через VPN и прокси только после
  реализации точного ограничения трафика выбранными доменами. Общий IP сайта
  сам по себе не разрешает перехватывать трафик других сайтов на том же адресе.
- Продолжать проверку подключений VLESS/Xray, Generic WireGuard и AmneziaWG
  через общий сетевой исполнитель, с отдельным подтверждением каждого
  поддержанного сценария.

Исторические рабочие планы интеграции не являются инструкцией установки
публичного выпуска. Успешные проверки на моделях не заменяют испытания на роутере.

## Активная очередь исследования и реализации — 09.11.2026

База `0e2db5ab` сохраняет четыре неопубликованных коммита после PR #23
(`a2d1c3c7`). Работа ведётся в `work/research-build-20261109`; прежние worktrees,
refs и незакоммиченные файлы сохранены. Старые номера SHA в приложении не
используются как разрешение откатить более новые исправления.
Общий перечень ниже заменяет приоритеты старой очереди; исторические результаты
31.10–02.11 сохранены ниже для проверки происхождения доказательств.

| Приоритет / направление | Владелец и зависимость | Работающий сценарий / изменение | Критерий приёмки и оставшаяся работа |
| --- | --- | --- | --- |
| Панель по референсам NetZapret | Root; product review |13 разделов,21 страница, прежние действия/API | Desktop/mobile Chromium PASS,118 Node commands PASS; Linux push и PR CI e895 PASS. Backend admission не расширен, router UI не обновлялся. |
| P0: VLESS startup/очередь/cleanup | Root; независимый review | Свежий bounded SOCKS readiness, scheduler и ранние Stop polls в прежнем4с grace |147d paired182rows PASS: live p50 311.632→223.534мс, selected2 queue1440→1267.5мс, cleanup100.5→11мс. N12; fixed baseline→candidate; не WAN/LAN. Далее: реальные WAN/CPU/flash и router/LAN измерения. |
| P0: CLI/API/UI измерения | Ведущий; verification; зависит от точной identity | CLI4979 actual localDNS/SOCKS/TLS/TTFB/body; eb1 API/UI original invocation snapshot после RecordCheck | CLI/profile/paired6df и полный Go normal/race+UI PASS. <=32rows, нет URL/ошибок/response bytes; absent/incomplete/multiple отличаются, интервалы не сумма. Не service/LAN proof. |
| P0: Mihomo lifecycle/recovery (F) | Root; catalog_product_analysis review; до расширения AUTO | Actual Apply/LAN/Stop, manual preview, ownership/closing |147d4/4PASS; e8953/4PASS, lifecycle candidate FAIL при HEV sidecar exit254; same-host4cc baseline тоже sidecar-start FAIL, его exit code не записан; rollback verified; это не TTL/context отказ. Далее: bounded startup diagnostic sealed HEV, полная restart/race ACK матрица. |
| P0: DNS / точный scope (B) | catalog_network_analysis; Root review | Scoped recovery, strict capture/exclusions; fresh images/lock |147d iptables1.8.11 normal/race PASS; strict/diagnostic30 FAIL. Profiler ABBA6558/8FAIL. Ubuntu26 effective BPF bind count1 refused; ubuntu24 guard PASS, strict FAIL, первая mapping проверка не завершилась к12с cancel. ABI storage исправлен6db, tests normal/race8ba PASS. Далее: полная стоимость свежих observations, затем GEN1/GEN2 ready/cancel/retire/retry12/4с. Внешнего блокера стенда нет. |
| P1: managed NFQWS2 (C) | Root после DNS/update; независимый review | Original consumer/history/manual intent, quarantine custody и joined cleanup |147d physical WAN bridge ownership drift PASS, fullLAN/manual normal/race FAIL; original activation15.64с/activeLAN11.06с overlap, rollback failed. Pure mount parser8ba74.610→36.940мкс/allocs518→259; это не доказательство полного Apply. Далее: full flow на прежних deadlines с точным cleanup. |
| P1: capabilities/API/AUTO (E) | Ведущий после F | Registration отдельно от availability; scoped manual support отдельно от live service proof | Сохранены unknown и stale/WAN guards. Общий AUTO допуск не расширен. Проверить полный per-plan HTTP workflow и remaining recovery; generic не повышает router admission. |
| P1: backup/update (A) | catalog_lifecycle_review; Root и product review | Snapshot3 binary/StrategyLab, encrypted backup, history/manual intent, fences |147d pair/public legacy empty/draft/history PASS. Modern468 source migration PASS, quiesce отказ;565 исправляет единственный schema2-only gate для уже проверенного schema3, не допускает1/4/forged/unbound/unjoined. 453559da полный public modern rollback/доступная панель/restart PASS102.73с; targeted normal/race62b PASS. Same-source lab versions, не arbitrary downgrade. Далее: retained-stage retry/Stop-during-rollback; произвольный downgrade не разрешён. |
| P1: оставшаяся цена проверок | Root; network/product review | Свежие полные source bytes/metadata; без кэша authority |8ba устраняет только повторный parser побайтно одинаковых mountinfo, normal/race/source parity PASS, paired pure calculation N5. Увеличение mount buffer уже отвергнуто: те же4reads,103.342→104.521/105.533мкс и большеallocation. Старые fixed-slot/metadata parallel эксперименты также не перенесены. Далее: измерить полный capture/Apply, не складывать overlapping стадии. |
| P2: платформы/новые backend | Ведущий после P0/P1 | Pinned isolated fixtures; SSH/read-only NC-1812 profile подтверждён | Нужны согласованный LAN scope, конкретный candidate и явная авторизация изменения устройства. На роутере rc106/stock1.4.21, CI-unshare отсутствует; работающий NFQWS2 сохранён. WAN/reboot/power-loss и MIPS/OpenWrt отдельно. [Профиль](measurements/2026-11-09/research/router-readonly.md). |

Первая волна источников и лицензии: [лабораторный журнал](RESEARCH_LAB_20261109.md).
Сверка возможностей и независимое ревью: [review](RESEARCH_REVIEW_20261109.md).
Результаты текущего прохода: [измерения](measurements/2026-11-09/research/README.md).
Наличие плана, guard или draft PR не закрывает направление. Общий CI проверяется
для своего SHA отдельно от native workflow и аппаратной приёмки.

### Точка продолжения после сохранения этапа

Актуализация общей таблицы — 16.11.2026. Исторические точки ниже сохранены.

Материалы: [probe results](measurements/2026-11-16/probes-147d8885.json),
[DNS ABBA](measurements/2026-11-16/dns-profiler-655e63d6.json),
[browser assets](measurements/2026-11-16/panel-navigation.json).
Неуспешные программные сценарии — оставшаяся работа, а не аппаратный блокер.
Для изменения действующего роутера необходимы точный candidate, согласованный
LAN scope и отдельная авторизация владельца.

Историческая точка09.11: Root интегрировал modern public rollback
`690c0c30` и focused workflow `83a1a933`; nfq_completion владеет его12fixture
файлами, verification — независимым ревью. Native42692078602 FAIL2.75с на `ordinary-preparation-owner-refused` до
обновления; три hooks PASS. Сначала разобрать исходный preflight owner отказ
без ослабления admission. Generic42692078123 ещё выполняется. Исправленный cancellation test9c прошёл30normal/race;
полный generic42690593933 pending. Старые d7 generic FAIL нельзя считать PASS.

На0470 public empty/draft/history/default-layout refusal PASS; unsupported
legacy upgrade не разрешён. Sameboot10/14, четыре race cuts120с FAIL.
Наd7 ledger allocation parity normal/race PASS; экономия752Б–180КБ, без
заявления route speedup. Strict DNS и полный NFQ LAN/manual ещё FAIL.
`dns_completion` измерил gate wait0.8–1.8мс: очередь не подтверждена причиной.

Следом: завершить modern rollback приёмку, retained-stage/stop-during-rollback,
GEN1/GEN2 ready/cancel/retire/retry на исходных12/4с, managed NFQWS2 full flow,
оставшиеся Mihomo cuts. Общие scope/ownership/evidence/cleanup guards сохранены.
Неудачные startup-image/metadata-parallel prototypes не перенесены в production.
Работа сохранена по просьбе пользователя из-за лимита, без новых экспериментов.
Внешнего блокера программных задач нет. Router/LAN изменения требуют отдельной
авторизации; отсутствие такой авторизации не блокирует лабораторную реализацию.
[Актуальный статус и доказательства](CURRENT_STATUS_RU.md).

### Последний60e0d4ba и конкретные исправления

4cc обаgeneric/all4Mihomo PASS остаётся последней полной приёмкой. На60e обаgeneric
остановились fixturemode; исправленоd4. Root исправил missingdataplane.test вdefault
native suite. Sameboot e75 обнаружил точный readABI gap; 0cc восстанавливает только
четыре исходных readonlytable207 формы. На60e warm lifecycle/manual110sFAIL;
root проверяет preserved4cc samehost, deadline unchanged. Backup7fb исправляет
physical-source schema1 fingerprint, не переписывая actual config. Exact1.8.11
apt flag разрешён только4verifiedlocalarchives; sourcepins unchanged. Audit e30
подтверждает -4320B/4alloc, FieldsSeq отклонён за замедление. Все эти направления
требуют собственного следующего запуска; новых внешних программных блокеров нет.

### Проверенный6df3d753 и следующая интеграция

- Ведущий: paired363f→6df PASS182строки с обычной App telemetry: live p50/p95
  314/317→225/256мс, selected2 1445/1468→1261/1280мс, cleanup101→11мс.
  API/UI actualTLS503/foreign/old/cancel/snapshot и full normal/race PASS.
- Mihomo: все4 native SUCCESS; два real manual preview/token/Apply/LAN/HTTPStop,
  оба physical baseline restored, closing retry, settlement и post-CAS rollback.
  Manual Apply90.281/90.219с, Stop5.539/5.551с; общий AUTO остаётся закрыт.
- dns_completion: strict12 FAIL; diagnostic30 три recoverycase PASS на6df.
  7c3 сократил145→143 hashes при460 Current. Classic1.8.10 fair inventory
  80.696→28.465мс,74equalrows/20→4children; lock/mutation normal/race PASS.
  Actual1.8.11 получает отдельный pinned26.04 job, stock1.4.21 не меняется.
  Coordinator828 сохраняет каждый Current/callback, новые6SHA savings — ещё гипотеза.
- nfq_completion: fullLAN/manual FAIL; на6df faultcuts не достигнуты, поэтому
  original quarantine/cleanup-only PASS1a/0f не переносится автоматически.
  6df race pathnamepool2104ns/1216B→stack1454ns/0B; normal1583/1603ns/0B
  без заявления ускорения.5cb переносит stack, original guards/syscall сохранены.
  866 bounded output ReadFrom сохраняет каждый childStart/Wait, измерение pending.
- backup: bbc/aa24 добавляют настоящую public configured-old193 producer→Stop→
  offlineRestore проверку. Source-reviewed namespaces/privateopt/realreceipts;
  actualCI pending. Nonempty publichistory/defaultlegacylayout не подразумеваются.
- verification: последний полный generic6df оба SUCCESS, как и4Mihomo jobs.
  Новые source reviews не подменяют собственные runtime tests.
  [Raw](measurements/2026-11-09/research/lifecycle/6df3d753/).

### Историческая отправная точка после441e97e4

Продолжение после освобождения диска: `441e97e4` исправляет только StartedAt
общего checker fixture; b5a общий CI FAIL не скрывается. Ведущий владеет
документацией, workflow и интеграцией. dns_completion владеет domain-specific
кодом; nfq_completion — NFQWS active execution/read observation. Общие helpers
меняются только после согласования; verification независимо проверяет оба
сетевых изменения и late mutation/ownership/cleanup контракты.

Доказательства b5a: Mihomo full lifecycle, StrategyLab pair/restored panel,
DNS preparation diagnostic30 и paired probes PASS; DNS strict12 и managed LAN
остаются FAIL. Следующая приёмка требует прежних таймаутов и полного завершения
сценариев, а не сокращения числа проверок состояния. [Точные результаты](measurements/2026-11-09/research/lifecycle/README.md#проверенный-b5a5f58e-и-продолжение-09112026).

Для сохранения места на ПК сборки выполняются в удалённом CI. Локальные исходники,
Git, история и непубликованная работа сохранены. Отсутствие места не считается
блокером программной реализации; новые большие worktrees и бинарные архивы
без необходимости не создаются.

## Историческая очередь и доказательства 31.10–02.11.2026

Ведущий интегрирует `work/bypass-integration-20261031` поверх PR #22/#23.
Один файл редактирует один владелец; Review проверяет рискованные переходы.
Незавершённая реализация ниже — работа команды, а не внешний блокер.

| Направление | Владелец | Работающий сценарий | Доказательства | Оставшиеся действия | Конкретный блокер |
| --- | --- | --- | --- | --- | --- |
| A: backup/restore | Ведущий; Backup/Review — независимое ревью | Совместимая snapshot3 пара binary/StrategyLab, encrypted import/export, история/manual intent, unknown/finalizing и восстановление панели | Native/race/restored panel ранее PASS; последний focused PASS9176/job125273939713. На2aa полный CI PASS, focused остановился до backup-тестов на stale reader8 assertion: [разбор](validation/2026-11-02/integrated-2aa/README.md) | Наa2d assertion9 исправлен, focused pair/job125301876679 PASS; повторить после оставшихся lifecycle изменений | Внешнего программного блокера нет. Power-loss/reboot требуют выделенного роутера и авторизации |
| B: точный scope, DNS, исключения | Review; ведущий — ревью/интеграция | DNS publication → Stop → cached-alias TLS; тот же владелец и два исходных FD при partial ACK; never-issued cleanup | Семь DNS-only cases PASS на e87 в diagnostic30s/10s: [evidence](validation/2026-11-02/integrated-e87/README.md). На2aa whole retirement FAIL; Join/repeat после failed setup не означает достигнутый ready-cancel | Завершить очистку исходного failed setup до создания kernel, GEN2 ready→cancel→retire→retry, selected/mismatch/opaque и production12s/4s | Внешнего программного блокера нет. Незавершённая реализация и native failures остаются работой команды |
| C: managed NFQWS2 | Ведущий; Review/Backup — независимое ревью | Scoped TLS/counter/sole Wait/COMMON cleanup, HTTP probes и manual выбор; WAN/bridge/included/excluded scope, drift refusal, original Snapshot FD | [Native single pair](measurements/2026-11-02/native-extension-path/README.md)9.851→8.789с; отдельные [wake](measurements/2026-11-02/physical-fence-wake/README.md) и [stat](measurements/2026-11-02/tool-path-stat/README.md) micro. Full LAN Apply на2aa FAIL | Завершить Apply/Stop/recovery в штатных дедлайнах. Isolated098 убирает только два дублирующих обхода вокруг readonly batch; каждый child и внешний SHA сохраняют проверки, full CI41453271652 SUCCESS, actual batch normal/race PASS; full LAN FAIL | Внешнего программного блокера нет. Полный workflow и ускорение его завершения ещё не подтверждены |
| D: полное время VLESS | Capabilities; ведущий — интеграция | Настоящий Xray26.3.27 full Check, очередь, dead/cancel и joined cleanup; один физический сервисный запрос | N12 controlled40ms wall p50/p95 509.784/512.177→405.332/408.381мс; CPU SELF/CHILD и143 строки: [сырые данные](measurements/2026-11-01/native-vless-resources-570b/README.md). На2aa job125288489039 PASS | Повторить на итоговом SHA; browser paint и физический WAN измерять отдельно | Программный сценарий подтверждён. RAM gain не заявлен; аппаратные замеры требуют выделенного стенда |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий — ревью/интеграция | Фактическая регистрация и tri-state availability, reviewed probe/update endpoints, manual Mihomo API/UI, config CAS и encrypted roundtrip | Go/UI проверки входят в успешный полный CI2aa. Наличие пакета/архива не выдаёт live readiness | После F подтвердить настоящий HTTP preview/apply/Stop и только затем согласовать per-plan readiness с AUTO/UI | Программная зависимость от F; внешнего блокера нет. Пока readiness=false |
| F: lifecycle/update/recovery | Capabilities — warm; Backup — offline/restart; ведущий — интеграция и независимое ревью | WG; cold retirement с пятью original leases; reader6/7/8/9; отдельные warm Apply/Check/Stop fault cuts; actual parent-death same-boot cleanup | На2aa cold CLI9 normal27.88с/race63.37с и health PASS: [evidence](validation/2026-11-02/integrated-2aa/README.md). Isolated816 Apply108.098с +Check cut1 +Stop cut2 сохранили процессы/TUN/traffic, повторный Stop FAIL. Same-boot ff2 normal99.70с PASS, race120с FAIL после terminal ACK, cuts SKIP. [Парный SHA двух файлов](measurements/2026-11-02/parallel-artifact-816/README.md) — отдельный library замер | Исправить stopped-plan ACK, пройти full Check/Stop/repeat; завершить same-boot race/ACK cuts, late metadata restart, prior stopped plan и более ранние прерывания. В maina2d original cursor/minimum8/9/plan bookends интегрированы, полный CI SUCCESS, actual same-boot normal91.50с PASS, race producer failed до consumer | Внешнего программного блокера нет. Unknown/source/ownership fences сохраняются. Роутерный WAN/reboot отдельно не проверен |
| G: интегрированная и аппаратная приёмка | Ведущий; независимый reviewer каждого рискованного пакета | Полный Linux normal/race/vet/UI/cross-build/Entware плюс отдельные native workflows | На2aa push41448791217 и PR41448797720 SUCCESS; cold9/health/D/WG PASS, focused A/B/C/warm требуют продолжения: [точные результаты](validation/2026-11-02/integrated-2aa/README.md). Maina2d push41452796557/PR41452807579 SUCCESS; focused A/D/WG/cold/health PASS, B/C/warm FAIL | Довести программные сценарии и финальный SHA, обновить матрицу и draft PR; затем выполнить [аппаратный сценарий](ROUTER_ACCEPTANCE_RU.md) | Для физической проверки нужны выделенные роутер/LAN-клиент и явная авторизация. Merge, release и deploy отдельно не разрешены |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.

Итог завершённых проверок и сохранённые ветки после ограничения лимита: [контрольная точка](validation/2026-11-02/budget-checkpoint/README.md). Новые прогоны не запускались.

Продолжение по конкретным native failure и SHA: [lifecycle журнал](measurements/2026-11-09/research/lifecycle/README.md).
