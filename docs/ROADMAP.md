# Дальнейшая работа

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
| P0: VLESS startup/очередь/cleanup | Ведущий; verification | Свежий bounded SOCKS readiness, scheduler продолжает очередной шаг, ранние Stop polls внутри прежнего4с grace | 357 paired182rows PASS, live314→224мс, selected2 1454→1250мс; cleanup101→11мс подтверждён предыдущей парой. Первые и повторные samples отдельно. Минутная WAN задержка не воспроизведена; контролируемые WAN/CPU/flash и router/LAN измерения остаются. |
| P0: CLI/API/UI измерения | Ведущий; verification; зависит от точной identity | CLI4979 actual localDNS/SOCKS/TLS/TTFB/body; eb1 API/UI original invocation snapshot после RecordCheck | CLI/profile/paired6df и полный Go normal/race+UI PASS. <=32rows, нет URL/ошибок/response bytes; absent/incomplete/multiple отличаются, интервалы не сумма. Не service/LAN proof. |
| P0: Mihomo lifecycle/recovery (F) | Ведущий; verification; до расширения AUTO | Actual Apply/LAN/Stop, manual preview, ownership/closing | 357 lifecycle PASS; manual/settlement/postCAS FAIL. Same-boot parent normal/race и5normal ACK cuts PASS; race retirement/history PASS, completed.json startupFAIL, terminalpair deadlineFAIL. Далее: native sidecar failure attribution и полная restart матрица. |
| P0: DNS / точный scope (B) | dns_completion; verification | Scoped DNS recovery, strict capture/exclusions; fresh images/lock | 357 actual1.8.11 normal/race PASS:74rows,20→4children,57.252→20.439мс. Strict12 FAIL; diagnostic30 все3recovery PASS. SHA126/132/137, Current379/460/460. Далее: full-Xray read measurements и GEN1/GEN2 ready/cancel/retire/retry на прежних12/4с. |
| P1: managed NFQWS2 (C) | nfq_completion; verification | Original consumer/history/manual intent, quarantine custody и joined cleanup | 357 consumer normal/closing PASS, fullLAN/manual и race FAIL. Intent/sync/quarantine/cleanup-only closeRetry normal PASS; subsequent Apply FAIL. FullSHA copy normal/race PASS:1MiB32952→184B normal, CPU близкий. Далее: measured active inventory costs без удаления checks. |
| P1: capabilities/API/AUTO (E) | Ведущий после F | Registration отдельно от availability; scoped manual support отдельно от live service proof | Сохранены unknown и stale/WAN guards. Общий AUTO допуск не расширен. Проверить полный per-plan HTTP workflow и remaining recovery; generic не повышает router admission. |
| P1: backup/update (A) | Ведущий; nfq_completion; verification | Snapshot3 binary/StrategyLab, encrypted backup, history/manual intent, fences | 357 pair/panel PASS. Public configured-old193 проходит preparation, затем provider отказывает скрытому /proc mount;3b27 исправляет только privatefixture, ожидаетCI. Далее: полный public flow, nonempty publichistory/defaultlegacy, retained-stage retry по originalFD. |
| P1: оставшаяся цена проверок | nfq_completion и dns_completion; после точной attribution | Сохранены все source bytes/metadata guards; syscall scratch не кэширует authority | 1a50 profile CheckWrite75.42%CPU большого test image, не lockwait; не удалять SHA. Native CopyBuffer caller attribution в d762; изменение только после подтверждения. Нет внешнего блокера для программного профилирования. |
| P2: платформы/новые backend | Ведущий после P0/P1 | Pinned isolated fixtures; SSH/read-only NC-1812 profile подтверждён | Нужны согласованный LAN scope, конкретный candidate и явная авторизация изменения устройства. На роутере rc106/stock1.4.21, CI-unshare отсутствует; работающий NFQWS2 сохранён. WAN/reboot/power-loss и MIPS/OpenWrt отдельно. [Профиль](measurements/2026-11-09/research/router-readonly.md). |

Первая волна источников и лицензии: [лабораторный журнал](RESEARCH_LAB_20261109.md).
Сверка возможностей и независимое ревью: [review](RESEARCH_REVIEW_20261109.md).
Результаты текущего прохода: [измерения](measurements/2026-11-09/research/README.md).
Наличие плана, guard или draft PR не закрывает направление. Общий CI проверяется
для своего SHA отдельно от native workflow и аппаратной приёмки.

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
