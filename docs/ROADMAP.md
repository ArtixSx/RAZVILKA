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
| P0: VLESS startup/очередь/cleanup | Ведущий; verification | Свежий bounded SOCKS readiness, scheduler продолжает очередной шаг, ранние Stop polls внутри прежнего4с grace | 1a50 paired182rows PASS, live313→225мс, selected2 1440→1261мс, cleanup101→11мс. Первые и повторные samples отдельно. Минутная WAN задержка не воспроизведена; контролируемые WAN/CPU/flash и router/LAN измерения остаются. |
| P0: CLI/API/UI измерения | Ведущий; verification; зависит от точной identity | CLI4979 actual localDNS/SOCKS/TLS/TTFB/body; eb1 API/UI original invocation snapshot после RecordCheck | CLI/profile1a50 и UI PASS; eb1 Go normal/race ожидаются. <=32rows, нет URL/ошибок/response bytes; absent/incomplete/multiple отличаются, интервалы не сумма. Не service/LAN proof. |
| P0: Mihomo lifecycle/recovery (F) | Ведущий; verification; до расширения AUTO | Actual Apply/LAN/Stop, single-use manual preview, original ownership/closing | 0f lifecycle277.94с, settlement116.02с, postCAS62.59с PASS; manual отказал в Acquire до preview. Причину должен показать tagged diagnostic d590. Требуются полный manual HTTP two-cycle, remaining restart/ACK cuts и их recovery; программного внешнего блокера нет. |
| P0: DNS / точный scope (B) | dns_completion; verification; после original cleanup | Scoped DNS original recovery, strict capture/exclusions; save inventory сохраняет fresh images/lock | 1a50 diagnostic30 три recovery PASS; 0f strict12 selected/cancel FAIL. Parity6pairs equal74rows PASS, но fair same-observer сравнение d762 и version-specific lock fixture ещё должны пройти. Завершить GEN1/GEN2 ready/cancel/retire/retry на штатных12/4с, без расширения shared-CDN scope. |
| P1: managed NFQWS2 (C) | nfq_completion; verification | Original probe/history/manual intent; whole quarantine custody и joined cleanup | 1a/0f intent/sync cleanup, fresh plan, cleanup-only secondStop PASS при permanent fence. Full Apply/LAN/manual/race превышает deadline. Fresh Fstat parity и allocation microbench PASS;1af9 pathname scratch требует normal/race bench/arm64 compile, end-to-end gain не заявлен. |
| P1: capabilities/API/AUTO (E) | Ведущий после F | Registration отдельно от availability; scoped manual support отдельно от live service proof | Сохранены unknown и stale/WAN guards. Общий AUTO допуск не расширен. Проверить полный per-plan HTTP workflow и remaining recovery; generic не повышает router admission. |
| P1: backup/update (A) | Ведущий; nfq_completion read-only gap audit; independent review | Snapshot3 совместимой binary/StrategyLab пары, encrypted backup, history/manual intent, unknown/finalizing fences | Ранее native/race pair/restored panel PASS; exact нового SHA отдельно. Аудит оставшихся transitions/restart/partial-failure сценариев; physical power-loss требует отдельной авторизации и плана. |
| P1: оставшаяся цена проверок | nfq_completion и dns_completion; после точной attribution | Сохранены все source bytes/metadata guards; syscall scratch не кэширует authority | 1a50 profile CheckWrite75.42%CPU большого test image, не lockwait; не удалять SHA. Native CopyBuffer caller attribution в d762; изменение только после подтверждения. Нет внешнего блокера для программного профилирования. |
| P2: платформы/новые backend | Ведущий после P0/P1 | Pinned isolated fixtures; SSH/read-only NC-1812 profile подтверждён | Нужны согласованный LAN scope, конкретный candidate и явная авторизация изменения устройства. На роутере rc106/stock1.4.21, CI-unshare отсутствует; работающий NFQWS2 сохранён. WAN/reboot/power-loss и MIPS/OpenWrt отдельно. [Профиль](measurements/2026-11-09/research/router-readonly.md). |

Первая волна источников и лицензии: [лабораторный журнал](RESEARCH_LAB_20261109.md).
Сверка возможностей и независимое ревью: [review](RESEARCH_REVIEW_20261109.md).
Результаты текущего прохода: [измерения](measurements/2026-11-09/research/README.md).
Наличие плана, guard или draft PR не закрывает направление. Общий CI проверяется
для своего SHA отдельно от native workflow и аппаратной приёмки.

### Текущая интеграция: проверенный 1a50bf07 и исправления 0f043902

- Ведущий: paired363f→1a50 PASS182 строки, N12: live p50/p95
  313/334→225/227мс; selected2 1440/1461→1261/1280мс; cleanup101→11мс.
  Отдельный profile подтверждает localDNS/SOCKS/TLS/TTFB/body наблюдения.
  Сетевые интервалы перекрываются и не доказывают доступность сервиса/LAN.
- Mihomo: на1a50 два actual Apply/LAN/Stop PASS287.04с, Apply97.981/98.615с,
  Stop6.314/6.440с. Manual HTTP Apply/LAN прошёл, Stop202 выявил ошибочную
  конфигурацию self-update fixture, не завершение Mihomo Stop. 0f043902
  задаёт абсолютный отсутствующий journal path, сохраняя production recovery
  gate; добавлены native-only fixed-stage diagnostics для ранних activate refusals.
  Полный manual HTTP, settlement и post-CAS требуют нового PASS.
- dns_completion: strict12 selected/canceled FAIL14.03/14.09с; diagnostic30
  три recovery сценария PASS. Original full inventory теперь688save children
  вместо1720-S при неизменных145 SHA/460Currents; actual native6pair parity
  пока не подтверждён: setup DROP в nat исправленe9caf84b на inert RETURN.
  a7fedf84 сохраняет общий1MiB raw budget сразу для двух образов.
- nfq_completion: original whole quarantine/continuous Gate и fresh plan
  подтверждены; новый cleanup-only second Stop PASS45.79с освобождает owner,
  permanent fence остаётся. Полный fresh Apply/manual/race ещё превышает deadline.
  Fresh Fstat normal/race parity PASS;6 micro samples median808.1→731.8ns,
  208B/1alloc→0/0. Это не ускорение полного Apply.
- Ведущий: eb1fccb8 публикует original invocation network timings в App API/UI
  только после всех прежних RecordCheck guards; <=32 immutable rows, отдельные
  absent/incomplete/multiple. Actual TLS503/foreign/cancel/snapshot tests добавлены,
  independent source review и UI PASS; Go normal/race ожидаются. Теперь ordinary
  App paired candidate включает стоимость telemetry, исторические цифры не переносятся.
- nfq_completion:1af9b7c5 сохраняет каждый свежий pathname fstatat, переиспользуя
  только обнулённый аргумент/syscall scratch. Source review PASS; microbench,
  normal/race и arm64 cross-build ожидаются, ускорение ещё не заявлено.
- verification: последний полностью успешный generic — b9bb (push и PR).
  dee compilation FAIL сохранён, исправлен17c3/1a50; на1a50 focused PASS,
  полный generic отменён следующей исправленной волной, не SUCCESS.
  [Raw и точные отчёты](measurements/2026-11-09/research/lifecycle/1a50bf07/).
  Strict DNS/NFQ и оставшиеся Mihomo cuts — программные задачи без внешнего блокера.

### Текущие владельцы следующего шага

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
