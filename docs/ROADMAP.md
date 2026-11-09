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
| P0: VLESS startup и длительность | probe_performance; независимый independent_review | Приватный deadline готовности SOCKS; отдельные runtime_start/runtime_ready/route_identity без выдачи service proof | Поздний SOCKS greeting после 8с отвергается; cancel, joined cleanup и evidence TTL сохраняются. Парные native full Check и App queue на одном runner; холодный и повторный запуск отдельно. |
| P0: CLI/API/UI измерения | lab_sources: cmd/nodeeval; ведущий: API/UI | Закрытый список стадий и полное время проверки/подготовки в JSONL; API/UI сохраняют новые стадии | Нет URI/логов/ошибок из внешнего checker; неверная идентичность не публикуется. Стадии не суммируются; CLI ожидание не называется очередью сервера, SOCKS readiness не называется LAN readiness. |
| P0: продолжение очереди и первые readiness retries | lab_sources: scheduler; probe_performance: readiness; independent_review: проверка | После успешного checkpoint следующий ограниченный шаг будит обычный scheduler без секундного простоя; первые SOCKS polls добавлены внутри первых100мс | Адресные Stop/recovery, burst3, cancel/WAN/busy/restart и CAS PASS. Native8c run42559470862 PASS: full Check p50 404.777→314.996мс; selected2 completion2615→1444мс, N12. Медленный80мс startup имеет≈2мс дополнительной работы в PC fixture. Router/WAN повтор остаётся отдельным этапом. |
| P0: Mihomo lifecycle / recovery (F) | probe_performance; independent_review; до per-plan readiness | Исправлены повторная rotation, собственный compiler/wire Plan и потеря original owned row при закрытии; Stop phases и exact wire images сохранены | Native b726 run42568035583 SUCCESS: два Apply/Check/Stop, fresh Apply/closing retry, failed Check settlement, post-CAS rollback и normal/race original bookends. Apply≈95.5с, SHA81.12% CPU whole-test; сокращение этой цены, остальные same-boot race/ACK cuts, late metadata и ранний restart ещё открыты. Старый WIP из 76c67f32 переносить адресно. Это программные задачи, внешнего блокера нет. |
| P0: DNS / точный scope (B) | lab_sources; independent_review; зависит от исходного cleanup | Original successor preparation cleanup включает оба ACK и отзыв только исходного joined listener; scope/exclusions/native VPN guards действуют | Native2924/b726 diagnostic30 clean/2partialACK CUT→COMPLETE→PASS, прежний alias проверен. B726 strict12 оба GEN1 FAIL; standby primitive4→2 PASS. Следующие два prepared baseline чтения44c1cd0b требуют native8→2/strict12 проверки. Осталось GEN1 failure recovery и GEN2 ready/cancel/retire/retry в штатных12с/4с; shared CDN и чужие DNS writers не расширяют capture. Старый f71db55f не достиг новой lane, PASS не заявлен. |
| P1: managed NFQWS2 (C) | Ведущий после B/F; reviewer до принятия | Изолированный probe, история, manual intent и generation guards есть | B726 actual LAN activation16.080с превышает15с, затем retire.policy-remove UNKNOWN; manual/race тоже FAIL. Active-LAN metadata/syscall cost подтверждён, snapshot14captures0.464с не главный источник. Завершить Apply → included/excluded traffic → Stop/recovery, сохранив все ownership/closing proofs и unknown/retirementStarted. Аппаратного блокера для этой программной работы нет. |
| P1: capabilities/API/AUTO (E) | Ведущий после F | Общий gate AUTO/worker, registration отдельно от available:null | Подтверждённый per-plan lifecycle на HTTP API и UI; до этого live readiness не повышать. Новые telemetry fields не меняют admission. |
| P1: backup/update (A) | Ведущий после F; независимый review | Snapshot3 binary/StrategyLab pair, encrypted backup, история/manual intent, unknown/finalizing fences уже реализованы | Наa9f/a9bd/2924/b726 native/race совместимые пары и restored panel PASS; старый focused native PASS не переносить автоматически на другой SHA. |
| P1: следующие причины длительности | Ведущий; после подтверждённого baseline этой волны | Общий wall/queue/start/ready/service/cleanup наблюдаем; private stage identity проверена | Отдельные DNS/connect/TLS/TTFB/body timings на каждый redirect ещё не реализованы. Cleanup≈101мс и оставшиеся≈333мс inter-check требуют собственного профиля; не убирать ownership/history checks. Минутные VLESS задержки на controlled fixture не воспроизведены; нужен соответствующий сценарий медленного WAN/CPU/flash. |
| P2: измерения платформ и расширение | Ведущий после P0/P1 | Воспроизводимый Linux namespace стенд и router acceptance сценарий | NC-1812 ARM64/KeeneticOS 5.01.C.6.0-1/Entware + отдельный LAN клиент; холодный/повторный Apply, WAN/reboot/power-loss. MIPS/OpenWrt/другие платформы отдельно. Не хватает выделенного аппаратного стенда и явной авторизации его изменения. |

Первая волна источников и лицензии: [лабораторный журнал](RESEARCH_LAB_20261109.md).
Сверка возможностей и независимое ревью: [review](RESEARCH_REVIEW_20261109.md).
Результаты текущего прохода: [измерения](measurements/2026-11-09/research/README.md).
Наличие плана, guard или draft PR не закрывает направление. Общий CI проверяется
для своего SHA отдельно от native workflow и аппаратной приёмки.

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
