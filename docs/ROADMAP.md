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

## Общая очередь реализации 31.10.2026

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
