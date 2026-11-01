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

| Направление | Владелец | Работающий сценарий и доказательства | Следующее действие / внешнее ограничение |
| --- | --- | --- | --- |
| A: backup/restore и совместимая пара | Ведущий: интеграция/CI; Review: независимое ревью | Encrypted import/export, snapshot3 binary/state pair, reader7/reader5/legacy transitions, history/manual selection, unknown/finalizing fences и actual Stop/Wait retention проверены. Наadb65182 native/race и запуск восстановленной панели PASS: run41272217578/job124747142156 | Программный сценарий этого этапа подтверждён. Повторять на итоговом HEAD; аппаратный power-loss/reboot требует выделенного роутера |
| B: scope/DNS/исключения | Review: coordinator/capture/baseline/retirement; ведущий: независимое ревью/интеграция | В7bd33acb diagnostic30 впервые получены реальный DNS-ответ клиенту и LookupPublished; selected HTTPS ещё FAIL по4с клиентскому пределу. Never-issued native обнаружил взаимную блокировку retainedXrayMu при записи COMMON; исправление9c229721 независимо проверено и интегрировано в79feb811. SHA4→2 внутри одного readonly сравнения сохраняет все source/process/kernel bookends; ускорение полного маршрута ещё не подтверждено | После9c readiness deadline сохраняется; 1682 и mainadb сохраняют native deadline отказ; добавить адресные измерения accepted-flow и устранить причину, затем завершить selected/mismatch/opaque, затем original DNS detach + published coexistence reader7 и повторный Apply/Stop. Программная работа продолжается; физический LAN/WAN отдельно |
| C: managed NFQWS2 | Backup: consumer/native fixture/измерения; ведущий: независимое ревью/интеграция | Полный consumer ранее PASS8.370с (f48), actual HTTP manual workflow PASS39.28с (a5); нестабильность deadline сохраняется на последующих workers. На5415 actual физический scope с WAN+двумяLAN-клиентами PASS2.69с; публичный stock compiler не принимает чужой профиль. В18d6d0b9 принята привязка private compiler к исходному packet owner. Изолированный c212: genuine version/closing-mutation/lifecycle проверки PASS; одинаковый worker,381 ToolChecks, metadata attempts3548→3114, Execute15.341→14.598с — ОБА FAIL deadline, это не успешное ускорение workflow | Уменьшить измеренную избыточную проверку неизменных tool bytes внутри original readonly bracket; сохранить каждый фактический command/kernel/cleanup guard. Завершить повторные HTTP probes→manual→LAN Apply→excluded/included packets→Stop/recovery. Race и полный LAN App ещё внутренние задачи |
| D: полное время проверок | Capabilities; ведущий: интеграция | Actual Xray26.3.27 Check N12, physical service requests2→1, dead/cancel/cleanup и App queue PASS. Серия570b/job124710713791: p50/p95 wall509.784/512.177→405.332/408.381мс, SELF CPU50.238/52.002→41.037/45.266мс, reaped CHILD CPU64.397/65.188→59.230/60.736мс.143 строки,0 RSS errors. Повторadb65182/job124747142129 PASS; [сырые данные](measurements/2026-11-01/native-vless-resources-570b/README.md) опубликованы | Подтверждено20.49% по p50 controlled40ms service; reference не исторический release, снижение RAM не заявляется. Аппаратные WAN/LAN и browser paint отдельно |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий: интеграция | Общий inventory и tri-state availability; API/AUTO используют фактическую регистрацию. Mihomo UI использует исходный isolated_probe getter. Вd6101ba3 package_update связан с исходным adapter/manager и остаётся available:null; обычная кнопка ведёт в тот же reviewed HTTP endpoint. Независимые Go/UI проверки PASS | Повторить actual HTTP/API/UI после B/C/F и итогового SHA. Для внешнего сайта нужен конкретный URL/репозиторий; GitHub About указывает Telegram, отдельный сайт не установлен |
| F: lifecycle/update/recovery и транспорт | Capabilities: original Mihomo/HEV; ведущий: COMMON/cold/WG; Review: независимая проверка | На18d6d0b9 actual persistent Mihomo child/kernel owner переживает Apply release, fresh cleanup и stale-control отказы PASS12.84с. Tagged полный Main: actual registry/tool inventories и HTTPS update1.19.32→1.19.33 PASS. WG native все4 suites PASS (включая dual-family LAN/NAT/excluded MAC/privacy/receipt recovery); HEV actual TUN/HTTPS/cleanup и finite Mihomo service ранее PASS. [WG evidence](measurements/2026-11-01/native-wireguard/README.md) | Постоянный live Apply/health/Stop/повторный Apply и cold recovery ещё реализуются. Reader6/typed live COMMON пока не опубликованы; оригинальный child, отдельный TUN sidecar/soleWait, two-writer custody и fresh cleanup проходят адресные проверки. Реализованы Manager scope, original pending rollback и отдельный Stop→terminal→config CAS→stopped-plan ACK; общий native сценарий ещё не подтверждён. Старые routing tuples сохраняются; новые207/31200–32223/shared78–79/transit80 не пересекаются с B31000. Нужны законченный native workflow и затем hardware WAN/reboot |
| G: независимая приёмка | Review; ведущий CI | Полный PR CI8522538a/run41267354412 SUCCESS: Go normal/race/vet/UI/четыре cross-build/Entware. Наadb65182 A/job124747142156, D/job124747142129, WG/job124747142179 PASS; scoped/C FAIL по явно указанным незавершённым B/C сценариям. Полныйadb PR/run41272220538/job124747151248 и push/run41272217629/job124747142308 SUCCESS целиком; отменённые b99 full не считаются PASS. Следующий независимо проверенный9ce81c87 добавляет реальный dirfsync обоих COMMON журналов с сохранением исходных FD при ошибке ACK (локальные адресные проверки PASS) | Исправлять native failures и дождаться полного CI итогового SHA. PR23 draft без merge/release/deploy. Аппаратные LAN/WAN/reboot требуют выделенного устройства, клиента и явной авторизации; [воспроизводимый порядок](ROUTER_ACCEPTANCE_RU.md) подготовлен |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.
