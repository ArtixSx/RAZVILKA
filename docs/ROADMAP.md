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
| A: backup/restore и совместимая пара | Ведущий: интеграция/CI; Review: независимое ревью | Encrypted import/export, snapshot3 binary/state pair, reader7/reader5/legacy transitions, history/manual selection, unknown/finalizing fences и actual Stop/Wait retention проверены. После исправления fixtures native/race и запуск восстановленной панели PASS на ebfbd4c4: run41252252725/job124687996380 | Программный сценарий этого этапа подтверждён. Повторять регрессии на интегрированном HEAD; аппаратный power-loss/reboot требует выделенного роутера |
| B: scope/DNS/исключения | Review: coordinator/capture/baseline/retirement; Capabilities: native fixture; ведущий: ревью/интеграция | На3cdb8be2/job124696084189 original DNS/process/baseline native PASS. Reader4 standby custody и полная проверка двух исходных журналов интегрированы. Наee402fd8/job124702822123 сквозной стенд проходит VLESS/service precheck и настоящий запуск; процесс listener-ready, baseline planned. Стек показывает активное хеширование tool closure внутри ExactPresence, а не зависший mutex | Измерить и устранить повторную работу до DNS publication, завершить LAN→selected TLS и mismatch/opaque. Неопубликованный standby retirement проходит адресные проверки частичных сбоев, независимое ревью продолжается. Затем published retirement/durable Apply/NAT/VPN; внутренние задачи |
| C: managed NFQWS2 | Backup: consumer/native fixture/измерения; ведущий: интеграция; Review: независимое ревью | App probe/selection, исходные runtime/control владельцы, reader2 и sole Wait интегрированы. Реальный NFQUEUE bootstrap PASS. На903f2f4b Execute14.0128с,31 ToolCheck занимают2.7343с; readiness не подтверждён, unknown остаётся fenced. c3e9039a прогревает диагностический pprof вне измеряемого actor; его14с бюджет не увеличен | Получить CPU baseline и проверенное before/after на отдельной validation-ветке; оптимизация8→4 повторных проверок ещё не принята в интеграцию. Завершить TLS/NFQUEUE/HTTP→ручной выбор→source bridge, затем live apply/recovery на изолированном LAN стенде; внутренние задачи |
| D: полное время проверок | Capabilities; ведущий: интеграция | Actual Xray26.3.27 full Check N12 live p50 502.681→396.741мс, p95 506.826→398.146мс, physical service requests2→1; dead/cancel/cleanup и actual App queue PASS. CSV и границы reference/cold/queue в measurements/2026-10-31/native-vless; повтор ebfbd4c4 PASS | Доступный программный стенд проверен. Ускорение относится к controlled40ms service, reference не исторический release. Аппаратные CPU/RAM/WAN/LAN и browser paint не измерены |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий: интеграция | Общий inventory и tri-state availability; c758ec34 публикует реальные регистрации installer/import/staged/native/probe/apply/health/recovery/rollback, AUTO использует тот же getter. Go/UI и независимое ревью PASS; registration не объявляет live readiness | Обновить матрицу после B/C/F. Для внешнего сайта нужен конкретный URL/репозиторий |
| F: lifecycle механизмов | Ведущий: core/native integration; Capabilities: Mihomo App/API/UI; Review: независимое ревью | HEV2.17.1 TUN/HTTPS/cleanup, install/crash recovery и next-boot проверены. Mihomo install/reinstall, CAS, reader6 и package recovery работают; официальный native `-t` для VLESS Reality/HY2/TUIC/SS/WS/gRPC PASS. На903f2f4b/job124702036287 actual native child, exe/argv/env/sealed profile/home/netns/socket association и sole Wait/полное отсутствие listener PASS6.83с | COMMON checker с исходными writer FD, всеми обязательными пробами/IPv4, cleanup retry и новым VLESS/TLS стендом проходит ревью; App/API/UI реализуются. Далее actual service CI, apply/health и безопасная замена версии. Работающий процесс сам по себе не закрывает F. WAN/reboot отдельно |
| G: независимая приёмка | Review; ведущий CI | На903f2f4b strategy-pair/job124702036290 и node-native-performance/job124702036169 PASS; scoped-native/job124702036287 FAIL по B, managed-probe-native/job124702036303 FAIL по C. F-подтесты внутри scoped-native PASS. Последующий HEAD проверяется; отменённые из-за новых push прогоны не считаются PASS | Полный CI итогового интегрированного SHA обязателен; PR23 остаётся draft без merge. Для аппаратных LAN/WAN/reboot нужны выделенное устройство, LAN-клиент и авторизация; сценарии стенда сохраняются в scripts и native tests |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.
