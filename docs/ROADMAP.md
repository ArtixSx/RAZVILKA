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
| B: scope/DNS/исключения | Review: coordinator/capture/baseline/retirement; Capabilities: независимый native LAN fixture; ведущий: ревью/reader admission | На3cdb8be2/job124696084189 original DNS/process/baseline native PASS. Finite proof сохраняет blocked plan и требует reader3 до записи. Сквозной App стенд прошёл реальный VLESS egress;05397d7d добавляет отсутствовавший точный DNS тестового сервера для service proof | Сквозной LAN→selected TLS и mismatch/opaque baseline ещё проверяется. Review реализует передачу подтверждённого standby исходному владельцу с reader4; далее явная retirement и durable Apply. NAT/VPN и исключения — внутренняя работа |
| C: managed NFQWS2 | Backup: consumer/native fixture; ведущий: App/tool dispatcher/reader admission | Actual App probe/selection, исходные runtime/control владельцы, reader2 и sole Wait интегрированы. Реальный NFQUEUE bootstrap PASS. ca559fa4 сохраняет исходную ошибку и ограниченную диагностику. На3cdb8be2/job124696084043 полный probe не уложился в14с: readiness завершился отказом TOOLS_A; стек показывает повторную проверку совместимости | Измерить затраты повторных readback/hash без ослабления freshness; завершить TLS/NFQUEUE/HTTP→ручной выбор→source bridge, затем live apply/recovery на изолированном LAN стенде. Это программная работа, а не внешний блокер; unknown остаётся fenced |
| D: полное время проверок | Capabilities; ведущий: интеграция | Actual Xray26.3.27 full Check N12 live p50 502.681→396.741мс, p95 506.826→398.146мс, physical service requests2→1; dead/cancel/cleanup и actual App queue PASS. CSV и границы reference/cold/queue в measurements/2026-10-31/native-vless; повтор ebfbd4c4 PASS | Доступный программный стенд проверен. Ускорение относится к controlled40ms service, reference не исторический release. Аппаратные CPU/RAM/WAN/LAN и browser paint не измерены |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий: интеграция | Общий inventory и tri-state availability; c758ec34 публикует реальные регистрации installer/import/staged/native/probe/apply/health/recovery/rollback, AUTO использует тот же getter. Go/UI и независимое ревью PASS; registration не объявляет live readiness | Обновить матрицу после B/C/F. Для внешнего сайта нужен конкретный URL/репозиторий |
| F: lifecycle механизмов | Ведущий: HEV/Mihomo App/update/recovery; Review: независимое ревью | HEV2.17.1 TUN/HTTPS/cleanup, install/crash recovery и next-boot выбор проверены. Mihomo install/reinstall, CAS, reader6 и App recovery интегрированы. На019b503d/job124693108229 официальный native `-t` PASS для VLESS Reality/HY2/TUIC/SS/WS/gRPC и отмены/отказа Start. ffead727 проверяет официальный raw SHA при каждом повторном допуске;4e031ea1 добавляет исходного владельца native probe с sole Wait и удержанием при unknown, независимо reviewed | Native процесс4e031ea1 ещё проходит CI; он пока не подключён как сервисная проверка. Далее typed COMMON scoped checker, API/UI, apply/health и замена версии после подтверждённого runtime inactivity. Работающий процесс сам по себе не закрывает F. WAN/reboot отдельно |
| G: независимая приёмка | Review; ведущий CI | На ebfbd4c4 strategy-pair, scoped-native, node-native-performance PASS. Full CI f9b3f769 выявил оставшееся CLI ожидание reader5:ffead727 исправляет на6, адресный TestComponentRead PASS. Последующий полный HEAD проверяется; отменённые из-за новых push прогоны не считаются PASS | Полный CI итогового интегрированного SHA обязателен; PR23 остаётся draft без merge. Для аппаратных LAN/WAN/reboot нужны выделенное устройство, LAN-клиент и авторизация; сценарии стенда сохраняются в scripts и native tests |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.
