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
| B: scope/DNS/исключения | Review: coordinator/capture/baseline/retirement; Capabilities: независимый native LAN fixture; ведущий: ревью/reader admission | Original DNS reserve, Xray held FD и sole Wait проверены; finite proof сохраняет blocked plan и требует reader3 до записи. Подготовлен actual LAN→capture→selected TLS и mismatch/opaque baseline стенд | Выполнить новый сквозной native прогон; затем known retained standby, retirement и durable Apply. Начальный baseline ограничен routed IPv4; NAT/VPN и исключения требуют отдельной реализации/приёмки. Это внутренняя работа |
| C: managed NFQWS2 | Backup: consumer/native fixture; ведущий: App/tool dispatcher/reader admission | Actual App probe/selection, исходные runtime/control владельцы, reader2, sole Wait и retained cleanup интегрированы. Native97bbfb52 обнаружил точный ENOENT родителя процесса; независимо проверенный4dffba91 создаёт приватный родитель через тот же Manager FD | Дождаться actual TLS/NFQUEUE/HTTP probe→selection→source bridge после исправления; далее проверять live apply и recovery. Неизвестные частичные эффекты сохраняют fence, успешная регистрация не закрывает сценарий |
| D: полное время проверок | Capabilities; ведущий: интеграция | Actual Xray26.3.27 full Check N12 live p50 502.681→396.741мс, p95 506.826→398.146мс, physical service requests2→1; dead/cancel/cleanup и actual App queue PASS. CSV и границы reference/cold/queue в measurements/2026-10-31/native-vless; повтор ebfbd4c4 PASS | Доступный программный стенд проверен. Ускорение относится к controlled40ms service, reference не исторический release. Аппаратные CPU/RAM/WAN/LAN и browser paint не измерены |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий: интеграция | Общий inventory и tri-state availability; c758ec34 публикует реальные регистрации installer/import/staged/native/probe/apply/health/recovery/rollback, AUTO использует тот же getter. Go/UI и независимое ревью PASS; registration не объявляет live readiness | Обновить матрицу после B/C/F. Для внешнего сайта нужен конкретный URL/репозиторий |
| F: lifecycle механизмов | Ведущий: HEV/Mihomo App/update/recovery; Review: независимое ревью | HEV2.17.1 TUN/HTTPS/cleanup, install/crash recovery и next-boot выбор проверены. Mihomo1.19.33 bounded artifact install/reinstall, binary+receipt+state CAS, reader6, crash/cache cuts и App recovery API/UI интегрированы; scoped-native ebfbd4c4/job124687996867 PASS | Native профиль из sealed FD реализуется и проходит независимое ревью; затем scoped runtime/checker/apply/health. Замена версии требует оригинального подтверждения runtime inactivity; пока сохраняется отказ. Остальные lifecycle сценарии — внутренняя работа; WAN/reboot отдельно |
| G: независимая приёмка | Review; ведущий CI | На ebfbd4c4 strategy-pair, scoped-native, node-native-performance PASS. Полный CI обнаружил только устаревшие reader6 ожидания:0c8e19d9 исправляет матрицу6/7 с адресным PASS. Полный текущий HEAD ещё проверяется | Полный CI интегрированного SHA обязателен; PR23 остаётся draft без merge. Для аппаратных LAN/WAN/reboot нужны выделенное устройство, LAN-клиент и авторизация; сценарии стенда сохраняются в scripts и native tests |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.
