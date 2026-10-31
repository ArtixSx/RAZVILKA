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
| A: backup/restore и совместимая пара | Capabilities: updatecheck и исходный cleanup producer; ведущий: app/startup; Review: независимое ревью | Encrypted import/export, snapshot3 pair, ordinary и settled supervised state; настоящие reader7/reader5/legacy binary transitions и двойной запуск восстановленной панели PASS в Linux run41247014499 | Реализуется отдельное durable удержание изменившегося после старта состояния только из исходного подтверждённого Stop producer; snapshot остаётся неизменным. Новая история и ручной выбор должны сохраняться при rollback. Это внутренняя работа |
| B: scope/DNS/исключения | Review: domain runtime/synthetic scope; ведущий: независимое ревью; shared registrar согласуется с Backup | Настоящий DNS reserve → исходные журналы → настоящий Xray из удерживаемых FD → отмена/sole Wait/listener absence PASS; selected LAN listener тоже PASS в run41247014499 | Завершить исходный capture и baseline relay для accepted FD → kernel proof → публикацию DNS/retirement. Проверка baseline должна учитывать исходные client/ingress и VPN; простой router-origin relay не подходит. Реализация продолжается |
| C: managed NFQWS2 | Backup: consumer/native fixture; ведущий: App/tool dispatcher/reader admission | State6/7, исходный candidate/epoch, тот же component/control/WAN/catalog owner, удерживаемый TCP socket; scoped consumer и точные NFQUEUE counters подготовлены; targeted tests PASS | Запускается настоящий isolated Linux TLS/NFQUEUE consumer с закреплённым официальным бинарником; затем HTTP probe → текущий evidence → selection/apply/health/cleanup. Проверяется отмена и повтор cleanup тем же владельцем. Новый execution reader нужен до публичного включения |
| D: полное время проверок | Capabilities; ведущий: интеграция | TLS/SOCKS N12: p50 93.651→50.622 мс, p95 94.937→51.990 мс (искусственная задержка40мс); queue/server-total/check-with-cleanup/UI readback в ecb33962; Go/UI PASS | Измерения очереди single/batch сохранены как модель. Живые/мёртвые внешние узлы, аппаратные CPU/RAM и полный LAN/apply цикл требуют выделенного стенда |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий: интеграция | Общий inventory и tri-state availability; c758ec34 публикует реальные регистрации installer/import/staged/native/probe/apply/health/recovery/rollback, AUTO использует тот же getter. Go/UI и независимое ревью PASS; registration не объявляет live readiness | Обновить матрицу после B/C/F. Для внешнего сайта нужен конкретный URL/репозиторий |
| F: lifecycle механизмов | Ведущий: HEV App/update/recovery; Capabilities: дальнейшие компоненты; Backup: probe lifecycle | HEV2.17.1 actual TUN/HTTPS/cleanup, pinned install и 3 subprocess crash recovery PASS; f1cbf478 интегрировал guarded install, exact rename admission, reader5, next-boot выбор, cold cleanup и recovery API/UI. Go/UI и независимое ревью PASS | Native CI f1cbf478 проверяет новое соединение сценариев. Mihomo large-artifact transaction и остальные lifecycle проверки остаются внутренней работой; WAN/reboot отдельно на устройстве |
| G: независимая приёмка | Review; ведущий CI | Полный Linux push CI9ea526d9 run41245989794 PASS; focused native bd8a98d4 run41247014499 PASS. PR race fixture ошибочно сравнивал preview с actual execution CreatedAt; d37fab29 исправил только тест, 30 повторов PASS | Полный CI каждого интегрированного SHA обязателен; f1cbf478 отправлен в PR23 без merge. Аппаратные LAN/WAN/reboot требуют выделенного устройства и авторизации |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.
