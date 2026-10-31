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
| A: backup/restore и совместимая пара | Ведущий: интеграция/CI; Capabilities: исходный cleanup producer; Review: независимое ревью | Encrypted import/export, snapshot3 pair, настоящие reader7/reader5/legacy transitions и восстановленная панель PASS в run41247014499. В0814da8c добавлено удержание нового settled state из исходного Stop/Wait producer, snapshot неизменен; ручной выбор/история сохраняются без восстановления live health из диска | CI18b6c75b обнаружил отсутствие старых init/config в двух модельных fixtures;690fd4a5 исправил только fixtures и добавил раннюю сверку всех3 prior images. Новый native/race CI ожидается, направление ещё не закрыто |
| B: scope/DNS/исключения | Review: domain runtime/synthetic scope; ведущий: независимое ревью; shared registrar согласуется с Backup | Настоящий DNS reserve → исходные журналы → настоящий Xray из удерживаемых FD → отмена/sole Wait/listener absence PASS; selected LAN listener тоже PASS в run41247014499 | Завершить исходный capture и baseline relay для accepted FD → kernel proof → публикацию DNS/retirement. Проверка baseline должна учитывать исходные client/ingress и VPN; простой router-origin relay не подходит. Реализация продолжается |
| C: managed NFQWS2 | Backup: consumer/native fixture; ведущий: App/tool dispatcher/reader admission | В0814da8c соединены actual App probe, текущий epoch/selection и retained execution reader2;20d8fdf1 сохраняет sole Wait и исходные root/marker FD для повторной очистки. Адресные тесты, Linux crosscompile/vet и независимое ревью PASS | Native TLS/NFQUEUE job20d8fdf1 ещё FAIL, Backup разбирает причину. Затем actual HTTP probe → selection, повторные пробы/ошибки/cleanup. Регистрация consumer не означает подтверждённый live apply |
| D: полное время проверок | Capabilities; ведущий: интеграция | TLS/SOCKS N12: p50 93.651→50.622 мс, p95 94.937→51.990 мс (искусственная задержка40мс); очередь измерена отдельно. Вdaf733fe добавлены настоящие Xray/XHTTP full Check и original App queue→HTTP-readback, CSV и описание стенда | Первый native прогон корректно отказал из-за неподдержанного Xray26.10.31; e721fb8e закрепляет фактически поддержанный26.3.27. Требуются завершённые измерения N12 live/dead/cancel и очередь. WAN identity/задержка моделируются; аппаратные CPU/RAM/LAN и browser paint отдельно |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий: интеграция | Общий inventory и tri-state availability; c758ec34 публикует реальные регистрации installer/import/staged/native/probe/apply/health/recovery/rollback, AUTO использует тот же getter. Go/UI и независимое ревью PASS; registration не объявляет live readiness | Обновить матрицу после B/C/F. Для внешнего сайта нужен конкретный URL/репозиторий |
| F: lifecycle механизмов | Ведущий: HEV/Mihomo App/update/recovery; Capabilities: фактические capability; Backup: probe lifecycle | HEV2.17.1 actual TUN/HTTPS/cleanup, pinned install и3 subprocess crash recovery PASS; scoped-native20d8fdf1 PASS. Guarded install, exact rename admission, reader5, next-boot выбор, cold cleanup и recovery API/UI интегрированы | Реализуется Mihomo large-artifact transaction: потоковый файл256MiB отдельно от малых journal images, pinned gzip, binary/receipt/lifecycle CAS и recovery. До независимого ревью, native tests, reader6 и App wiring функция не объявляется доступной. Остальные lifecycle сценарии — внутренняя работа; WAN/reboot отдельно |
| G: независимая приёмка | Review; ведущий CI | Полный Linux push CI9ea526d9 run41245989794 PASS; focused native bd8a98d4 run41247014499 PASS. scoped-native20d8fdf1 PASS; полный текущий HEAD пока не принят | Полный CI каждого интегрированного SHA обязателен; PR23 остаётся draft без merge. Для аппаратных LAN/WAN/reboot нужны выделенное устройство, LAN-клиент и авторизация; сценарии стенда сохраняются в scripts и native tests |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.
