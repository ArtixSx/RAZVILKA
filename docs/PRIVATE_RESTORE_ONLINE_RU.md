# Приватный импорт: online-журнал и согласование хранилищ

Локальный этап 31 августа 2026 года. Версия остаётся `0.18.1-dev`.
Ни публикации, ни установки на роутер в этом этапе не было.

## Реализовано

- Существующий HTTP private-backup import использует lifetime coordinator,
  созданный до загрузки Store при старте. Прежняя последовательная компенсация
  больше не является production fallback; её harness оставлен только в тестах
  отдельных guarded undo API. Без coordinator импорт отказывает до записи.
- Перед записью захватываются config/catalog/devices Store sessions и выбранные
  staging slots. Их bindings сверяются с доверенными путями startup layout.
  Чужой Store/root не может подменить цель восстановления. Вычисление ожидаемой
  привязки не открывает файл и не пытается повторно взять уже занятую lease.
- Online/offline строят одинаковые типизированные образы: desired services,
  объединённый каталог, имена/группы устройств и выбранные черновики. Applied,
  Safe Mode, EngineOrder, DNS, учётная запись UI и runtime не активируются.
- Журнал prepared/committed сохраняется **до завершения обновления кэшей**.
  Сначала проверяются записи/откат, затем закрываются Store sessions с перечтением
  файлов, затем журнал становится idle. API/background/collector всё это время
  исключены общим admission. Ошибка закрытия сессии тоже учитывается.
- При recovery_required coordinator и App остаются закрыты для новых операций.
  Допуск не открывается после окончания запроса. Следующий запуск проверяет
  журнал до Load; неизвестный/испорченный образ не затирается. Unexpected panic
  тоже сохраняет запрет дальнейших операций. Это не автоматический restart.
- UI различает отказ до начала, подтверждённый откат и необходимое recovery.
  Recovery имеет приоритет над not_started: занятый/запрещённый повторный запрос
  не скрывает исходную проблему. Нет предложения применить частичные черновики
  или удалить журнал; пароль/архив/preview сбрасываются, автоповтора нет.
- Внутренний online coordinator также проверен с копиями Cloudflare accounts.
  **Общий HTTP-импорт ProviderSnapshots всё ещё запрещён**. Это не расширение
  публичного archive-контракта и не регистрация/активация аккаунтов.

## Занятость, а не ложная неисправность

`/api/v1/status` во время приватного импорта не читает запертые Store. Ответ
409 содержит только безопасную identity процесса и `RESTORE_OPERATION_BUSY`.
Healthcheck сверяет имя/версию/PID и возвращает код 75 (temporary unavailable),
а не «healthy». Strict dataplane health тоже не получает выдуманный PASS.
Recovery fence остаётся ошибкой 503, а не временной занятостью.

S99 status сообщает занятость; startup по исчерпании ожидания с последним busy
ответом не останавливает процесс. Upgrade не запускает автоматический rollback
из-за кода 75: сохраняет ссылку на snapshot, оставляет процесс и сообщает, что
готовность **не подтверждена**. Это не завершённая успешная установка. Нормальная
ошибка health остаётся ошибкой и не обходится этим исключением.

Migration получает те же custom-services/devices/stage пути, что S99 startup,
в том числе при нестандартном `RAZVILKA_BASE`. Cloudflare/journal по-прежнему
размещаются относительно config согласно общей startup-функции.

## Проверки

- Полные `go test ./... -count=1 -timeout=90s` и `go vet ./...` на Windows.
- Online/journal handover/fence сценарии прошли пять повторов.
- Успех, отказ каждого из семи writes, отмена между writes, отсутствие чужих
  изменений, сохранение отсутствующего/пустого/незаконченного draft, сверка
  каждого Store binding, освобождение сессий, повторная операция после отката.
- Кэши config/catalog/devices сравниваются с повторно загруженными файлами.
  Ошибка cache handover и повреждённый конфиг сохраняют committed journal;
  неизвестная третья версия сохраняет prepared journal и блокирует запуск.
- Дочерние процессы реально завершаются принудительно в 11 online-точках:
  prepared, семь writes, rollback, committed перед handover и после завершения.
  Recovery выполняется production Open до повторного Load.
- Настоящий HTTP import работает под общей блокировкой; испорченный журнал
  закрывает последующие GET/devices/status/Apply/import и фоновые операции.
  Отдельно проверены отсутствие fallback и приоритет fenced UI-сообщения.
- Шесть JS suites и синтаксис app.js прошли. Дополнительный
  `test-restore-busy-supervision.mjs` исполняет извлечённые production shell
  ветви с заглушками: healthy/error/busy start/status, busy upgrade, одинаковые
  migration/startup пути. `sh -n` для двух изменённых скриптов прошёл.
  Общий check.sh включает новый regression и device UI suite; syntax-check
  теперь перебирает каждый shell-файл, включая S99, а не только первый аргумент.
- Все пакеты и пять test binaries (privaterestore/App/journal/gate/main)
  собраны для Linux arm64/mips/mipsle softfloat; **не запускались**.

Shell branch tests выполнены через bundled Git sh на Windows. Это не полный
`test-entware-transaction.sh`, не Linux/race, не HIL и не отключение питания.
Browser visual QA не проводился; UI-поведение проверено скриптом.

## Следующий обязательный блок перед релизом

1. Upgrade сейчас делает snapshot отдельных файлов **до остановки сервера**.
   При online restore это может получить несогласованный набор. Нужны остановка/
   exclusive ownership до snapshot и явная работа с pending private journal.
   Не решать проблему простым копированием/удалением `.restore.lock`.
2. Rollback не управляет private journal и не проверяет поддержку протокола
   старым бинарником; stop failure сейчас допускается. Запретить восстановление
   поверх активного/неизвестного journal и согласовать snapshot/rollback layout.
   Idle scope привязан к layout/набору slots: нужна политика совместимости при
   изменении путей/версий, а не автоматическое удаление recovery evidence.
3. Прогнать полный Linux/race/Entware цикл: import одновременно с upgrade,
   process crash до/после commit, неудачный stop, rollback новой/старой версии,
   занятый health, changed layout. Затем аппаратная матрица и power-loss.
4. Только после этих gates открывать общий router+provider HTTP archive,
   продолжать secret access/lifecycle ownership и новый registrar.

Защита относится к участвующим API/Store writers. Прямой root-доступ, старые
бинарники и альтернативные inode/symlink/hardlink aliases не изолируются новым
in-process gate. Запрет Apply при неопределённом исходе намеренный; обходить его
через ручное удаление journal/lock нельзя. До аудита пунктов выше этап **не готов
к стабильному релизу**, даже при успешных локальных тестах.
