# Протокол приватного восстановления при обновлении и откате

Этот локальный этап устраняет несогласованный снимок, который мог быть создан
одновременно с online-импортом. Он не открывает импорт provider-архивов и не
считает функцию готовой к стабильному релизу без Linux/Entware/HIL.

## Обновление

1. Read-only preflight проверяет кандидат до изменений.
2. Установщик определяет, был ли запущен прежний сервис, и строго останавливает
   его. Неудачная остановка завершает обновление до снимка.
3. Новый кандидат запускается в отдельном режиме `-recover-private-restore`.
   Режим использует тот же config/custom/devices/staging/provider layout, не
   загружает Store, не создаёт учётные данные и не запускает HTTP.
4. Только после подтверждённого `clean`, `applied` или `rolled_back` создаётся
   снимок. В него входят отдельные файлы, dataplane, staging и приватные копии
   Cloudflare. Сам журнал и `.restore.lock` не копируются и не удаляются.
5. Manifest записывается последним и получает
   `PRIVATE_RESTORE_PROTOCOL=1`. Незавершённый каталог без manifest не является
   допустимой точкой отката.
6. Затем выполняются установка, миграция, деактивация dataplane, запуск и
   проверка. Ошибка использует только полный снимок.

Если восстановление журнала прервано или имеет третье состояние, старый процесс
не запускается автоматически: это fail-closed, потому что старый бинарник может
не знать новый протокол. Если ошибка произошла до recovery или после
подтверждённого idle, прежний сервис можно безопасно вернуть.

## Откат

- Путь snapshot канонизируется и допускается только внутри приватного
  `update-backups`; корень установки должен быть абсолютным и не `/`.
- Manifest и все заявленные файлы/каталоги проверяются **до остановки** сервиса
  и до первой перезаписи.
- Ошибка stop больше не игнорируется. При новом manifest текущий бинарник после
  остановки обязан успешно выполнить `-recover-private-restore`.
- После idle-журнала точно восстанавливаются staging, Cloudflare private copies
  и dataplane. Журнал остаётся текущим idle evidence и не заменяется снимком.
- Старые manifest не содержали staging/provider. Для них действует `skip`, а не
  удаление текущих каталогов; это сохраняет обратную совместимость.

## Автоматические проверки

- clean maintenance recovery не загружает и не создаёт application Store;
- повреждённый журнал останавливает операцию и остаётся неизменным;
- shell regression проверяет порядок `stop → recover → snapshot`, отсутствие
  мягкого `stop || true`, одинаковый layout boot/migrate/recover и запрет
  восстановления неполного private snapshot;
- Linux Entware regression должен проверить точное сохранение staging/provider,
  обратную совместимость старого manifest и реальный restart/rollback.

## Аппаратный baseline 1 сентября 2026

На эталонном Keenetic ARM64 выполнен цикл `0.18.0 → 0.18.1-dev → 0.18.0`:

- dry-run подтвердил SHA-256 и совместимость schema 1 без изменений;
- apply остановил прежний PID, выполнил recovery, создал protocol-1 snapshot,
  запустил новый PID и прошёл HTTP/dataplane health;
- существующие UI credentials и config сохранились;
- snapshot пометил существующий staging и отсутствие provider-каталога;
- rollback вернул `0.18.0`, healthy PID, точное содержимое staging и исходное
  отсутствие provider-каталога; idle journal directory намеренно сохранился;
- на том же роутере прошёл полный изолированный `test-entware-transaction.sh`:
  dry-run, fresh/same-version install, protocol-1 staging/provider restore,
  incomplete snapshot rejection до stop, port-conflict auto-rollback, manifest
  injection/path traversal, old snapshot и rollback-aware uninstall;
- повторный fault-прогон подтвердил отказ до записи, когда stop оставляет owned
  PID живым, и когда maintenance recovery встречает повреждённый journal;
- временный кандидат и проверочные файлы удалены с роутера.

## Оставшийся release gate

Нужны Linux race-прогон и оставшаяся аварийная матрица (kill во время recovery/
snapshot/restore, power-loss), затем MIPS/MIPSel HIL. Stop failure и corrupt
journal уже проверены на изолированных ARM64-процессах. Успешные ARM64
transaction и рабочий upgrade/rollback не заменяют эти gates. До этого изменение
остаётся локальным защитным этапом, а не опубликованной гарантией.
