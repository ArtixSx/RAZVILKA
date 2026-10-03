# D11: журнал обновления компонентов

Реализован persistent journal для managed opkg-обновлений. Это проверяемое ядро D11, не заявление об аппаратной приёмке или power-cut испытании.

## Хранение и этапы

`components/update-journal/current.json` хранит schema, случайный transaction ID, component/package, версии, фазу, SHA-256 пакета и конфигураций. Приватные снимки находятся в подкаталоге transaction ID с правами 0700/0600. Пакет копируется потоково, конфигурации ограничены 32 файлами и 4 MiB суммарно. Данные снимка синхронизируются до записи prepared. Фазы записываются через временный файл, file sync, atomic rename и directory sync на Linux.

`prepared → upgrade-started → upgrade-finished → awaiting-live-acceptance → accepted`.

Откат: `rollback-config-before → rollback-ready → rollback-started → rollback-installed → rollback-config-after → awaiting-rollback-acceptance → rolled-back`. Перед и после установки старого пакета восстанавливаются сохранённые conffiles. Package/config checksums проверяются до восстановления. Только prepared допускает abandon без установки пакета.

Незавершённый journal блокирует новые Apply/Remove/ManagedUpdate во всех новых экземплярах Manager. Постоянный inode с kernel lock сериализует процессы; lock не удаляется по PID/возрасту. Повреждение/неизвестная схема также блокируют операции. Public Apply не обновляет уже установленный managed компонент: нужен отдельный checked managed path.

Скачивание нового rollback-пакета больше не удаляет прежний LKG. Снимки и прежние версии пока не удаляются автоматически: retention требует отдельного решения с учётом доступного места.

## Контракт приложения

- `ManagedUpdateGuarded(ctx, id, candidateCheck, authorityGuard)` повторяет актуальную проверку полномочий перед изменениями. После candidateCheck результат содержит `PendingLiveAcceptance=true`, `TransactionID`; lifecycle receipt обозначен `candidate-installed`.
- `PendingManagedUpdate()` читает fence без запуска opkg и без восстановления. Ошибка чтения является блокировкой, а не отсутствием pending.
- `RecoverManagedUpdate(ctx, request, authorityGuard, liveCheck)` требует точные component+transaction ID, ненулевой authorityGuard и не допускает SafeMode/Stopped. Guard должен читать текущие флаги/ревизии, а не замыкать прежнее разрешение.
- `accept-live` требует awaiting-live-acceptance, точную установленную версию и проверку фактически принятого runtime. Изолированный candidate probe не является такой проверкой.
- `rollback` продолжает известные этапы; upgrade-started требует отдельного AllowUnknownRollback. Upgrade никогда не повторяется. Rollback-started запрещает повтор команды установки.
- `verify-rollback` только наблюдает совпадение версии/config и live evidence. Для rollback-started нужны ExternalRepairConfirmed и доверенный QuiescenceCheck. Этот callback не заполняется из HTTP JSON; он должен независимо подтвердить завершение opkg и package scripts. Без такого доказательства unknown остаётся заблокированным.
- Приложение должно сохранять maintenance fence при PendingLiveAcceptance и при unknown, восстанавливать его при startup и допускать только matching repair/Stop. Общий app/worker/CLI wiring выполняет интегратор.

Оба installer schema gates требуют от целевого бинарника `-component-update-schema` с ответом `1`, когда retained current.json существует. Проверки выполняются до остановки и после quiescence. Журнал не включается в восстанавливаемую копию конфигурации приложения и не стирается при downgrade.

## Проверки и ограничения

Unit fault matrix прерывает выполнение до/после 38 границ durable phases, package commands, config writes и receipts. Пять subprocess-тестов завершают дочерний процесс через os.Exit: старые память и mutex не переживают restart. Package runner в этих тестах явно является симулятором с дисковым состоянием.

`scripts/test-component-update-supervision.mjs` выполняет настоящие shell schema gates на временных файлах. `scripts/test-component-update-native.sh` отдельно запускает opt-in интеграцию с настоящим opkg, локальным feed и временным offline root. Синтетический IPK содержит postinst, который намеренно мигрирует конфигурацию; тест требует подтверждения его выполнения. Этот native тест не запускается обычным unit-прогоном и не объявляется пройденным без отдельного запуска.

Windows backend проверяет file sync, атомарную замену и process-crash recovery; directory power-loss durability на Windows не заявляется. Нужны Linux native opkg, реальное отключение питания до/после фаз, fsync/storage испытания на целевом роутере. Package scripts могут менять данные вне объявленных conffiles; данный журнал не обещает восстановление произвольных внешних эффектов таких скриптов. Unknown команды не повторяются.

Полный self-update application binary/config script по-прежнему использует существующий snapshot/rollback protocol; компонентный журнал и schema gate сами по себе не являются crash-safe журналом каждой файловой фазы этого установщика.
