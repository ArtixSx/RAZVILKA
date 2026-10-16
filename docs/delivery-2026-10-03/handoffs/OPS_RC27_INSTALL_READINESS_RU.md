# OPS: установка rc27 и будущие обновления 0.20+

Дата: 16.10.2026. Анализ исходника `98eec3ce`; это проверяемая памятка,
не подтверждение обновления роутера. VM, роутер и GitHub здесь не запускались.
Изменений установочного протокола, config/schema и сетевых writers нет.

## Решение для установленной rc26

Штатного локального ввода неопубликованного rc27 сейчас нет. Оставить rc26
установленной, пока координатор не выберет допустимый источник кандидата.

- `internal/updatecheck/updater.go`: `NewUpdater` выбирает `OfficialClient`;
  `PrepareChannel` получает только revision/fingerprint/channel, затем читает
  официальный release; `Apply` заново получает тот же release ID.
- `internal/updatecheck/release.go`: `FetchReleaseChannel` использует фиксированный
  официальный GitHub repository, проверяет release/asset URL, ID, размер и digest.
  Production-переменной окружения для локального источника нет.
- `self-update-files` принимает действия только для существующего matching
  helper/review. Это не команда подготовки локального пакета.
- `self-update-bootstrap-old193` предназначен для старого 0.19.3; он не является
  входом rc26→rc27. Миграция старых выпусков в текущую задачу не входит.
- Подмена HTTP transport в tests — fixture. Запись выдуманных release IDs,
  правка `current.json` и ручная сборка review не создают release admission.

Реальный preview prerelease с версией выше установленной rc26 допускается
preview-каналом. Его публикация — отдельное решение координатора; памятка не
публикует выпуск. Для последующего stable-теста использовать семантически более
высокую версию, например 0.20.1, а не 0.2.0. Нельзя перезаписывать assets одного
опубликованного номера ради следующего теста.

## Почему uninstall не открывает переустановку

`scripts/uninstall-entware.sh` сначала выполняет init `stop`, затем recovery
private restore и owned dataplane deactivation; отказ любого шага оставляет
бинарник для ремонта. Только успех разрешает удалить ровно binary/init.
Настройки, profiles, компоненты, backup и все retained control/file receipts
остаются. В uninstall нет shell-проверки `require_legacy_file_protocol_free`;
это не обещание, что native Stop/recovery разрешат неизвестный lifecycle.

`scripts/upgrade-entware.sh --apply`, напротив, до stop/замены отвергает даже
одно наличие `self-update-stop`, `self-update/current.json`,
`self-update-files/current.json` либо непустого retained protocol directory.
Остановленный процесс, отсутствие PID и удалённый binary этот guard не снимают.
Поэтому uninstall→clean install поверх сохранённых данных не поддержан.
Не удалять и не переносить retained ledger ради обхода guard. До наличия пути
обновления uninstall может оставить установку без штатного пути возврата панели.

## Минимальный штатный тест после доступности настоящего кандидата

1. Сверить candidate commit/version/ARM64 hash с reviewed артефактом и сохранить
   исходные hash/version бинарника rc26. Выписать состояние `self-update current`,
   recovery/control, component/private recovery и runtime; неизвестный владелец
   или незавершённый network cleanup — blocker. Отдельно снять readonly исходные
   DNS/RPDB/чужой `nwg0` и контрольные наблюдения выбранного LAN-клиента.
2. Подготовить приватную резервную копию вне изменяемых каталогов: бинарник/init,
   `/opt/etc/razvilka` и `/opt/razvilka/state`, включая permanent ledgers и LKG.
   Держать копию root-only, проверить читаемость, hashes и свободное место.
   Для согласованного checkpoint использовать исходного владельца и его quiesce;
   копию при работающем writer считать forensic, не атомарным recovery image.
   Эта копия не даёт права поверх вернуть старые сетевые эффекты или ledger.
3. Через авторизованную панель выбрать preview-канал для rc27 и подготовить
   пакет. API: POST `/api/v1/self-update/prepare` с
   `{"confirm":"PREPARE_APP_UPDATE"}`; дождаться готового matching job и
   проверить release/version/hash, config revision и review token. Auth/CSRF
   и исходная config revision обязательны. Не задавать ручные ID/token.
4. POST `/api/v1/self-update/apply` с полученными `job_id`, `review_token`,
   `config_revision` и `confirm=INSTALL_APP_UPDATE`. Единственный исходный helper
   выполняет prepare → stop-old-panel → prepare-private-state →
   quiesce-old-runtime → install → start-candidate-panel → accept-live.
   Не останавливать helper отдельным таймером. Пользовательский durable Stop
   меняет authority; это отдельный тест, не предварительное условие обновления.
5. Дождаться terminal journal, independently проверить новый PID/hash/version,
   authenticated API, настройки/исключения и реальные packet/route/DNS-наблюдения.
   Отсутствие PID старой панели не доказывает quiesce сети. Не считать бинарную
   замену или живую панель доказательством LAN-доступа.
6. Отдельно на согласованном стенде проверить сбой до/после file install,
   неизвестный command outcome и durable Stop. Сохранять исходные ID/receipts.
   Обычный helper при ошибке выполняет stop-candidate-panel → restore →
   restore-private-state → start-rollback-panel → accept-rollback. Durable Stop
   требует matching `settle-stopped-rollback`, а не запуска маршрутов через
   старую конфигурацию. Не возвращать запрещённые текущими исключениями эффекты.

Независимая диагностика без панели: `/opt/bin/razvilka self-update-files current`.
Ремонт через API `/api/v1/self-update/recovery` или CLI
`/opt/bin/razvilka self-update-files <action> <transaction-id> <revision>`
допустим только для свежо прочитанного matching состояния и допустимого следующего
действия. Recovery API требует `transaction_id`, `action`, `expected_revision`,
`confirm=REPAIR_SELF_UPDATE_TRANSACTION`, auth/CSRF. `resolve-unknown` не означает
безусловный повтор неизвестной команды. При отказе сохранить журналы и исходные
образы; shell rollback, raw cp и удаление stop/state не являются fallback.

Чистая 0.20.0 проверяется отдельно на действительно чистом production root:
проверенный archive + `dist/SHA256SUMS`, сначала `upgrade-entware.sh --dry-run`,
затем `--apply`. `RAZVILKA_BASE` не перенаправляет native control authority;
временная директория shell-fixture не доказывает реальную установку.

## Проверки этого прохода

Локально Windows/Git Bash, исходник `98eec3ce`, без live сети/пакетов:

- `sh scripts/test-bootstrap.sh`: PASS, isolated recording fixtures.
- `sh scripts/test-clean-control-installer.sh`: PASS, 11 models;
  вывод явно `native_initialization=false`.
- `sh scripts/test-uninstall-entware.sh`: PASS, isolated Stop/recovery/cleanup.
- `sh scripts/test-installer-architecture.sh`: FAIL в первом mipsle dry-run:
  `Self update metadata is unknown or incompatible; installation unchanged`.
  Отдельная проверка Git Bash `sh -c 'ulimit -f 128'` возвращает rc1:
  `file size: cannot modify limit: Invalid argument`; metadata probe требует
  успех этого ограничения до запуска кандидата. Это ограничение Windows host,
  а не PASS архитектур и не аппаратный тест.
  Повторить в Linux штатным CI, не ослаблять metadata guard ради Windows.

ARM64 live clean/update/rollback, ARM64 rc26→rc27, прерывания native lifecycle,
future 0.20.0→higher и schedule update здесь `not_run`. MIPS/MIPSel cross-build
отложен координатору; аппаратных MIPS-роутеров нет, будущий cross-build-only
нельзя называть проверкой железа. Legacy shell pruning не менялся: он недостижим
как обход текущего managed update. Полный CI выполняет координатор на финальном
commit; перечисленные fixtures его не заменяют.
