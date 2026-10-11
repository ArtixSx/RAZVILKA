# OPS: подготовка обычного обновления 0.20.0 → выше

Область: `internal/updatecheck`. Выпуск остаётся 0.20.0; VERSION, публичные
документы, Main/App signatures и CLI не меняются. Чистая установка 0.20.0 и
последующее ручное/автоматическое обновление — текущий контракт. Старый внешний
bootstrap 0.19.3 не используется этим producer.

## Причина и закрытый профиль

В genuine native run 339 проверенный будущий архив дошёл до Prepare/preflight,
где shell dry-run требовал `-self-update-schema=2`. Текущий Main правдиво
объявляет 0; общий capability2 путь остаётся строгим. Обычный новый профиль
доступен только исходному `Updater.prepare` для версии >=0.20.0 и строго более
нового релиза, с полным reader4. Он не предоставляет raw apply или runtime
acceptance.

Private `ordinaryPreparation` привязан к исходному конечному контексту Prepare,
конкретному Updater/done generation, тому же adapter и self seal. Он отзывается
после возврата, отмены, смены поколения/record или начала handoff. Только
фактический Linux UID0 producer с каноническими путями может его выпустить.
Новый job изначально содержит ровно проверенные bundle и release.tar.gz.

До/после дочерних команд сверяются неизменённые current bytes, физические roots,
архив и девять extracted hashes, фактическая исходная панель (PID file,
boot/birth/device/inode/executable SHA), config revision/fingerprint, SafeMode,
Stop epoch и отсутствие pending file effect. Метаданные требуют точные 0/4,
native/subscription1 и достаточные typed node/component readers. Сохраняются
проверки retained journals и полный immutable reader4 proof.

## Команды и staged containment

Запускаются существующие genuine candidate `-check` и `-migrate-config`.
Источник `-check` — настоящий текущий config, а каталоги — проверенный bundle.
Все mutable flags миграции направлены в `<job>/staged`: config.json,
custom.json, devices.json, nodes, engines, warp, cloudflare. Recovery journals,
которые Main выводит из каталога config, тоже остаются внутри staged.
До миграции staged содержит ровно исходный config; после проверяются private
bounded tree без ссылок/special files и реальная сохранность настроек.
`migrated=false` допустимо для genuine no-op migration.

Executable открывается через ownedfs, проверяется его digest и удерживается
до настоящего Wait. Exec использует `/proc/self/fd/3`; argv[0] сохраняет реальное
имя, а для syntax-only shell — `/bin/sh` (BusyBox applet). Только точный Start
проходит существующий Stop effect admission; Wait вне lock. Команды имеют
конечный срок, периодический отзыв исходного owner, cancellation/group cleanup
и обязательный join фактического direct child. Raw stdout/stderr не сохраняются
в metadata или публичном результате. Installer scripts проходят только `sh -n`.
Public failure codes используют закрытые категории `ordinary-preparation-*-
refused`: owner/version/histories/capabilities/journals/candidate-check/
script-syntax/migration/ready. Private cause остаётся только в error chain;
первоначальный вывод команды не раскрывается.

## Ready до рождения helper

Новый обычный sealed review содержит optional private `preparation_parent`.
Фактические boot/birth/device/inode/executable SHA исходной панели входят в
существующий review digest и полный reader4 профиль, Bootstrap остаётся nil.
Ready независимо проверяет свежую настоящую каноническую панель против этой
идентичности, неизменённый review/header, authority/Stop, файлы и typed readers.
Исходная capability подготовки не восстанавливается. `helper.identity.json`
должен ещё отсутствовать; обычный helper создаёт и проверяет его позже.

Отсутствующее поле сохраняет прежний строгий capability2 Ready. Некорректное,
неизвестное или несовпадающее присутствующее поле отказывает без fallback.
Последующая helper identity обязана сохранять тот же исходный parent.

Private read cut между fsync review и публикацией current доступен лишь тому же
живому producer/context/adapter и точному review digest. Публичные/cold readers
продолжают считать такой uncommitted cut fence. Процессные/runtime/private
receipts, Stop/CAS/auth/CSRF и существующие RunHelper/Startup/Live gates не
заменяются.

## Проверка и native acceptance

Windows: focused ordinary regression tests, полный updatecheck suite и vet.
Linux amd64/arm64: vet и test-c, без запуска ELF в OPS. Portable tests покрывают
отзыв/копирование/смену поколения; closed metadata/command arguments; parent
birth/boot/inode/device/exe/PID; invalid-present no fallback; absent strict cap2;
private/public read cut; helper parent binding и no-op migration.

Native runner tests отдельно проверяют настоящий Start/Wait при отзыве и
same-byte inode replacement до Start. Они пишут только новый private `/root`
fixture, не используют production `/opt` и не являются genuine future-update
acceptance. OPS их не запускал.

Root должен собрать новые genuine clean0.20.0 и higher archives из интегрированного
finished source, выполнить native source checks и четыре независимых harness
runs: manual/auto × upgrade/rollback. Run339 и прежние архивы не подтверждают
этот новый consumer. Frozen harness63 и его private README/audit остаются без
изменений. Только Root владеет VM/ELF/router; общая `/opt/var` не используется
новым producer.
