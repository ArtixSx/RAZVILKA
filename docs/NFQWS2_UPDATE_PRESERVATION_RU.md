# NFQWS2: сохранение настроек при обновлении

Статус: **исследование и выбранное направление, не реализованное автообновление**.
Дата: 22 октября 2026 года. Основа чтения: рабочее дерево кандидата 0.20.0
при HEAD `a4c15f03ab35c70f03ac43b525fc3c9a4d543a31`, включая находящуюся
на интеграции first-start реализацию. Этот документ не подтверждает её релизную
приёмку и не разрешает изменять runtime.

## Решение

Настройки пользователя должны переживать обновление движка. Для управляемого
закрытого NFQWS2-профиля выбран путь **закреплённых file-only generations**:
проверенный бинарник, Lua и blobs устанавливаются отдельным неизменяемым
поколением; настройки и область обработки сохраняются по смыслу; запуском
и откатом управляет существующий coordinator.

Обычный `opkg upgrade` с последующим возвратом конфигурации для этого пути
не подходит: пакетный postinst может запустить сервис до возврата ограничений.
Текущая блокировка изменения пакета — временная защита до законченной интеграции
безопасного обновления. Документ не снимает её и не предлагает ручной обход.

## Что подтверждено upstream

- В [z2k `lib/auto_update.sh`, commit
  `3d54cb6f075de2c455ec51b9a1dc752f9c660f31`](https://github.com/necronicle/z2k/blob/3d54cb6f075de2c455ec51b9a1dc752f9c660f31/lib/auto_update.sh)
  отделяются поставляемые файлы от пользовательских флагов. Флаги переносятся
  при обновлении; `au_merge_extra_domains` объединяет новую поставку с локальными
  добавлениями относительно прежней поставки: `new ∪ (current − old)`.
  Эта формула сохраняет добавления; сама по себе она не доказывает сохранение
  пользовательского удаления элемента из поставляемого списка.
- В [z2k `lib/install.sh`, тот же commit](https://github.com/necronicle/z2k/blob/3d54cb6f075de2c455ec51b9a1dc752f9c660f31/lib/install.sh)
  сохраняются пользовательские доменные и адресные исключения. При auto-update
  reinstall явный набор переносимых полей включает `ENABLED`, policy-настройки
  и пользовательские флаги; исключения возвращаются до первого запуска.
- В [nfqws2-keenetic `common/ipk/postinst`, commit
  `5d155f33ab00f3a4879c485c1094e8ec1e014586`](https://github.com/nfqws/nfqws2-keenetic/blob/5d155f33ab00f3a4879c485c1094e8ec1e014586/common/ipk/postinst)
  есть вызовы остановки init, установка бинарника/конфигурации и последующий
  вызов старта init. Сохранённый конфигурационный файл не исключает этот старт.
- В [nfqws2-keenetic `common/ipk/preinst`, тот же commit](https://github.com/nfqws/nfqws2-keenetic/blob/5d155f33ab00f3a4879c485c1094e8ec1e014586/common/ipk/preinst)
  отсутствующий `CONFIG_VERSION` или версия ниже build `CURRENT_VERSION`
  инициирует миграцию: существующий `nfqws2.conf` перемещается в
  `nfqws2.conf-old`, postinst получает режим чистой установки. Поэтому даже
  сохранённый пользовательский conf нельзя считать безусловно совместимым
  с новой версией движка/обёртки.
- [nfqws2-keenetic `common/ipk/conffiles`, тот же commit](https://github.com/nfqws/nfqws2-keenetic/blob/5d155f33ab00f3a4879c485c1094e8ec1e014586/common/ipk/conffiles)
  перечисляет основной conf и пять списков: user, auto, exclude, ipset,
  ipset_exclude. S51 в этот список не входит. Опора только на opkg conffiles
  не сохраняет управляемый inert init.

Это подтверждает применимость идеи переноса пользовательского выбора.
Совместимость z2k с RAZVILKA, корректность его packet semantics и безопасность
копирования его update executor здесь не заявляются. Shell-код upstream не
переносится в RAZVILKA этим решением.

## Действующие части RAZVILKA и их границы

| Механизм | Где и какие функции | Что уже обеспечивает; чего не обеспечивает |
| --- | --- | --- |
| Обновление opkg с сохранением конфигурации | `internal/components/managed_update.go`: `snapshotConffiles`, `ManagedUpdateGuardedWithRollback`; `internal/components/update_journal.go`: `updateTransaction.prepare` | Сохраняет файлы из package `.conffiles` и прежний IPK в durable snapshot, проверяет admission. Это не полный snapshot first-start ownership, assets и init. Candidate check выполняется после пакетной команды. |
| Откат opkg | `internal/components/update_recovery.go`: `updateTransaction.rollback`, `restore`; `managed_update.go`: `restoreConffiles` | Восстанавливает конфигурацию до и после переустановки старого IPK. Его пакетные скрипты тоже могут выполняться. Возврат файлов не устраняет уже случившийся промежуточный запуск. |
| Проверка старого package-update пути | `internal/app/component_managed_update.go`: `nfqws2UpdateCheck`; `internal/dataplane/nfqws2_adopt_init.go`: `AdoptPackageInit` | Сравнивает конфигурацию до/после, проверяет runtime; adoption меняет только допустимый init hash. FirstStart lease намеренно не принимается этим adoption. Это не перенос закрытого профиля на новую версию. |
| Надзор над пакетной командой | `internal/components/package_supervision.go`: `updateTransaction.runPackage` | Фиксирует исход и containment команды. Не удаляет postinst и не превращает его старт в разрешённый coordinator action. |
| File-only установка/обновление | `internal/components/nfqws_bundle_archive.go`: `extractManagedNFQWS`, `stageManagedNFQWS`; `internal/components/nfqws_bundle.go`: `InstallManagedBundle`, `UpdateManagedBundle`, `continueManagedNFQWS` | Проверяет закреплённый архив и выбранные members, публикует отдельное поколение и receipt. Из control archive ничего не исполняется; config/init/hooks не входят в выбранные payload members. Receipt `ready-idle` описывает файлы, не работоспособность маршрутов. |
| File-only recovery | `internal/components/nfqws_bundle.go`: `publishManagedNFQWSReceipt`, `RecoverManagedBundle` | Сравнивает допустимые before/after образы receipt, сохраняет поколения; rollback возвращает прежний receipt или прежнее отсутствие. Не выполняет runtime handoff или запуск прежнего процесса. |
| Actual owner поколения | `internal/components/nfqws_bundle_runtime_current.go`: `AcquireCurrentManagedNFQWSRuntime`; `nfqws_bundle_runtime.go`: `AcquireManagedNFQWSRuntime`, `Check` | Читает защищённый receipt, terminal journal и assets под существующим component writer. Detached descriptor не заменяет этот owner. |
| Закрытый stock first-start | `internal/engineconfig/nfqws_first_start.go`: `NFQWSFirstStartConfig`, `NFQWSFirstStartEffectiveConfig`; `internal/dataplane/nfqws2_first_start.go`: `startFirstStart`, `captureFirstStartProcess` | Компилирует ограниченную область и проверяет фактический запуск. Пока фиксирует stock executable и Lua-пути; выбора managed generation здесь нет. |
| Stock native review | `internal/components/nfqws_stock_native.go`: `ReviewStockNFQWSNative`, `CheckCurrentWithOwnedInit`, `ReviewClosedFirstStartParameters` | Удерживает исходные package assets и проверяет native параметры. Замена бинарника/Lua во время удержания должна отзывать проверку. Это не разрешение принять новые assets. |

В `internal/app/component_nfqws_bundle.go` bundle пока связан с установкой
и managed compatibility-проверкой. App не вызывает `UpdateManagedBundle`;
имеющиеся вызовы обновления находятся в компонентных тестах. Bundle authority
`Inactive` проверяет свой managed runtime, stock runtime не присваивает.

Каталог `ReviewedManagedNFQWSManifest` в
`internal/components/nfqws_bundle_manifest.go` закреплён на ARM64/1.3.1.
Для следующих версий/архитектур нужны отдельные reviewed manifest, hashes,
ABI/Lua compatibility и сведения об источниках/лицензиях. Наличие текущего
manifest не является реализацией безопасного «скачать latest».

## Что переносится по смыслу

Планируемый перенос не равен копированию всего старого shell config поверх
новой поставки. Источником пользовательского выбора остаётся текущая
конфигурация RAZVILKA и подтверждённый план, а не defaults нового IPK.
Новый поддержанный формат пересобирается из этих semantic settings с явной
проверкой совместимости. Это требуется и из-за версионной миграции upstream:
возврат полного старого conf может восстановить устаревший формат вместо
сохранения пользовательского выбора в новом формате. Exact byte snapshot
прежнего файла остаётся материалом для согласованного отката на прежние assets,
а не автоматическим конфигом для нового движка.

- Выбранные сервисы и стратегия, положительные suffix-domain scopes каждого
  активного профиля, разрешённые интерфейсы/клиенты и policy-настройки сохраняются
  без расширения. Общий UDP/QUIC, custom/IPSET passthrough или обработка всего
  HTTPS не возникают как побочный эффект новой версии.
- Пользовательский Stop/пауза, SafeMode, согласие на сетевые эффекты и выбор
  автообновлений сохраняются. Обновление assets не включает ранее выключенный
  сервис и не возобновляет отозванное согласие.
- Эффективные доменные и адресные exclusions пересчитываются из актуальных
  источников до запуска. Они применяются ко всем активным профилям. Изменение
  исключений или политики во время подготовки отзывает прежний review.
- Пользовательские добавления и удаления отделяются от поставляемых списков.
  Если потребуется merge поставки, его база и обе версии должны быть известны;
  конфликт или отсутствующая база не дают права молча расширять обработку.
  Формула z2k для добавлений — пример, не готовая политика RAZVILKA для удалений.
- Несовместимая стратегия/параметр требует понятного отказа или отдельной
  миграции с review. Нельзя тихо подменять её более широким профилем.

## Минимальная законченная доработка: ещё предстоит

1. Связать current accepted managed generation с existing first-start ownership
   и компилятором. Executable, Lua и blobs берутся из actual retained asset owner;
   init остаётся inert для обычных boot/NDM/start/restart. Новые пути/argv должны
   иметь точное детерминированное представление, а не произвольные shell overrides.
2. Добавить coordinator handoff под существующими operation/resource/component
   gates: сохранить прежний план и generation, проверить актуальную политику,
   остановить только exact owned process, подтвердить полное отсутствие конфликтов,
   затем переключить assets. Обновление file-only receipt само по себе не
   останавливает процесс и не разрешает запуск.
3. Согласовать порядок locks и lifetime owners. Нельзя вызвать bundle update,
   пока прежний stock native review удерживает тот же component writer, либо
   закрыть review и затем использовать его как прежнее разрешение. Нужны явная
   передача под coordinator и новый actual owner для кандидата/отката.
4. Перед каждым запуском выполнить native validation точного закрытого argv на
   выбранном поколении, затем повторить currentness/policy/process/kernel checks.
   После controlled start записать свежую process identity и проверить здоровье
   выбранных сервисов. `--dry-run` подтверждает параметры, но не packet semantics
   и не успешный обход DPI.
5. Подключить этот законченный путь к HTTP и scheduler update, корректно показывая
   provider/flavor и отдельную opkg-версию. Не выдавать замену managed payload
   за выполненное обновление stock opkg package. Guard снимается только для
   реально поддержанного и проверенного пути, не общим исключением NFQWS2.

## Crash, CAS, health и rollback: критерии приёмки будущей реализации

- Durable intent предшествует каждому эффекту. Проверяется exact before image
  и ожидаемый staged/after image для receipt, плана, конфигурации и ownership;
  неизвестный третий образ сохраняется и блокирует продолжение.
- Сбой между публикацией поколения, receipt, запуском и записью process receipt
  не даёт права повторить неоднозначный старт или принять найденный PID по argv.
  Recovery повторяет только доказуемые локальные CAS-переходы; boot не обходит
  незавершённый журнал и пользовательский Stop.
- Отмена, изменение revision/consent/exclusions, foreign process/kernel state,
  подмена binary/Lua/blob/init, timeout и заполнение диска проверяются до эффектов
  и на соответствующих границах. Неизвестный исход остаётся fenced.
- Candidate generation сначала проходит независимую проверку; успешная загрузка
  или receipt `ready-idle` не считается live acceptance. Нужны фактический новый
  процесс, его exact identity, runtime/kernel observation и сервисные health checks.
- При доказанном отказе кандидата coordinator останавливает только его owned
  процесс, возвращает exact prior generation/settings/ownership и отдельно
  валидирует прежние параметры перед прежним controlled start. Candidate health
  не переиспользуется как доказательство rollback health.
- Если пользователь успел остановить сервис, откат возвращает файлы и состояние
  без автоматического запуска. Если остановка/rollback не доказаны, нельзя
  обещать «всё восстановлено» или снимать maintenance fence.
- Регрессии должны покрывать сбой на каждой durable границе, замену третьим
  образом, сохранение Stop/exclusions, отказ нового native argv/ABI, health failure,
  отмену и recovery после reboot. Аппаратная проверка должна отдельно подтвердить
  отсутствие промежуточного broad start и реальную обработку только выбранных сайтов.

## Freeze

Документ фиксирует исследование и направление дальнейшей работы. Реализация
executor/asset migration, изменение активной recovery-интеграции и ослабление
package guard в этот scope не входят. Рабочее автообновление с сохранением
ownership этим документом не объявляется готовым.
