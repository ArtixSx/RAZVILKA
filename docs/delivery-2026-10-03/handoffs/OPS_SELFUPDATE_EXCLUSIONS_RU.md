# D11: сохранение исключений при замене файлов

Дата: 2026-10-08. Законченная ограниченная порция OPS по пользовательской
коррекции list mode. Это проверка сохранённых данных и отрицательный отказ
перед эффектом, а не приёмка восстановленных маршрутов или production runtime.

## Зависимости и область

Ветка `sol/ops-20261003`; непосредственный родитель этой порции `d4f41af` —
локальный эквивалент finished CORE `5446c58`. Предыдущие зависимости:
`bb5cd10` = CORE `0438dd9`, `97bb7c5` = CORE `5be9925`. Root уже принял
оригинальные CORE пакеты; повторно переносить эти зависимости не требуется.
В пакет OPS входят только updatecheck, selfupdatejournal, их regression tests
и этот handoff. App/main/config/DEFAULT/NET не редактировались.

## Проверки перед миграцией и rollback

Прежний permissive `json.Unmarshal` в staged migration и текущей authority
заменён строгим `config.InspectBytes`: неизвестные поля, неподдерживаемая
структура и дополнительные JSON значения больше не могут исчезнуть при чтении.
Config revision, SafeMode, ServiceControl.Stopped и прежняя Stop authority
проверяются отдельно и не переопределяются сравнением исключений.

Старый и staged конфиги должны сохранить одинаковые:

- typed manual и последний accepted RU snapshot, включая выключенный RU;
- legacy Russian state и direct rules с исходными DeviceIDs;
- полный client scope, включая device/CIDR exclusions;
- соответствующие сохранённые отрицания в desired, applied и историческом
  consent policy image.

Сравнение active effective digest не заменяет сохранённый RU document:
выключенный источник остаётся в конфиге. Миграция не является способом
отредактировать исключения или область клиентов.

Когда текущий конфиг равен sealed старому образу, сравниваются его реальные
bytes и sealed staged bytes. После установки candidate прежний образ читается
из точного retained six-file journal. Новый readonly API:

```go
(*selfupdatejournal.Store).ReviewedConfigImages(
    ctx, id, files, oldBinarySHA256, oldInitSHA256, oldConfigSHA256,
) (old, candidate []byte, err error)
```

Он возвращает ограниченные копии конфигурации (до 4 MiB), проверяет точный
six-file review и retained images до/после чтения, сверяет оба config digest.
API ничего не восстанавливает, не принимает runtime и не выдаёт grant.
Adapter выполняет эту проверку из прежней AuthorityAction перед admission.

Третий текущий config image по-прежнему вызывает отказ **до эффекта**. Новая
manual запись после review остаётся нетронутой; автоматического merge,
отката config revision или восстановления поверх последнего редактирования
нет. Неопределённое восстановление сохраняет pending/recovery fence.

## Отрицательный forward guard

`start/live` дополнительно отказывает на historical `all_except` в desired
или applied policy. Такой образ остаётся строго читаемым для анализа и
data-only rollback, но не разрешает запуск панели/пробу/acceptance.

Если последние сохранённые отрицания или client scope расходятся с applied
image, `start/live` тоже отказывает. Например, новая manual exclusion при
старом AppliedNetworkPolicy не позволяет запустить rollback panel по старому
applied image. Данные не исправляются автоматически. Stop-owned и
data-only rollback сохраняют прежнюю отдельную authority.

Форматы file review и journal, reader versions, производственная capability,
durable Stop epoch и отсутствие Resume API не изменены. Config restore не
перезаписывает независимый control root.

## Проверки

Windows: новые focused `TestFileConfigExclusions` PASS 1.611 s; финальные
полные updatecheck PASS 25.673 s и selfupdatejournal PASS 10.168 s.
Связанные App `TestSelfUpdate` PASS 11.175 s; main self-update/configured
tests PASS 1.131 s. Vet updatecheck/selfupdatejournal и diff check — код 0.

Linux amd64/arm64: vet и cross-compilation полных test binaries обоих
изменённых пакетов — код 0. Артефакты в `.review-local/`:
`selfupdate-exclusions-linux-{amd64,arm64}.test` и
`selfupdate-exclusions-journal-linux-{amd64,arm64}.test`.
OPS не исполнял Linux, race, VM, router или native commands.

Модели проверяют валидный staged config с потерянным manual, disabled RU,
изменённой RU revision, device/CIDR exclusions, scoped direct и applied
отрицаниями; отказ до begin и отсутствие скрытого merge. Реальный six-file
journal проверен после installation, при новой третьей config image и при
повреждённом prior snapshot. Дополнительно проверены строгий reader,
format-only migration, historical full intent и новое unapplied отрицание.

Root может выполнить Linux race этих моделей и прежние actual persistent
crash-recovery/live-probe fixtures. Предыдущие native результаты не объявляются
приёмкой новой порции.

## Оставшийся owner hook

Совпадение config images не доказывает, что фактический восстановленный plan,
DNS targets или COMMON/NFQ rules учитывают текущие исключения. Для этого нужны
SAME actual CORE Store, исходный operation/control owner и independent
DEFAULT/NET plan proof перед запуском/acceptance. Текущий adapter constructor
получает Stop/effect/runtimeInactive; separate worker не получает actual Store
или positive resource targets. Минимальный hook согласуется с CORE/DEFAULT.

`WithResourceExclusionObservation` удерживает Store RLock: callback не должен
повторно обращаться к Store/App gate. Whole Start/Transfer/Accept protocol
под этим lock не оборачивается; detached set, hash или match=false не являются
разрешением. Actual restored-route compatibility остаётся OPEN.

CORE follow-up с `inactive_resource_exclusions` ещё не входит в dependency
5446. Reader этой порции строго откажет на неизвестном поле, сохранив bytes.
После finished pin требуется добавить typed preservation этой единственной
inactive записи; обход strict reader или молчаливое удаление запрещены.
