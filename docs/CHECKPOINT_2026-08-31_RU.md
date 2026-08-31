# Точка продолжения — 31 августа 2026

## Сохранено локально

- `7d9e6b1`: PR-0.3 — исправление ошибочного запрета `x`/`0` в ID процессов
  Sing-box/Xray, bounded diagnostics, loopback-порты, anchored cleanup.
- `e5af107`: PR-0.4 — HTTPS/SSRF boundary, source schema 2, TTL, provenance,
  LKG, quarantine, сводка diff и запрет изменения scope автопилотом. В том же
  блоке ограничены endpoints/metrics/logs импортированных proxy-canary.
- `614ceae`: общий бюджет community include, ранний entry limit, отказ от HTML
  и частичного parsing, redaction ошибок чтения, лимит HTTPS-заголовков.
- `0298a0b`: пассивная основа PR-1.1 — Cloudflare Provider model/import/store.
  Полная интеграция PR-1.1 не завершена; см. отдельный отчёт.
- `2a5f57e`: продолжение PR-1.1 — типизированные адаптеры USQUE/wgcf,
  синтетические fixtures, зашифрованный backup и атомарное объединение копий.
  Общий импорт явно отклоняет Provider-архивы до интеграции полной транзакции.
  Подробности: [legacy imports](CLOUDFLARE_LEGACY_IMPORT_RU.md).
- `6aed8ef`: закрытые preview/import/list API Cloudflare и свёрнутый раздел
  копий в «Настройки». Изолированное хранилище рядом с выбранным config,
  ограничение запросов, очистка приватного кандидата в UI. Это не активация
  обхода и не подключение общего backup — [отчёт](CLOUDFLARE_COPY_UI_RU.md).
- `df174c8`: отдельные Cloudflare backup export/preview/restore
  API и UI, digest review, атомарное добавление без замены ключей, общий
  незапирающий лимит для шести HTTP-операций архивов. См.
  [перенос копий](CLOUDFLARE_COPY_BACKUP_RU.md). Это не общий restore роутера.
- `2ed5dba`: [явное copy-only копирование с роутера](CLOUDFLARE_LOCAL_MIGRATION_RU.md),
  неизменяемый allowlist источников, digest review, bounded anchored read,
  Linux nonblocking/no-follow open и UI. Исходники/runtime не переходят во владение.
- `8091e1e`: [восстановление writer после сбоя процесса](CLOUDFLARE_WRITER_RECOVERY_RU.md).
  Постоянный протокольный маркер и системная блокировка Linux/Windows;
  старые/неизвестные lock не меняются. Настройки и runtime не затронуты.
- `fc123d1`: [защищённый откат приватного импорта](PRIVATE_BACKUP_GUARDED_RESTORE_RU.md).
  Снимки до/после под блокировками хранилищ, отказ затирать последующие правки,
  обработка ошибок возврата файлов и понятный результат в UI. Это prerequisite,
  не общий router+provider restore и не durable recovery.
- `c4eda04`: [основа журнала восстановления](PRIVATE_RESTORE_JOURNAL_RU.md).
  Снимки before/after, commit decision, bounded canonical journal, OS lease,
  повторный откат после аварии и защита третьего состояния. Реальные target
  adapters/App/startup ещё не подключены; рабочий импорт не изменился.
- `fca9f17`: [config recovery adapter](CONFIG_RESTORE_ADAPTER_RU.md).
  FileTarget с per-file OS lease/durable CAS, обычные config writers и migration
  на том же протоколе, bounded read, stale-cache guard и uncertain-write fence.
  Typed target/session согласует файл и кэш. App/startup recovery ещё не подключены.
- `deef425`: [catalog/devices recovery adapters](REGISTRY_RESTORE_ADAPTERS_RU.md).
  Обычные writers/undo/discovery на том же per-file OS lease/CAS, typed targets/
  sessions и общий crash test config+catalog+devices. UI сообщает о несохранённом
  discovery. Полный HTTP/startup restore ещё не включён; staging/provider остаются.
- Следующий локальный блок: [engine staging recovery](ENGINE_DRAFT_RESTORE_RU.md).
  Все staging writers используют slot leases/CAS, batch откатывает также failed
  target после возможного rename; StagePrivateWithRollback даёт guarded undo
  следующей фазе. Typed target/session допускает absent/empty/incomplete before
  images. Provider только исследован: общая .import.lock и несовпадение лимитов
  16 МиБ store / 4 МиБ Image / 8 МиБ plan требуют отдельного адаптера.

В этой работе не было push/release и изменений роутера. Стабильный релиз —
`v0.18.0`, опубликованный предварительный — `v0.18.1-rc.1`. Его успешный Linux CI
не следует выдавать за проверку новых локальных commits.

## Финальные локальные проверки

В блоке staging прошли полный `go test ./... -count=1 -timeout=90s`,
`go vet ./...`, синтаксис app.js и шесть JS suites. Engineconfig tests прошли
десять повторов, включая реальные дочерние процессы с завершением после prepare,
каждого target write, rollback и commit. Новая App regression проверяет undo
успешного staging после последующей ошибки. Все пакеты и engineconfig/App tests
собраны для Linux arm64/mips/mipsle, не выполнены. Linux-only FIFO/symlink/mode
tests только скомпилированы. Linux/race, shell/HIL/power-loss и browser visual QA
не выполнялись; зависимости не менялись.

В блоке catalog/devices adapters прошли полный `go test ./... -count=1 -timeout=90s`,
`go vet ./...`, синтаксис app.js и шесть JS suites. Catalog/devices tests
прошли 10 повторов, App registry recovery/API tests — три. Реальные дочерние
процессы остановлены после prepare, каждой из трёх записей, во время rollback
и после commit. Восстановление проверено до Load; внешний неизвестный файл
блокирует весь откат без перезаписи остальных. Сохранность live/gate полей,
discovery metadata, отказ stale writers, uncertainty fence и предупреждение
API/UI проверены. Все Go-пакеты и customservices/devices/App tests собраны для
Linux arm64/mips/mipsle, не выполнены. Linux/race, Entware shell, HIL,
power-loss и browser visual QA не выполнялись; dependencies не изменены.

В блоке config adapter прошли полный `go test ./... -count=1 -timeout=90s`,
`go vet ./...`, синтаксис app.js и пять JS suites. Config/restorejournal прошли
10 повторов, включая настоящие дочерние процессы с завершением после prepare,
записи config, во время rollback и после полного commit. Другой процесс не смог
писать во время сессии. Восстановление выполнено до загрузки кэша Store.
Go-пакеты и config/restorejournal/App tests собраны для Linux arm64/mips/mipsle,
не выполнены. Новые Linux-only file target FIFO/symlink/permissions tests также
только скомпилированы. Linux/race, Entware shell, роутер, power-loss и browser
visual QA не выполнялись; dependencies не изменены.

В блоке restore journal прошли полный `go test ./... -count=1 -timeout=90s`,
`go vet ./...` и пять JS suites. Пакет restorejournal прошёл 10 повторов на
Windows, включая настоящие дочерние процессы с принудительным завершением
после prepare, каждой целевой записи, commit/idle и каждого шага rollback.
Собраны пакеты и restorejournal/ownedfs/cloudflareprovider/App test binaries
для Linux arm64/mips/mipsle. Они не выполнялись; Linux-only FIFO/symlink/POSIX
tests только скомпилированы. Роутер, power-loss, Linux/race, shell regression
и браузер в этом блоке не проверялись. Runtime панели и dependencies не менялись.

В блоке guarded restore прошли полный `go test ./... -count=1 -timeout=90s`,
`go vet ./...`, синтаксис `app.js` и пять JS regression suites. Целевые тесты
компенсаций/конкурирующих правок/ошибок записи прошли пять повторов. Собраны все
Go-пакеты и App/config/customservices/devices/engineconfig test binaries для
Linux arm64/mips/mipsle, но не выполнены. Реальный зашифрованный HTTP-импорт
проверен в изолированном временном каталоге с отказом staging. Браузерная
визуальная проверка, Linux/race, shell regression, роутер и power-loss в этом
блоке не выполнялись. Dependencies не менялись.

В блоке writer recovery прошли полный `go test ./... -count=1 -timeout=90s`,
`go vet ./...` и четыре JS regression suites. Новые `TestWriter*` прошли
20 повторов на Windows: восемь конкурирующих Store, реальные дочерние процессы
с принудительным завершением до/после commit, отсутствие потери/дублирования
копий, сохранность неизвестного lock. После добавления concurrent test повторены
writer tests, vet и полный `go test -mod=readonly ./...`; `go mod verify` прошёл.
Linux arm64/mips/mipsle: собраны все пакеты
и provider test binaries с новым FIFO test, но не выполнены.
POSIX-права и symlink-тест на Windows пропущены. Полный Linux/race,
Entware shell regression, HIL и отключение питания не выполнялись.
Дополнительный `go mod tidy -diff` предложил нормализацию `x/net` и
зависимостей тестов YAML (`kr/text` и checksums); она не применялась в этом
блоке. `go.sum` не изменён; `x/sys` той же зафиксированной версии только
перенесён из indirect в direct для Windows lock adapter. Это отдельная
проверка модульного графа, не результат выполнения Linux-тестов.

В предыдущем блоке миграции прошли полный `go test ./... -timeout=90s`,
`go vet ./...`, синтаксис `app.js`/`cloudflare-accounts.js`/`cloudflare-backups.js`,
`test-probe-ui.mjs`/`test-cloudflare-ui.mjs`/`test-cloudflare-backup-ui.mjs`
а также syntax/test для `cloudflare-migration.js` и сборка всех Go-пакетов для
Linux arm64/mips/mipsle. Provider tests, включая Linux-only FIFO test,
скомпилированы для трёх архитектур; App tests cross-build — в предыдущем блоке.
Fuzz импорта (79 409 запусков), provider tests для трёх архитектур и dataplane
tests для ARM64 проверялись в предыдущих блоках, не повторялись в этой итерации.
Linux-бинарники локально не выполнялись. Файлы сборок
лежат в игнорируемом `.tmp/truth-safety`, это не опубликованный install bundle.
Раздел миграции ранее проверен в браузере на изолированном loopback-стенде с
вымышленным профилем: preview → copy → list, отсутствующий источник, ширина
390 px. SHA-256 исходника не изменился. Сценарий архива проверялся предыдущим
блоком; не повторялся здесь. Стенд остановлен, тестовая вкладка закрыта и размер
окна возвращён. В блоке writer UI не менялся и браузер не открывался.
Это не визуальный аудит всех вкладок и не HIL.
Не объявлять новую сборку аппаратно стабильной.

## Продолжать отсюда

1. Перечитать CURRENT_STATUS и отчёты PR-0.3/0.4/Cloudflare foundation, проверить
   `git status` и актуальный log. Не повторять уже завершённые изменения.
2. Довести PR-1.1: общая транзакция router+provider backup/recovery,
   secret access contract и lifecycle ownership. Recovery writer нового
   протокола и явная copy-only миграция добавлены локально. Типизированные адаптеры,
   внутренний backup/restore, аутентифицированные passive preview/import/list
   и отдельный encrypted archive API/UI готовы. Общий лимит HTTP-операций
   архивов реализован; неизвестный, старый пустой или частично созданный writer
   lock не удалять автоматически. Не подменять реальный power-loss gate тестом
   завершения процесса; безопасный учёт временных файлов ещё не реализован.
   Общий приватный импорт теперь имеет guarded компенсацию в процессе,
   но не межпроцессный guard и не подключённый журнал. Основа журнала готова
   отдельно (`internal/restorejournal`); теперь есть production FileTarget
   и config/customservices/devices.OpenRestoreTarget + restore sessions.
   Их обычные writers, включая discovery и undo, используют ту же per-file
   lease/CAS, но App/main общий журнал ещё не вызывают.
   Engine staging target/session и ordinary slot writers тоже готовы; есть
   post-success guarded undo, поэтому staging больше не обязательно последняя
   компенсируемая фаза. Следующий шаг — provider adapter на его же .import.lock:
   читать bounded, сравнивать bytes, синхронизировать каталог, заранее проверять
   лимиты общего журнала (см. ENGINE_DRAFT_RESTORE_RU). Затем
   владение/исключение параллельных мутаций всех API/background/processes,
   подключение startup recovery до загрузки кэшей и изменяющих API, затем общий
   router+provider restore. Запрет ProviderSnapshots сохранять.
   Публичный импорт профиля остаётся на старой компенсации, нужен отдельный аудит.
3. PR-1.2 делать сначала с локальными ключами и mock API. Не включать регистрацию,
   новый DNS, proxy feeds или расширенную автоматику без соответствующих gates.
4. Перед следующей крупной публикацией — полный Linux CI/race, Entware shell
   regression и аппаратный baseline. Отдельно проверить реальные процессы
   Sing-box/Xray после исправления ID; успешный запуск не равен работающему узлу.
5. Source review пока показывает число записей относительно прошлой загрузки,
   не полный diff применённых адресов. Conditional GET/jitter/signatures остаются.

Все операции с private input должны сохранять redaction и bounded parsing.
Подписки и публичные proxy-источники не подключать автоматически.
