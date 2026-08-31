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
- Следующий блок PR-1.1: отдельные Cloudflare backup export/preview/restore
  API и UI, digest review, атомарное добавление без замены ключей, общий
  незапирающий лимит для шести HTTP-операций архивов. См.
  [перенос копий](CLOUDFLARE_COPY_BACKUP_RU.md). Это не общий restore роутера.

В этой работе не было push/release и изменений роутера. Стабильный релиз —
`v0.18.0`, опубликованный предварительный — `v0.18.1-rc.1`. Его успешный Linux CI
не следует выдавать за проверку новых локальных commits.

## Финальные локальные проверки

После правок блока архивов прошли полный `go test ./... -timeout=90s`,
`go vet ./...`, синтаксис `app.js`/`cloudflare-accounts.js`/`cloudflare-backups.js`,
`test-probe-ui.mjs`/`test-cloudflare-ui.mjs`/`test-cloudflare-backup-ui.mjs`
и сборка всех Go-пакетов для Linux
arm64/mips/mipsle; также скомпилированы App tests для трёх архитектур.
Fuzz импорта (79 409 запусков), provider tests для трёх архитектур и dataplane
tests для ARM64 проверялись в предыдущих блоках, не повторялись в этой итерации.
Linux-бинарники локально не выполнялись. Файлы сборок
лежат в игнорируемом `.tmp/truth-safety`, это не опубликованный install bundle.
Новый раздел архивов проверен в браузере на изолированном loopback-стенде с
вымышленным профилем: archive preview → restore → list, скачивание нового
архива и повторный preview с результатом «уже сохранено: 1», ширина 390 px.
Стенд остановлен, тестовая вкладка закрыта. Это не визуальный аудит всех
вкладок и не HIL. Тестовый скачанный JSON содержит только синтетические данные.
Не объявлять новую сборку аппаратно стабильной.

## Продолжать отсюда

1. Перечитать CURRENT_STATUS и отчёты PR-0.3/0.4/Cloudflare foundation, проверить
   `git status` и актуальный log. Не повторять уже завершённые изменения.
2. Довести PR-1.1: lifecycle ownership, явная миграция с сохранением исходных
   файлов, интеграция общего backup/recovery. Типизированные адаптеры,
   внутренний backup/restore, аутентифицированные passive preview/import/list
   и отдельный encrypted archive API/UI готовы. Общий лимит HTTP-операций
   архивов реализован; неизвестный writer lock не удалять без доказанного
   владельца. Общая транзакция router+provider restore остаётся отдельной задачей.
3. PR-1.2 делать сначала с локальными ключами и mock API. Не включать регистрацию,
   новый DNS, proxy feeds или расширенную автоматику без соответствующих gates.
4. Перед следующей крупной публикацией — полный Linux CI/race, Entware shell
   regression и аппаратный baseline. Отдельно проверить реальные процессы
   Sing-box/Xray после исправления ID; успешный запуск не равен работающему узлу.
5. Source review пока показывает число записей относительно прошлой загрузки,
   не полный diff применённых адресов. Conditional GET/jitter/signatures остаются.

Все операции с private input должны сохранять redaction и bounded parsing.
Подписки и публичные proxy-источники не подключать автоматически.
