# Очистка GitHub после 0.20.0 — локальный список для review

Это предложение, не выполненная очистка. GitHub inventory не запрашивался и
удаления не выполнялись. Перед действием координатор получает свежий список
releases/assets, сохраняет имена, SHA-256 и необходимые notes. Локальные теги
не доказывают, что соответствующий release существует на GitHub.

Кандидаты на удаление публичных тестовых сборок после принятой чистой установки,
часовой проверки и выпуска нового verified Latest:

- Releases/assets старых `*-rc.*`, DEV и временных higher test versions,
  не представляющих действующий стабильный релиз. Точные имена — из свежего
  inventory, не из предположений. Не удалять ещё нужный future-update fixture.
- Старые binary/archive/checksum assets версий до 0.20.0, если они больше не
  используются поддержанными инструкциями. В локальных тегах есть ряд
  `v0.18.*` и `v0.19.0`–`v0.19.3`; их наличие не подтверждает удалённые assets.
- Прежний Latest убирать последним, после проверки опубликованных 0.20.0
  manifest/checksums, download links и bootstrap. Не заменять содержимое
  уже опубликованного тега другими байтами.

Документы, которым нужен исторический статус/перенос из пользовательской навигации,
а не безусловное удаление:

- `docs/archive/` и старые candidate/install/rollback инструкции: оставить явно
  историческими; новые README ведут на `docs/INSTALL_RU.md`.
- `docs/delivery-2026-10-03/`, `docs/research-hardening-2026-09-30/`: приёмочные
  журналы, handoffs и исследования сохранять в истории/архиве, убрать из quick start.
- `docs/INTERFACE_R3_RU.md`, старые Cloudflare candidate/scan/local-migration
  отчёты и `docs/AUTONOMY_A1_RU.md`: проверить актуальность перед переносом;
  не выдавать старый этап за текущую инструкцию или текущий PASS.
- `docs/CURRENT_STATUS_RU.md`, `docs/RUNTIME_SUPPORT_RU.md`, CHANGELOG и release
  notes обновить фактами нового source/hash/clean/hour; не удалять ограничения.

Сохранить Git commits/tags, лицензии и attribution, SECURITY, meaningful regression
и защитные ownership/journal/rollback тесты. Не включать в GitHub cleanup router
backups, secrets, private evidence и работающие компоненты Entware.

README сохраняет существующий branding banner. Новые UI-снимки добавляет
координатор после clean и обезличивания. Telegram подтверждён исходниками:
`https://t.me/RAZVILKA_UI`. Владелец предоставил точную ссылку поддержки
`https://dalink.to/artixsx`; она включена в README/RU/EN. Реквизиты не придумывались.
