# CLOUD — оставшиеся границы источников D13

04.10.2026. Worktree `C:/Projects/RAZVILKA/worktrees/sol-cloud`, branch `sol/cloud-20261004`; base `c6c6077b7146f2b54ef7713fad28cabd78f3d1d4`.

## Завершённая порция

`internal/sources/sources.go` закрывает две границы существующего Source Hub:

- `NewManager` сохраняет собственную копию Sources, Services и RedirectHosts. Изменение переданного registry, включая изменение во время HTTP запроса, больше не меняет approved URL, mirror allowlist, service scope, source hash или TTL этого manager. Новая конфигурация требует нового manager; отдельного reload API не добавлено.
- `Refresh` проверяет operation context после успешного чтения body, после нормализации списка и перед atomic commit. Уже наблюдаемая отмена не заменяет receipt, не продлевает TTL и не создаёт свежий статус. Отмена сразу после body также не создаёт cache directory или quarantine record. Atomic rename остаётся границей записи; эти проверки не являются новым app admission/Stop протоколом.

Regression fixtures проверяют отменённый успешный ответ с пустым cache и с существующим LKG; bytes, provenance, timestamps, состояние и readback после restart сохраняются. Отдельный fixture изменяет caller registry в середине redirect: исходный approved mirror остаётся допустимым, внешний новый mirror отклоняется без замены LKG, TTL остаётся один час и service scope не расширяется.

## Проверенный существующий контракт

| Требование D13 | Результат в CLOUD библиотеке |
| --- | --- |
| Approved source/mirror provenance | Schema 2 receipt содержит normalized content/digest, raw digest, source configuration hash и redacted исходный/final origin. Final origin проверяется по исходному host либо явному RedirectHosts при загрузке и restart. Signed CDN query/path не сохраняются. |
| TTL зеркала | ExpiresAt точно равен FetchedAt + local source TTL; смена конфигурации, pin, origin или сроков делает receipt непригодным. TTL 0 означает 24 часа, верхняя граница 720 часов. |
| LKG при ошибке | Rejected update оставляет предыдущие bytes и даты; quarantine metadata не заменяет receipt. Stale receipt не удаляет активную политику. |
| Stale/legacy и новые планы | EntriesForService не выдаёт expired entries; AutomaticUseReady требует schema 2 и unexpired receipt для источников, которые явно обогащают данный service. Неиспользуемый источник не блокирует другой service. |
| Offline catalogue | OfflineCatalog — detached local read без fetch/write/upgrade; ready=false, offline=true, сохранены provenance/expiry/entries и stale/legacy/quarantine labels. View не даёт права новой route mutation. |
| Unknown enrollment | Pending до POST и checkpoint key/response остаются на прежнем nativeenrollment root/lease. Pending без recoverable response не разрешает новый POST после restart/fresh; response+key восстанавливают тот же enrollment. Legacy wgcf не создаёт новый account. |

OfflineCatalog уже существует как library API. В committed app, находящемся в этой CLOUD базе, GET использует memory-only List; отдельного consumer OfflineCatalog нет. Выбор offline presentation и её UI labels — остающаяся CORE/UI интеграция, без автоматического Refresh при входе/GET. App/config/UI в этой порции не изменены.

Следующая согласованная порция — dedicated app handler/DTO: [exact registrar, DTO и UI request](CLOUD_SOURCE_OFFLINE_CONSUMER_RU.md). Регистрацию existing app.go выполняет CORE после finished checkpoint; CLOUD handler tests сами по себе не закрывают production consumer/UI gate.

## Первичные источники, проверка 04.10.2026

Существующие approved feeds не расширялись и не переподписывались. Re:filter сам публикует `domains_all.lst` и `ipsum.lst`; эти же filenames присутствуют в проверенной странице assets. [Репозиторий издателя](https://github.com/1andrevich/Re-filter-lists), [assets release 01082026](https://github.com/1andrevich/Re-filter-lists/releases/expanded_assets/01082026).

При чтении `releases/latest` resolver страницы вернул release `01082026`. Это наблюдение web read, а не durable pin или гарантия актуальности operational feed. Moving URL и локальный raw SHA уже фиксируются фактическим Refresh; stale SHA конкретного release не добавлен в bundled registry. [Проверенная release page](https://github.com/1andrevich/Re-filter-lists/releases/tag/01082026).

Официальный Telegram endpoint содержит CIDR lines IPv4 и IPv6 и соответствует существующему `telegram-cidrs`. Данные в registry не заменялись снимком веб-страницы. [Telegram CIDR](https://core.telegram.org/resources/cidr.txt).

24 часа в bundled registry — локальное окно допустимости после проверенной загрузки. Оно не равно обещанному интервалу публикации upstream, HTTP Cache-Control, DNS TTL или дате изменения самого списка. Signed redirect не продлевает это окно. Source trust tier и hash не доказывают доступность сервиса или независимость publishers. Node subscription feeds/reserve diversity относятся к D10, а reference записи RunetFreedom/v2fly/OpenAI/RKN остаются reference без list fetch.

## Фактические проверки

Go 1.26.5, GOTOOLCHAIN=local, GOMAXPROCS=2, GOFLAGS=-p=2, GOPROXY=off. Все три CLOUD native opt-in flags пусты.

- `go test -count=1 ./internal/sources`: RC 0, 0.834s.
- Полный portable `go test -count=1 ./internal/sources ./internal/warp ./internal/cloudflareprovider ./internal/usquediag`: RC 0; sources 0.856s, warp 4.412s, provider 7.821s, usquediag 0.490s. Это включает прежние enrollment checkpoint/unknown/response recovery/legacy/retention regressions с local API doubles.
- `go vet` тех же четырёх пакетов: RC 0.
- Linux amd64 и arm64 `go build ./internal/sources`: оба RC 0, без исполнения binaries.
- `git diff --check`: RC 0.

Новых незавершённых source/enrollment library требований в проверенном D13 scope не выявлено. D13 целиком не объявлен закрытым: actual USQUE consumer/lifecycle, CORE/UI offline presentation и root native/live acceptance остаются отдельными gates. Native/router/registration/system changes здесь не выполнялись. VERSION, go.mod, go.sum, bundled feeds, общий TASKS/VALIDATION и чужие ownership файлы не изменены. Live USQUE ledger остаётся **UNVERIFIED**: [checklist](CLOUD_USQUE_LIVE_CHECKLIST_RU.md).
