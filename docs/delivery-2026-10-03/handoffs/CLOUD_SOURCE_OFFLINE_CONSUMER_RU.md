# CLOUD → CORE/UI: read-only offline consumer

04.10.2026. Dedicated `internal/app/source_offline.go` и `source_offline_test.go` переданы CLOUD координатором и CORE. Работа начата на CLOUD `a05320c51cbd25b2b877505d66fb48ff5793be76`; перед итоговой проверкой собственный worktree fast-forward до принятой root integration `2c180f9d23de5656dd399a886f558fea1d6d024b`, включая CORE engineconfig isolation `51b91f7e8e89fe5133bf5336f8de9230d96879c8`. Shared WIP не использован.

## Согласованная регистрация CORE

CORE подтвердил exact `GET /api/v1/sources/offline` → `(*App).sourceOfflineCatalog`. Единственная требуемая регистрация в существующем `App.Handler`:

```go
mux.HandleFunc(sourceOfflineCatalogPath, a.sourceOfflineCatalog)
```

`sourceOfflineCatalogPath` — private constant в новом файле. Добавить рядом с existing source routes, до `/api/v1/sources/` для читаемости. Exact ServeMux match отделяет handler от existing `sourceAction` subtree; `/api/v1/sources` и его array response не изменяются. Регистрация принадлежит CORE и в CLOUD commit **не выполнена**.

Handler проходит прежние security/operation middleware; нового auth flow, public API exemption, recovery/admission bypass нет. Сохраняется обычная политика Security.Middleware, включая прежнее поведение diagnostic reads до first-run setup. Для configured account anonymous/logout GET получает 401. Handler сам задаёт `Cache-Control: no-store`, JSON content type и для non-GET `405` + `Allow: GET`. Ошибки, возникающие в outer middleware до handler, сохраняют общий middleware contract.

## Минимальный DTO

```json
{"offline":true,"read_only":true,"sources":[]}
```

`sourceOfflineCatalogView` использует существующий `[]sources.State` для rows; новой persistence schema нет. Nil Sources возвращает non-null пустой массив с теми же view flags. При наличии manager единственный вызов — `Sources.OfflineCatalog()`; данные копируются из памяти. URL/query/body запроса не выбирают источник, не запускают Refresh и не задают сроки.

| Поля row | Значение для consumer |
| --- | --- |
| offline, ready | Всегда true/false в этой view. Это presentation, а не online proof или grant. |
| id, name, kind, description, url | Существующая source identity и redacted public origin; стандартное HTML escaping. |
| entries, sha256, provenance, diff | Сохранённые metadata. Body списка/секретные URL/токены не добавлены. |
| updated_at, expires_at | Исходные даты загрузки и окончания локального TTL; GET их не обновляет. Zero/invalid dates отображлять как «—». |
| enabled, applied_enabled, dirty | Сохранённые draft/applied facts, не permission на запись и не готовность маршрута. |
| legacy_cache, last_error, last_known_good, cache_status | Показывать совместно. При сохранённом Ready=true библиотека меняет cache_status на offline-cache и ставит LKG, но оставляет legacy_cache/last_error. Нельзя трактовать offline-cache отдельно как проверенную свежую копию. |

Offline read не меняет manager List/AutomaticUseReady, applied policy, settings или files. Новые планы по-прежнему проверяют действующие library TTL/provenance gates; DTO не используется как источник admission.

## Конкретный запрос UI

Добавить в существующую таблицу источников явную view «Сохранённые копии» с GET указанного route. Banner: **«Сохранённые данные. Сейчас источники не обновлялись.»** Возврат к обычной view делает обычный GET; открытие/переключение/вход не запускают POST refresh. Отдельного source hub, browser persistence или Internet-availability probe не требуется.

В offline view source toggle, refresh, draft apply/discard неактивны. Сохранённый выбор и dirty можно показать текстом; вход в эту view не сохраняет и не сбрасывает draft. Поздний ответ прежней view после переключения/logout не должен вернуть write controls или прежний green counter. 401/403 — ошибка входа/прав, а не успешный offline fallback.

| Состояние | Человеческая подпись и уровень |
| --- | --- |
| reference | «Справочный источник», нейтрально. |
| stale | «Срок копии истёк», предупреждение; сохранить дату и записи. |
| quarantined | «Копия не подтверждена», предупреждение. |
| legacy_cache | «Источник требует сверки», предупреждение независимо ready; при stale оставить обе причины. |
| last_error + сохранённый LKG | «Последнее обновление отклонено · сохранена прежняя копия», предупреждение. |
| offline-cache без предыдущих ограничений | «Сохранённая копия», нейтрально. |
| missing cache | «Сохранённой копии нет», нейтрально. |

Для disabled/draft source отдельно показать «Сохранённый выбор: выключен/включён» и applied факт; не скрывать срок/legacy/rejected reason за disabled label. `updated_at` подписать «Загружено», `expires_at` — «Срок локальной копии». Сохранённый TTL не подтверждает дату публикации upstream, доступность сервиса или runtime. Overview показывает число сохранённых копий/справочных источников, не «готовы», PASS или «актуален». UI files CLOUD не изменяет; координатор передаёт этот запрос действующему UI owner.

## Проверка и остающаяся приёмка

CLOUD targeted handler tests проверяют fresh/stale/legacy/LKG/quarantined/missing/reference, неизменные files/modes/mtime/settings/provenance/dates и manager readiness после повторных GET. Source HTTP client после подготовки fixture запрещает любой fetch. Existing sourceList response, nil array, non-GET rejection и configured-account auth/logout проверяются отдельно.

Route-specificity/auth fixture регистрирует handler в локальном ServeMux и использует тот же securityHeaders/audit/security/operation chain. Это **не проверка production App.Handler registration**: её после CORE wiring должен отдельно подтвердить root. Handler не меняет app.go/security/operation/UI files.

Фактические CLOUD проверки на integration базе выше, Go 1.26.5 с GOTOOLCHAIN=local/GOMAXPROCS=2/GOFLAGS=-p=2/GOPROXY=off и пустыми CLOUD native flags:

- `go test -count=1 ./internal/app -run '^TestSourceOfflineCatalog|^TestSourceDraftAPIIsIndependentAndVisibleInStatus$|^TestStatusCountsOnlyEnabledDownloadableSourcesAsReadinessGate$'`: RC 0, 1.481s.
- `go vet ./internal/app`: RC 0.
- Linux amd64/arm64 `go build ./internal/app`: оба RC 0; binaries не исполнялись.
- Formatting/diff checks: RC 0.

DTO и конкретный UI request направлены действующему UI owner `01a10215-f0ef-7233-a69e-66636ec2beec`; выполнение и UI acceptance этой CLOUD порцией не заявлены.

Actual consumer gate после регистрации: через настоящий `App.Handler` authenticated GET отдаёт exact DTO и no-store; existing sourceList остаётся array; unauth/logout отказ; GET не обращается к fetch и не обновляет cache/expiry/settings. UI gate: все labels выше, empty/invalid dates, отсутствие POST при view/login, неактивные controls и stale response/logout suppression. Только после обеих проверок можно принять offline consumer D13. D13 не закрывается библиотечным PASS; actual USQUE/lifecycle/root live отдельно, ledger **UNVERIFIED**.
