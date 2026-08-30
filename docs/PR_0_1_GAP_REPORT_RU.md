# PR-0.1: version и documentation truth

Проверенная база: `8fa1d61914cb7fcfb354259408e18ce1dc72e354` (`v0.18.0`).

## Найденные разрывы

| Разрыв | Файл до исправления | Проверка |
|---|---|---|
| Dev-сборка называлась `0.17.0-dev` | `build.sh`, `.github/workflows/ci.yml` | consistency test + build |
| Source Hub отправлял `RAZVILKA/0.2.0` | `internal/sources/sources.go` | unit/static consistency test |
| UI fallback и cache key оставались на опубликованной версии | `cmd/razvilka/web/index.html` | embedded layout test |
| Старые gap-документы выглядели актуальными | `docs/MASTER_PLAN_RU.md`, `docs/PRODUCT_GAPS_RU.md`, `docs/ARCHITECTURE_GAP_2026-08-28.md` | текущий status/roadmap и архивные пометки |
| Не было одной матрицы implemented/CI/router/experimental | отсутствовал `docs/CURRENT_STATUS_RU.md` | Markdown link test |
| Release не сверял tag с версией исходников | `.github/workflows/release.yml` | workflow guard |

## Scope

- канонический `VERSION` для текущего dev-цикла;
- version/commit/time/dirty metadata в сборке и понятное отображение в UI;
- актуальный status и перенумерованный roadmap;
- автоматическая проверка согласованности версии и локальных ссылок;
- проверка release tag против канонической версии.

## Non-goals

- не менять dataplane, NFQWS2, firewall, DNS, TUN и маршруты;
- не расширять Автопилот;
- не подключать Cloudflare API или public proxy feeds;
- не заявлять новые платформы поддерживаемыми.

## Rollback

Изменения не затрагивают состояние роутера. Откат выполняется обычным revert
этого набора файлов; установленный `v0.18.0` и его конфигурация не изменяются.

## Обязательные проверки

- `gofmt`;
- `go test ./...` и race в CI;
- `go vet ./...`;
- JavaScript syntax;
- shell syntax;
- version consistency;
- локальные ссылки текущей документации;
- cross-build и существующий Entware transaction test.
