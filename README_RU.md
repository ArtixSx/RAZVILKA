# RAZVILKA

![RAZVILKA — сервис-ориентированный центр маршрутизации](docs/assets/razvilka-banner.png)

[![CI](https://github.com/ArtixSx/RAZVILKA/actions/workflows/ci.yml/badge.svg)](https://github.com/ArtixSx/RAZVILKA/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ArtixSx/RAZVILKA?include_prereleases)](https://github.com/ArtixSx/RAZVILKA/releases)
[![License](https://img.shields.io/github/license/ArtixSx/RAZVILKA)](LICENSE)

💬 [Telegram проекта — новости, тестовые сборки и поддержка](https://t.me/RAZVILKA_UI)

**Универсальный multi-engine routing hub для Keenetic / Netcraze + Entware.**

RAZVILKA объединяет разные способы маршрутизации и обхода ограничений в одном локальном Web UI: NFQWS2, usque/MASQUE, WARP WireGuard, sing-box, Xray, AmneziaWG и будущие адаптеры.

Главная идея — пользователь выбирает **сервис** (например YouTube, Discord или ChatGPT), а RAZVILKA отделяет этот выбор от конкретного **обхода**, проверяет доступные пути и в дальнейшем сможет автоматически выбирать рабочий маршрут на основе реальных проверок.

> Текущий статус: **v0.0.9-ui-layout / Safe Mode**. Изменяющие запросы защищены локальным токеном администратора; активные изменения firewall/DNS/policy routing пока заблокированы. Config Center, черновики, валидация, диагностика и текущие HTTP-пробы работают.

## v0.0.9 — исправление компоновки

- Полноэкранные панели теперь занимают высоту по содержимому, а не резервируют почти весь экран.
- Заголовки разделов больше не смещаются вниз и не перекрывают первые строки данных внутри панелей.
- CSS и JavaScript получили ключ версии в URL, чтобы после обновления роутера браузер не использовал старый интерфейс из кеша.

## Security Gate

- При первом запуске создаётся случайный 256-битный токен `/opt/etc/razvilka/admin.token` с правами `0600`.
- POST/PUT/PATCH/DELETE требуют Bearer-токен, `application/json` и совпадающий `Origin` браузера.
- Web UI запрашивает токен при первом изменении и хранит его только в `sessionStorage` текущей вкладки.
- Read-only API остаётся доступным в LAN, чтобы панель могла загрузиться до входа.
- Секретные конфиги по-прежнему redacted: приватные ключи и credentials в браузер не выдаются.

## Основные принципы

- Service-first UI: сервисы отдельно, обходы отдельно.
- Desired / Planned / Applied / Observed состояния не смешиваются.
- Никаких выдуманных результатов тестов или соединений.
- Проверка конфига до применения.
- Атомарное применение и транзакционный rollback.
- LAN-only интерфейс по умолчанию.
- Секреты не должны попадать в браузер или GitHub.
- Каждый обход подключается через отдельный адаптер.
- Уже существующие маршруты через внешние туннели учитываются как возможное искажение CURRENT-тестов.

## Проверка проекта

```sh
./scripts/check.sh
```

Проверяются Go tests, race detector, vet, shell/JavaScript syntax, сборки для amd64, arm64, mips и mipsle и полный цикл Entware apply/rollback; исходники при проверке не переписываются.

## Лабораторная установка Entware

В исходном checkout с GitHub скомпилированные бинарники не хранятся. Сначала собери их:

```sh
./build.sh
./scripts/lab-bootstrap.sh
```

GitHub Releases будут собирать и публиковать бинарники автоматически. Bootstrap устанавливает только Manager в Safe Mode и выполняет preflight до и после установки. Обходы автоматически не активируются.

## Безопасное обновление существующей установки

По умолчанию обновление выполняет только dry-run. Если на роутере работает ARTEM Flow, миграция требует отдельного флага и сначала проверяет старую конфигурацию без записи:

```sh
./scripts/upgrade-entware.sh --dry-run --from-artem-flow
./scripts/upgrade-entware.sh --apply --from-artem-flow
```

Перед записью проверяются архитектура, SHA256 (если присутствует `dist/SHA256SUMS`), бинарник, схема конфигурации, каталог сервисов и реестр источников. Apply создаёт root-only snapshot, атомарно устанавливает файлы, мигрирует конфигурацию, запускает init и автоматически откатывается, если точный health-check новой версии не прошёл.

Текущий snapshot для ручного отката:

```sh
./scripts/rollback-entware.sh "$(cat /opt/var/lib/razvilka/current-backup)"
```
`uninstall-entware.sh` автоматически использует тот же snapshot. После миграции с ARTEM Flow он восстанавливает старый бинарник, init и running-state, а не оставляет прежний сервис отключённым.


Управление сервисом:

```sh
/opt/etc/init.d/S99razvilka status
/opt/etc/init.d/S99razvilka restart
/opt/etc/init.d/S99razvilka guard-status
/opt/etc/init.d/S99razvilka clear-guard
```

После трёх неудачных стартов за пять минут boot-guard блокирует дальнейший автозапуск до диагностики и явного `clear-guard`. Health-check имеет таймаут и принимает только ответ с точными именем `RAZVILKA`, версией и PID процесса из pidfile.

Подробности: [README.md](README.md), [LAB.md](LAB.md), [план миграции v0.0.8](docs/V0.0.8_DEPLOYMENT_RU.md), [Roadmap](docs/ROADMAP.md).
