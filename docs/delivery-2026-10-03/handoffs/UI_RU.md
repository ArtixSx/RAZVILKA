# UI: первая порция D01 — 03.10.2026

Исполнитель: чат UI `sol/ui-20261003`, один исполнитель, без дополнительных чатов/агентов.
Worktree: `C:/Projects/RAZVILKA/worktrees/sol-ui`.
Base: `52eee92c28af1b9ad3c789f2ee2c3ffc43a0e175` (проверенный код `367ef14` и документы).
Эта порция готова к review; D01 целиком и D12 не объявляются закрытыми.

## Результат и изменённые файлы

- `cmd/razvilka/web/app.js`: один pending запрос создания администратора/входа/восстановления/временного входа; отключение повторных кнопок и полей во время операции. Клиентская generation проверяется после ответа, чтения состояния и плана: старый success/error/finally не открывает панель, не стирает новые поля и не снимает блокировку новой операции. Logout закрывает локальную панель и SSE сразу, переживает ошибку `/auth/status`, показывает честное сообщение и доступную кнопку повторного выхода при неизвестном результате. Вход показывает фактическую ошибку HTTP вместо сообщения о неверном пароле при любом сбое.
- `cmd/razvilka/web/autopilot-settings.js`, `index.html`: видимая кнопка «Обновить состояние» рядом с обычными параметрами. До исправления reconciliation unknown write было привязано только к скрытому `a1-reloadButton`; видимая верхняя кнопка не снимала fence. Теперь отдельная кнопка и верхнее обновление читают состояние, сохраняя dirty draft; ни один из этих обработчиков не повторяет PUT. После новой revision требуется явное «Отменить правки». Старый ID сохранён.
- `scripts/test-auth-actions-ui.mjs`: 15 адресных регрессий повторов, late success/error, смены сессии, post-login readback, logout/status failure и explicit retry.
- `scripts/test-autopilot-settings.mjs`: ещё 3 регрессии доступного reconciliation; всего 24.
- `scripts/test-ui-http-browser.mjs`: opt-in Windows browser runner с настоящим embedded приложением, одноразовым аккаунтом, отдельными config/catalog/runtime/state под `.review-local/ui-http-*`, портом **127.0.0.1:18851**. Отказывается использовать занятый порт. `--auth-only` не подменяет политику. `--policy-transport` явно включает синтетический transport только для policy/panel-autonomy и отмечает эту границу в результате. Без флага требуется настоящий API политики. Устанавливать Playwright/Chrome или скачивать браузер runner не пытается. Процесс сервера и браузер завершаются в finally.

Серверные permissions, app/API, recovery fence, CAS, CSRF, TLS, ownership, Stop, SafeMode и LKG не изменены. `go.mod`, `go.sum`, `VERSION`, общие скрипты CI и чужие worktrees не изменены. Никаких GitHub/роутер/VM/native/HIL действий.

## Воспроизведение дефектов до исправления

1. Настоящий исходный бинарник: повторный submit login отправляет **2 POST**; отложенный настоящий успешный ответ после нового auth lifecycle снова устанавливает `state.authenticated=true`. Runner `--auth-only` имеет RC 1; `.review-local/ui-http-0QKFod/result.json`, `ui-state.json` сохраняют результат. Новая unit-регрессия также имела RC 1 (`2 !== 1`).
2. Chromium на исходных assets, контролируемая политика: при попытке reconciliation Playwright находит `a1-reloadButton`, но он имеет `hidden`; RC 1. `.review-local/ui-http-CuI8ao` хранит состояние. Ошибки DOM/CSP не обходились, кнопка не нажималась принудительно.
3. Первый настоящий policy GET имеет **503**, ещё до тестовых перехватов; `.review-local/ui-http-RN6mdP/server.log`. Это backend-блокер ниже, а не успешный CAS тест.

## Фактически проверено в браузере

Настоящий HTTP (Go 1.26.5 Windows/amd64, системный Chrome, Playwright):

- Быстрая серия Подключения → Сервисы → Устройства → Настройки → Автопилот → Главная и повторные refresh: итоговый раздел верен, writes отсутствуют, `uiRenderIssues={}`.
- Реальный logout/revocation; защищённый GET отвечает **401**, dirty поле очищается на границе сессии.
- Повторный login submit: один настоящий POST. Доставка настоящего ответа отложена тестовым transport; после нового auth lifecycle callback не открывает панель.
- Старый GET `/services` выполняется после реального отзыва сессии и получает **настоящий 401**. После нового настоящего входа доставка старого ответа не закрывает новую сессию.
- Настоящий logout 200 с последующим подставленным 500 `/auth/status`: локальная панель остаётся inert, вход доступен, необработанного исключения нет. Это ошибка transport чтения, не backend 500.
- Чужой Origin получает **403** до выполнения действия. CSP содержит `default-src 'self'` и `frame-ancestors 'none'`.
- SHA-256 сетевого `config.json` до/после совпадает; `safe_mode=true`. Первый login/dirty navigation/focus из D00 целиком не повторялись.

Отдельный **контролируемый transport**, не доказательство backend CAS/commit:

- Политика синтетическая, disabled, maintenance windows off; bootstrap не выдаётся за настоящую настройку автопилота.
- Два submit обычной формы → один PUT и отдельный GET readback.
- 409 revision conflict сохраняет dirty поле; доступное чтение получает новую revision, reset явный.
- 500 после модельного commit блокирует повторный PUT; видимое обновление читает состояние, поля не исчезают.
- 409/500 чтения сохраняют список/сохранённое представление, не дают ready/PASS; уход в Настройки и retry не читают hidden services/engine-configs/DNS/strategy-lab.

Полный browser прогон `--policy-transport`: **9 сценариев + отдельная проверка настоящего backend 503**, RC 0, `errors=[]`, config unchanged. Локальные артефакты: `.review-local/ui-http-37qAr1`.
Чистый прогон `--auth-only`: **5 сценариев**, RC 0, `.review-local/ui-http-KrXK4t`. Только ошибка чтения статуса logout подставлена; ответы login/401/403 и assets настоящие.
Runner сохраняет счётчики HTTP по сценариям и wall time. Например, быстрые переходы в указанном полном прогоне: 17 GET, 0 writes; повторный login: 1 POST. Это число с отдельными фоновыми читателями и инструментированным transport, **не** request budget одного открытия, render-cost или скорость ARM64.

## Команды и RC

Окружение: `C:/Projects/RAZVILKA/tools/go/bin/go.exe`, **go1.26.5 windows/amd64**; bundled Node **24.19.0**. Для Go: `GOTOOLCHAIN=local`, `GOMAXPROCS=2`, `GOFLAGS=-p=2`.

| Команда | RC / граница |
|---|---|
| `go build -o .review-local/razvilka-ui-fixed.exe ./cmd/razvilka` | 0, настоящий embedded сервер |
| `go test ./cmd/razvilka -run 'Test.*(Web\|Layout\|Interface\|Autopilot)' -count=1` | 0, адресный предварительный прогон |
| `go test ./cmd/razvilka -count=1` | 0, полный пакет cmd |
| `go vet ./cmd/razvilka` | 0 |
| 77 строк `node ...` из `scripts/check.sh`, исключая `*supervision*` | 77/77, RC 0; журнал `.review-local/frontend-d01.log`; shell/package lifecycle не дублировались |
| `node scripts/test-auth-actions-ui.mjs` | 0, 15 регрессий; до исправления 1 |
| `node scripts/test-autopilot-settings.mjs` | 0, 24 регрессии |
| `node scripts/test-auth-resume-ui.mjs` | 0 |
| `node scripts/test-ui-http-browser.mjs --auth-only` | 0; на исходном бинарнике 1 |
| `node scripts/test-ui-http-browser.mjs --policy-transport` | 0; policy transport обозначен отдельно |
| `node --check cmd/razvilka/web/app.js`, `node --check scripts/test-ui-http-browser.mjs`, `git diff --check` | 0 |

Для browser команд требуется перед запуском задать:

```powershell
$env:NODE_PATH='C:/Users/Artix/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules'
$env:RAZVILKA_UI_BINARY='C:/Projects/RAZVILKA/worktrees/sol-ui/.review-local/razvilka-ui-fixed.exe'
$env:RAZVILKA_UI_CHROME='C:/Program Files/Google/Chrome/Application/chrome.exe'
& C:/Users/Artix/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe scripts/test-ui-http-browser.mjs --auth-only
```

Локальные credentials, бинарники и частные логи не включены в коммит. `.review-local/.gitignore` исключает их; дерево после коммита чистое.

## Блокер и точные запросы владельцам

**CORE (`cmd/razvilka/main.go`, при необходимости совместно с OPS для components):** `components.New()` сохраняет StateDir `/opt/var/lib/razvilka/components`. На Windows `ownedfs.Open` отклоняет такой путь как не абсолютный. `PendingManagedUpdate` возвращает ошибку, `InitializeComponentRecoveryGate` правильно сохраняет fence; `/api/v1/autonomy` получает 503, startup не может прочесть автономию. Нельзя снимать guard или исправлять `ownedfs` ради зелёного UI.

Нужен startup-контракт явного абсолютного **локального** component StateDir до инициализации recovery gate (например, отдельный flag/env), а для полностью изолированных стендов — также BinDir/InitDir/RepoDir/InfoDir. Production Linux defaults и location retained journals должны остаться совместимыми: существующий pending/corrupt journal нельзя скрыть сменой defaults. После владельческого исправления запустить runner **без** `--policy-transport` на отдельном состоянии: настоящий CAS 409 и успешный PUT/readback. Сейчас этот подэтап **unverified/blocked**, изменение файлов CORE не сделано.

**Координатор (`scripts/check.sh`, общий gate):** добавить `node scripts/test-auth-actions-ui.mjs` в штатный Node gate. Browser runner оставить opt-in; Linux/ARM64 потребует назначенного координатором изолированного process/filesystem/network окружения, Windows runner сам его не запускает.

## Unverified и следующий шаг

- Настоящий backend policy CAS/commit, backend 500 при записи, SSE-disconnect серверной реализации остаются непроверенными этой порцией. Контролируемые ответы не закрывают их.
- Общий Linux check/race/cross-build/install gate новой порции, CPU/RSS/render-cost/ARM64, native engines, реальный LAN/DNS и аппаратная матрица выполняются координатором; здесь не запускались.
- D12 card workflow/version/pending/recovery не начинался. После review этой порции можно согласовать следующую вертикаль и реальные recovery endpoints CORE.

## Вторая порция: D12 matching component recovery

Продолжение после review и fast-forward до интеграции `99ac304778f881bab24692f9d87f880d41da4d09`.
Добавлен `component-recovery-ui.js`; изменены только owned web assets, CSS bundle и UI-тесты.

- В разделах Обходы/настройка движка/Обновления показывается реальный GET `/api/v1/components/recovery`: причина, transaction, before/after versions, revision. Login и Home не запускают этот GET; переходы запускают только чтение, single-flight и auth/view epochs сохранены.
- Поддержаны существующие matching POST `accept-live`, known `rollback`, `verify-rollback` для awaiting-rollback-acceptance, `abandon-prepared`. Перед POST отдельный review и повторная проверка текущей UI revision/SafeMode/Stop; JSON содержит только exact transaction/component/expected_revision/confirm/action. Сервер остаётся единственным владельцем полномочий и live proof.
- `upgrade-started`/`rollback-started` не имеют кнопки force, operator boolean или повторной команды. Повреждённый/неизвестный журнал закрывает действия, но причина и повторное чтение доступны. Ошибки POST, включая 409 и transport 500, не повторяются; требуется явное чтение.
- `accepted` в GET само по себе не доказывает live acceptance. Положительная отметка версии допускается только после matching `accept-live` POST с `live_accepted=true` и независимого GET той же terminal transaction. Это принятие версии в момент операции, не PASS конкретного сервиса. Процесс без такого доказательства имеет нейтральный статус.
- Update с `pending_live_acceptance=true` больше не проходит через прежнюю ветку «установка проверена/готово». Показывается ожидание принятия и сохранённый LKG. Legacy IDs/URLs/API сохранены; install/update/remove закрыты, пока recovery не прочитан или pending.

Проверки: `test-component-recovery-ui.mjs` — **11/11**, `test-component-cards-ui.mjs` — RC 0 с новыми проверками process-only и pending update; `node --check component-recovery-ui.js`, `build-interface.mjs`, `git diff --check` — RC 0. `go test ./cmd/razvilka -count=1` — RC 0. Общий выбранный Node-прогон: **78/79**, единственный RC 1 — `test-native-opkg-runner.mjs`, `spawnSync sh ENOENT`; адресный повтор с `C:/Program Files/Git/bin` в PATH — **RC 0 (stubs only)**. Лог `.review-local/frontend-d12-recovery.log` сохраняет первый RC 1. Новый UI test ещё не добавлен в shared `check.sh`: это запрос координатору.

Точные контрактные запросы:

- CORE/OPS: after matching durable settlement синхронизировать operation receipt (сейчас pending update записывает `operation_status=running`, а recovery не обновляет его явно). UI не снимает это состояние самостоятельно; сообщает о расхождении terminal journal/operation mark и сохраняет запрет package actions. Это может оставить обычные кнопки disabled после успешного repair до исправления владельцем.
- OPS/CORE: для нового `accept-installed-idle` предоставить exact action, допустимые phases, response acceptance и retained receipt/GET field. Текущий UI не отправляет ещё не реализованное действие и не превращает installed-idle в live.
- CORE: желательно публиковать current Stop/SafeMode/action capabilities в recovery GET вместе с revision. Сейчас UI использует имеющийся status и известный service-control Stop; неизвестные/изменённые полномочия повторно проверяет существующий серверный guard. Нового API не выдумано.

На момент этой UI-порции native runtime/recovery и browser POST recovery не выдаются за проверенные: unit transport явно synthetic. Принятый координатором path fix `0a3a25b3859658d4686ca200df85c079e894a796` будет объединён следующим шагом для настоящего policy HTTP/PUT/CAS без `--policy-transport`. Self-update wiring, полный card workflow, массовые подключения/AI и удаление legacy-дублей остаются дальнейшими D12 шагами.

## Review-поправки и настоящий HTTP после path fix

UI recovery commit: `2ba264e`. Принятый CORE path fix `0a3a25b3859658d4686ca200df85c079e894a796` объединён обычным merge `b5160d1`; чужие файлы вручную не изменялись.

- После 60 секунд ранее нарисованная кнопка больше не завершает обработку молча: показывает устаревание, делает только GET и просит просмотреть журнал и выбрать действие заново. Автоматического POST после чтения нет.
- Уход с раздела во время review отменяет ещё не отправленный POST. Если POST уже отправлен, старый ticket освобождён, результат остаётся неизвестным, возврат допускает независимое чтение. Поздний ответ не восстанавливает старую отметку принятия и не блокирует новые кнопки. Ошибка и инструкция чтения показаны вместе.
- Unit transport: `test-component-recovery-ui.mjs` теперь **14/14**, включая freshness, уход во время подтверждения и уход во время pending POST. Эти проверки не выданы за настоящее package recovery.
- Browser runner передаёт все пять component path flags в отдельные абсолютные каталоги своего `.review-local/ui-http-*`. Настоящий policy API теперь работает без `--policy-transport`; прежний Windows path blocker устранён владельческим CORE commit.

Браузерный прогон без `--auth-only`/`--policy-transport`: **12 сценариев, RC 0**, Chrome `154.0.8037.95`, артефакты `.review-local/ui-http-MyMyJX/result.json`, `ui-state.json`, `server.log`. `errors=[]`, `configUnchanged=true`, `safe_mode=true`; сервер завершён, порт 18851 свободен. Предыдущие полные RC 0 сохранены в `.review-local/ui-http-SlCvpg` и `.review-local/ui-http-eIFcwq`.

Настоящие ответы: policy GET/PUT/readback 200, CAS 409 после второго настоящего HTTP writer, recovery GET 200, logout/session 401, CSRF 403. На дубликат Save — 1 PUT + 2 GET. Recovery navigation — только GET, без записи. Эти суммарные счётчики включают фоновые читатели и не являются бюджетом одного открытия или ARM64 замером.

Recovery отрицательные сценарии используют **только журнал-заготовку в собственном одноразовом каталоге**; embedded assets, HTTP decoder и guards настоящие. GET pending prepared показывает версии и disabled repair в Safe Mode. Matching POST `abandon-prepared` получает настоящий **409 COMPONENT_AUTHORITY_CHANGED**, байты журнала не меняются. После GET `upgrade-started` кнопок force/replay нет. Повреждённый JSON получает настоящий **503 COMPONENT_JOURNAL_UNAVAILABLE**, UI показывает причину и доступное чтение, сохраняет fence. Заготовка удалена только из своего каталога, независимый GET снова показывает отсутствие pending. Пакет, процессы, native quiescence и успешный live/idle acceptance этим не проверены.

Контролируемые transport faults обозначены отдельно: настоящий policy PUT commits 200, затем только его доставка заменена на 500; read 409/500 и auth/status 500 подставлены. Проверены сохранение dirty полей, отсутствие replay и доступное reconciliation. Backend 500 при самой записи по-прежнему unverified.

Повторные проверки после review-поправок:

| Проверка | Результат |
|---|---|
| 79 строк Node gate из `check.sh`, исключая `*supervision*` | **79/79, RC 0**, `.review-local/frontend-d12-review.log`; Git shell в PATH, opkg launcher stubs only |
| recovery UI unit | **14/14, RC 0**; новый test ещё подключает координатор |
| `go build` embedded server, `go test ./cmd/razvilka -count=1`, `go vet ./cmd/razvilka` | **RC 0**, Go 1.26.5 Windows/amd64, `GOMAXPROCS=2`, `GOFLAGS=-p=2`, `GOTOOLCHAIN=local` |
| полный браузер без policy transport | **12/12, RC 0** |

### Снимки для визуальной приёмки координатором

Это PNG настоящего embedded приложения в последнем прогоне; никакого mock/preview transport. В PNG не сохранялись пароли, tokens, config или private profile contents; все три просмотрены исполнителем. После визуальной проверки добавлены отступы и перенос заголовка recovery-панели, `interface.css` пересобран. Narrow capture ждёт завершения анимации закрытия меню.

- [Главная — 1280 × 900](../../../.review-local/ui-http-MyMyJX/01-home.png): отдельная тестовая копия catalog/config, Safe Mode включён, автоматика выключена. Inventory использует бинарники ПК (включая установленный пользователем AmneziaWG); native-проверки не выполнялись. Показаны настоящие пустые/ещё не загруженные данные, успех не имитирован.
- [Обходы/recovery — 1280 × 900](../../../.review-local/ui-http-MyMyJX/02-component-recovery.png): настоящие HTTP и интерфейс; только `upgrade-started` журнал является одноразовой заготовкой. Видны неизвестный исход, версии, чтение и отсутствие replay.
- [Подключения — 390 × 844](../../../.review-local/ui-http-MyMyJX/03-connections-narrow.png): настоящая пустая библиотека в отдельном состоянии; узкий экран с закрытым меню. Full-page PNG длиннее viewport. Общие счётчики, controls и сообщения взяты из приложения.

Абсолютный каталог всех снимков: `C:/Projects/RAZVILKA/worktrees/sol-ui/.review-local/ui-http-MyMyJX/`. Поля `screenshots[].source` и viewport также записаны в `result.json`. PNG и частные run logs остаются игнорируемыми локальными артефактами.

OPS WIP контракт прочитан по указанию координатора: `accept-installed-idle`, terminal `accepted-installed-idle`, `installed_idle_accepted=true`, `live_accepted=false`; exact version/config + trusted inactivity/quiescence. В текущей интегрированной базе action/phase ещё нет, UI не отправляет его по догадке. Будущая idle отметка должна означать установленную неактивную версию, не live и не сервисный PASS. `awaiting-rollback-acceptance` уже имеет отдельную проверку результата отката; candidate callback не используется UI как доказательство принятия.

Эта порция готова к review; весь D12 не закрыт. Следующие шаги: подключить принятый CORE/OPS idle contract, затем полный card workflow, массовые подключения/AI и legacy-дубли. Linux/native/HIL/race/weak-router CPU/RSS/render-cost остаются за координатором.

## Мобильный drawer: отдельная browser регрессия

База `988aebd`. Отступы recovery и закрытый mobile screenshot из `ui-http-MyMyJX` уже приняты координатором; повторно добавлены проверки открытого меню, геометрии и фокуса.

На прежних assets новая настоящая browser проверка воспроизводит **RC 1: open drawer obscures bottom navigation** (`.review-local/ui-http-beNZlH`). Переполнения по ширине закрытого меню не обнаружено: прежний обрезанный снимок `ui-http-eIFcwq` был снят во время transition. В production теперь drawer заканчивается над нижней навигацией с учётом safe-area, footer расположен над drawer/backdrop; четыре кнопки занимают четыре колонки. Выбор раздела из открытого sidebar переводит фокус в заголовок страницы. Escape, X и backdrop возвращают фокус кнопке открытия, закрытый sidebar остаётся inert.

Исправленная проверка: **13/13 browser, RC 0**, `.review-local/ui-http-RGI8GP/result.json`. На ширине 390: **document scrollWidth=390, clientWidth=390, body scrollWidth=390** при закрытом и открытом меню. Main начинается с x=0 и имеет ширину 390; brand целиком внутри открытого drawer. Нижняя навигация y=784…844 видна и доступна под обоими состояниями (проверены hit targets всех кнопок). Проверены закрытие Escape/X/backdrop, выбор раздела sidebar и переход нижней навигацией из открытого меню. Только GET при navigation; никаких package/runtime действий.

Свежие реальные снимки, просмотрены исполнителем:

- [Закрытые подключения — 390 × 844](../../../.review-local/ui-http-RGI8GP/03-connections-narrow.png)
- [Открытый drawer — 390 × 844](../../../.review-local/ui-http-RGI8GP/04-mobile-drawer-open.png)

Абсолютный каталог: `C:/Projects/RAZVILKA/worktrees/sol-ui/.review-local/ui-http-RGI8GP/`. Данные намеренно пустые тестовые; журнал-заготовка recovery по-прежнему явно описан как fixture. `errors=[]`, `configUnchanged=true`, Safe Mode включён. Скриншоты не включены в Git.

Node selected gate **79/79**, лог `.review-local/frontend-d12-mobile.log`; `go build`, `go test ./cmd/razvilka -count=1`, `go vet ./cmd/razvilka` — RC 0. Shared gate, backend и чужие файлы не редактировались. Следующая вертикаль по указанию координатора: полный card workflow, массовые подключения/AI и legacy-дубли; новый idle action ждёт принятой реализации CORE/OPS.

## Независимый порт browser harness

По просьбе координатора добавлен `RAZVILKA_UI_PORT`, default **18851**, проверенный целый порт **1024…65535**. Один `listen` используется для origin, server startup и TCP occupancy check. Занятый TCP порт отклоняется до запуска сервера/браузера, даже если слушатель не отвечает HTTP. В result.json записаны origin/port. Координатор может задать **18852**, не пересекаясь с UI стендом на default 18851.

Проверены отказ для `0`, `65536`, `abc`, `18852x`, пустого значения и занятый собственным одноразовым TCP listener **18851**; RC 0 проверяющего сценария. Порт 18852 не занимался исполнителем. Полный default browser **13/13, RC 0**, `.review-local/ui-http-QWvip7/result.json`, origin `http://127.0.0.1:18851`, `errors=[]`, config unchanged. Syntax и diff-check RC 0.

Перед этим объединён принятый CORE settlement commit `dc17f55` обычным merge `4cbb71f`; собственный backend не редактировался. Новый сервер собран из этой базы. Новая idle action ещё не включена.

## Schema 2 / idle после принятого CORE HTTP контракта

Объединены принятые OPS предки до `ba99ef4` и CORE предки до `74b987c`, без ручной правки чужих файлов. Источник DTO — `internal/app/component_recovery_capabilities.go`: `supported_actions`, `available_actions`, `quiescence_confirmed`, `inactivity_confirmed`, `installed_idle_accepted`, `live_proof_required`. Поля `allowed_actions/safe_mode/stopped/authority_current` не выдуманы.

- Recovery понимает **только schema 1 и 2**, future schema закрывает действия. `accepted-installed-idle` разрешён только в schema 2 и всегда имеет нейтральный статус, включая receipt с ложным `live_accepted=true`.
- Кнопки — пересечение известных безопасных phase/actions и supported/available из свежего GET. Без capabilities старый сервер доступен для чтения; пустой available список не заменяется локальным предположением о разрешении.
- `accept-installed-idle` доступен только для schema 2 `awaiting-live-acceptance`, когда **сервер** сообщил quiescence и inactivity, supported+available включают action. Review поясняет exact version/config и неактивность; POST использует прежние exact transaction/component/revision/confirm, без force/operator boolean.
- Idle POST требует `installed_idle_accepted=true`, **`live_accepted=false`**, затем независимый GET той же terminal idle transaction с соответствующим capability. Missing/mismatched ответ остаётся unknown, не replay. Это не live и не сервисный PASS.
- Historical `upgrade-started`/`rollback-started` по-прежнему без force/replay. Текущие UI actions не добавляют `allow_unknown_rollback` / `external_repair_confirmed`.

Unit transport **18/18 RC 0**. Selected Node gate **79/79**, `.review-local/frontend-d12-capabilities.log`; `go build`, `go test ./cmd/razvilka -count=1`, `go vet ./cmd/razvilka` RC 0.

Настоящий полный browser **14/14 RC 0**, `.review-local/ui-http-NCdA0a/result.json`, port18851. Read-only fixture journal сначала schema1 prepared, затем schema2 upgrade-started и schema2 idle terminal: настоящие GET читаются UI без schema blocker, idle остаётся unknown tone, новые записи не отправляются. В Safe Mode backend `available_actions=[]`, repair-кнопок нет; matching POST отвергнут настоящим 409 без изменения журнала. Corrupt journal даёт настоящий 503. Прежние CAS/auth/mobile проверки также прошли, `errors=[]`, config unchanged. Idle terminal здесь **записанная тестовая заготовка**, не native proof; успешный idle POST проверен только unit transport. Safe Mode стенда не выключался, аппаратные/пакетные действия не выполнялись.

## D12: шаги в карточках, массовые действия и ИИ — 04.10.2026

Карточка каждого обхода теперь показывает установку, профиль, проверки и применение. Метаданные файла и сохранённые назначения не выдаются за проверенный формат или доступ сервиса. Кнопки открывают существующий редактор **того же движка** на нужной вкладке и переводят фокус на нужный контрол; переход не запускает install/check/Apply. Версии, обновление и удаление раскрываются в «Версии и обслуживание»; ошибки операции и recovery остаются видимыми. Старые ID и обработчики сохранены, новый backend не добавлялся.

`openEngineConfiguration` возвращает результат перехода и проверяет auth generation, текущий раздел и последовательность запросов после чтения/подтверждения. Отсутствующий движок требует независимого чтения; подстановка другого движка запрещена. Повторное открытие того же движка сохраняет dirty профиль. Отказ от смены, уход из раздела, новый переход и logout отзывают старый переход до изменения редактора. Logout также очищает результат проверки формата.

В библиотеке обычные проверки и выбор остаются доступны; «Весь VLESS-каталог» и очистка раскрываются отдельно. Текст прямо объясняет, что фильтры/страницы/выбор не ограничивают all-VLESS, удаление требует preview, группа/назначение/резерв защищены. Изменения касаются представления и однократной привязки существующих кнопок; generation/digest/idempotency/CAS/Stop не менялись. Общая заметка о загрузке и дата сохранённых данных размещаются компактнее без скрытия freshness.

Проверки: selected Node gate **79/79 RC 0**, `.review-local/frontend-d12-card-bulk.log`; новый `scripts/test-engine-card-flow-ui.mjs` **11/11 RC 0**; `go build`, `go test ./cmd/razvilka -count=1`, `go vet ./cmd/razvilka`, diff-check RC 0. **Координатору:** добавить новый card-flow test в общий `check.sh`; исполнитель общий gate не редактировал.

Настоящий browser **17/17 RC 0**, `.review-local/ui-http-qFiZ53/result.json`, port18851, `errors=[]`, failure отсутствует, config unchanged, Safe Mode включён и автоматика выключена:

- Engine metadata GET → профиль Xray → локальный dirty draft → отмена перехода к USQUE → проверки Xray с тем же draft. Ноль записей на всех переходах.
- ИИ disclosure: три определения добавлены **только в каталог одноразового стенда**, помечены `UI fixture`, домены `.invalid`, без проверки доступа. Раскрытие, фокус после readback, поиск одного участника и возврат всех участников проходят; группа не создаёт общий маршрут/PASS. Stock каталог этих определений не содержит.
- В одноразовую библиотеку импортированы три VLESS и один Shadowsocks с фиктивными ключами и адресами `.invalid`. При одном видимом подключении review all-VLESS показывает три; отмена не отправляет node-check POST. Реальная резервная группа защищает одну запись. Настоящий preview разрешает две записи, commit удаляет их с `working_routes_changed=false`; **только доставка ответа** заменена на 500. Повторный вызов UI не повторяет commit; отдельный GET получает защищённый VLESS и Shadowsocks. Native checks и Apply не запускались.
- Auth/CSRF/CAS/lost reply/recovery schema1+2/real 503/mobile сценарии из прежней порции проходят.

Снимки из этого же запуска: `07-engine-flow.png`, `05-ai-group.png`, `06-bulk-library.png`, `03-connections-narrow.png`, `04-mobile-drawer-open.png`, `02-component-recovery.png`, `01-home.png`. Источник и viewport записаны рядом в result.json. Полные страницы снимаются с начала прокрутки; карточки/ИИ/массовые действия просмотрены визуально. Результаты Windows UI не заменяют native или ARM64 приёмку координатора.

## Отдельный read-only HTTP измеритель — 04.10.2026

`scripts/measure-ui-http-browser.mjs` работает **только с уже запущенным HTTP(S) сервером**. Не создаёт сервер, аккаунт, fixture или профиль, не вызывает probe/check/install/Apply/Stop/recovery actions. Существующий cookie session читается из Playwright storageState файла (`RAZVILKA_PERF_SESSION`), либо выполняется единственный явный `/auth/login` через env credentials до измерений. Setup/reset/recovery-login отсутствуют. Все запросы страницы, кроме GET/HEAD/OPTIONS того же origin, блокируются до отправки; внешние origins и `refresh=true/force=true` также запрещены. Любая попытка выходит за boundary и делает run failed. Содержимое запросов/ответов, headers/cookies, query, профили, DOM text и screenshots не сохраняются.

Обязательные параметры env:

```powershell
$env:RAZVILKA_PERF_URL='http://127.0.0.1:<порт существующей копии>'
$env:RAZVILKA_PERF_PROFILE='empty' # либо loaded для заранее подготовленного состояния
$env:RAZVILKA_PERF_CHROME='C:/Program Files/Google/Chrome/Application/chrome.exe'
$env:RAZVILKA_PERF_SESSION='<абсолютный путь к частному storageState.json>'
# Альтернатива SESSION: RAZVILKA_PERF_USERNAME и RAZVILKA_PERF_PASSWORD.
# Нельзя одновременно передавать SESSION и пару credentials.
$env:NODE_PATH='C:/Users/Artix/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules'
node scripts/measure-ui-http-browser.mjs
```

По умолчанию результат под `.review-local/ui-perf-*/result.json` рядом с runner; `RAZVILKA_PERF_OUTPUT` задаёт другой корень **локальных частных** артефактов. Chrome/Playwright уже должны быть установлены. Сервер и назначение порта целиком принадлежат координатору; runner произвольный заданный порт не занимает. TLS проверяется штатно, `ignoreHTTPSErrors` не включён.

`RAZVILKA_PERF_DWELL_MS` default2000 (250…30000), `RAZVILKA_PERF_IDLE_MS` default16000 (1000…60000), `RAZVILKA_PERF_TIMEOUT_MS` default45000 (5000…120000). Для сравнения держать одинаковые viewport/Chrome/параметры/состав fixture. Read-only route fence отключает browser HTTP cache; это явно записано, и одинаково для всех прогонов. Cold означает новый browser context, а не холодный сервер. Live HTTP/cookies без response fixtures.

Четырнадцать измеряемых фаз: холодное авторизованное открытие, семь остальных основных разделов, возврат на Home с остальными скрытыми разделами, быстрые переключения с возвратом, возврат к подключениям с idle, mobile подключения/обходы390×844, явный readbackHome. Дополнительно попытка настоящей фоновой браузерной вкладки: если Chromium не сообщает `hidden`, фаза **skipped**, без overrides `document.hidden` и без придуманных чисел.

На фазу сохраняются UTC start/end для совмещения с SSH sampler, настоящие запросы по method/path/status и request IDs, пути текущего `panelViewRequests` + common reads и прочие API paths, pending/stream counts, CDP delta Task/Script/Layout/RecalcStyle duration/counts, Nodes/Documents/JSEventListeners/JSHeap, longtasks, total/active/hidden DOM и горизонтальное переполнение/геометрия. Requests относятся к фазе по моменту **начала**; статус в phase summary — на момент окончания, поздние завершения видны в общей request table. `other_api_paths` требуют анализа, не автоматически дефект. TaskDuration измеряет браузерный main thread; это **не CPU/RSS ARM64 процесса**. CPU/RSS, router/network/native приёмка остаются координатору.

После фаз три явно отделённых GET проверяют реальные counts библиотек/выбранных сервисов/устройств. `empty` допускает stock service catalog и требует отсутствия nodes/groups/enabled/applied services; `loaded` требует ненулевого состава именно этой пользовательской библиотеки. Устройства LAN/их policies и installed inventory — независимые наблюдения. Counts устройств сохраняются целиком: total, discovered, not_discovered, unknown discovery marker и policy assignments (null при неполном DTO). Устройства не превращают пустую библиотеку в наполненную. Несоответствие/неполные **library** counts — failure, unknown не подставляется нулём. Обнаружение binaries идёт на host сервера. Установленный на Windows `C:/Program Files/AmneziaWG/awg.exe` не означает Linux kernel/native route acceptance и не изменяется исполнителем.

Проверки boundary **6/6 RC 0** (`scripts/test-ui-http-perf.mjs`, можно добавить в общий Node gate координатора). Настоящие Windows smoke на собственном18851, dwell250/idle1000: `.review-local/ui-perf-k9tFi6` — empty/env-login; `.review-local/ui-perf-0L4DGM` — loaded/существующий частный session. Оба:14 измеренных+1 честно skippedbackground, verified fixture, failures/blocked/browser_errors отсутствуют, UI requests **только GET**, метрики CDP/DOM получены, horizontaloverflow0 на всех измеренных фазах. Loaded — только4 фиктивных VLESS `.invalid`; config и node metadata hash неизменны до/после измерения. Аккаунт и эти4 записи подготовлены отдельным ignored test helper до запуска измерителя; не runner. Эти короткие smoke доказывают работоспособность измерителя, не слабый роутер/большой каталог и не ARM64 performance PASS. До уплотнения карточек замечен отдельный GET `/engine-configs/nfqws2/guided` при `enter-engines`; follow-up UI уберёт скрытый editor read.

ARM baseline координатора выявил auto-discovery LAN при пустой библиотеке: прежний criterion devices==0 ошибочно давал RC1 уже после всех14 измерений. Исправлено только определение profile, query/body/backend не менялись; существующие `empty/loaded` env совместимы. Boundary tests теперь **7/7 RC0**, включая discovered-only пустую библиотеку и ненулевые nodes. Compact UI в этот hotfix не входит.

## Уплотнение карточек и скрытый profile GET — 04.10.2026

Четыре этапа видны в компактном progress (выделен **следующий**, не доказанно пройденный этап), рядом одно текущее действие. Все остальные переходы/описания доступны в «Все шаги настройки», версии отдельно. Каждый profile/check/apply control существует ровно один раз. Раскрытие и фокус сохраняются при обновлении метаданных. При одинаковом viewport1280×900 полный снимок страницы сократился **3539→2877px** (около19%); это геометрия той же UI-заготовки, не CPU benchmark. Mobile390×844 с раскрытым Xray workflow имеет horizontaloverflow0; footer остаётся видимым.

«Бинарник обнаружен» теперь требует свежих metadata `engine.installed===true` **и** непустой `engine.binary_path`; aggregate running/config/component installed без path даёт только «Есть сведения об установке; бинарник не уточнён». Contradictory installed=false + path не становится proof. Источник backend checked read-only: `internal/engine/engine.go`, `Detector.Inventory()` определяет installed по найденному executable path, `internal/engineconfig` переносит detector status; редактор/шаблон installed не создаёт. Конкретный AmneziaWG Windows снимка — пользовательский host binary, не дефект backend. Он не изменялся. В тексте карточки указано, что версия протокола/поддержка ядра и доступ требуют собственной проверки.

`renderPanelSection(engineConfigs)` открывает editor только в `engineconfig`, иначе обновляет карточки. Это устраняет обнаруженный hidden `/engine-configs/nfqws2/guided` GET на `engines`, не меняя editor/CAS/actions. Real browser регрессия требует **0 guided GET** на карточках до явного перехода; Xray/USQUE выбор, dirty draft и отмена сохраняются.

Selected Node **79/79 RC0**, `.review-local/frontend-compact-engine.log`; card-flow11/11, perf-boundary7/7, component-cards включая новые binary/progress assertions и CSS/DOM contract RC0; build/test/vet cmd RC0. Реальный финальный browser **17/17 RC0**, `.review-local/ui-http-vKOwil`, `errors=[]`, config unchanged, SafeMode/автоматика по прежним ограничениям. Снимки `07-engine-flow.png` и viewport excerpt `08-engine-flow-narrow.png` просмотрены визуально; captions содержат source/viewport/fullPage. Read-only perf smoke после правки: `.review-local/ui-perf-qbcog0` empty и `ui-perf-ktXg7I` loaded, verified fixture, no blocked/errors, overflow0; `enter-engines` other paths только `/components/recovery`, без guided profile. Dwell250/idle1000, Windows — не ARM64 приёмка.

Read-only анализ ARM artifact координатора `delivery-review/.review-local/ui-perf-RDZm6u/result.json`: library0, services selected/applied0, **14 discovered-host devices** в исходном total count (discovery flags старый report ещё не сохранял). 40cold API; home idle22/node idle31. Кроме hidden guided GET, на Home/Nodes видны периодические `/connections`. Последующий отдельный UI follow-up ограничит REST/SSE видимым разделом соединений; node/activity/inventory/read-capability schedulers этим коммитом не менялись.

## Соединения: REST/SSE только в видимом разделе — 04.10.2026

`app.js` теперь допускает periodic REST и SSE только при authenticated + `currentView==='connections'` + visible document. Уход в другой раздел/скрытие вкладки закрывает stream, отзывает epoch, abort GET и освобождает flight. Сохранённые строки остаются в памяти текущей сессии как **не live**; logout очищает их прежним lifecycle. Возврат открывает один свежий stream, foreground запрашивает новое чтение, REST fallback остаётся каждые15сек в видимом разделе. Два одновременных refresh делят один GET. Старые ответы/ошибки/finally/пакеты не меняют новый flight/сессию. Общие node activity, Stop, inventory, service-control и capability schedulers не редактировались; backend/производитель потоков не менялся.

`scripts/test-connection-session-ui.mjs` расширен: Home/background не допускают REST/SSE; повторный GET single-flight; отмена signal на уходе/hidden; late REST/401/SSE не пересекают navigation/logout; старый finally не снимает новый flight; возврат, повторный sync и текущий401. Selected Node **79/79 RC0**, `.review-local/frontend-connection-scope.log`, card-flow11/11, perf-boundary7/7; build/test/vet cmd RC0.

Real HTTP browser **18/18 RC0**, `.review-local/ui-http-Zt6fqp/result.json`, failures/errors отсутствуют, config unchanged. Новый сценарий: на Home нет connection requests; явный `connections` открывает1stream; двойной refresh даёт1GET; на Nodes stream закрыт и hidden reads0; возврат открывает1новый stream. Остальные auth/CSRF/CAS/recovery/bulk/card/AI/mobile сценарии проходят. Browser пока не доказывает настоящую hidden browser tab: это поведение покрыто unit lifecycle и честно skipped в headless perf.

Read-only smoke текущего поведения: `.review-local/ui-perf-dKpyAE` empty/env-login и `ui-perf-UcvZ4O` loaded/session, 14 измерений + skippedbackground. В обоих **0 `/connections*` и 0 `*/guided`** в общем request table, overflow0, no errors/blocked/failure, fixture verified; config и node metadata неизменны. Это короткий Windows dwell250/idle1000, не новый ARM CPU/RSS benchmark. Координатор отдельно повторяет ARM после новой embedded сборки; его прежний baseline происходил рядом с production autonomy, которая меняла config, и не означает «production config неизменен». Router/VM/порты18854/8787 исполнитель не трогал.

Отдельный косметический commit `9a45551` исправляет undefined цветовой token progress на существующий theme accent; geometry/actions не менялись, compiled CSS contract51/51. Состояние highlighted step по-прежнему next, а не PASS.

## D12: завершённые шаги из текущих receipts — 04.10.2026

Карточка обхода теперь показывает независимые результаты формата, свежего веб-сценария и совпадающего committed Apply. Receipt записывается только после пользовательского Validate/Apply/probe через существующий authenticated API. Карточка ничего не проверяет и не применяет автоматически. Публичная привязка включает engine/file ID, фактический SHA256 текущего файла или ответа Stage, config revision, auth epoch, наблюдаемые node generation/network, состав установки и время версии файла. FileView SHA относится к live даже при staged: для черновика берётся только фактический Stage/read receipt. После Apply перенос проверки формата допускается только при том же SHA и revision. Секреты, content и review tokens в receipts не хранятся.

Apply требует совпадения reviewed/transaction/execution digest и plan ID, revision, committed state, engine adapter и реально сохранённых applied service routes. Safe Mode, pending и unconfirmed не завершают Apply. Старый `services.observed_state` не становится новым тестом после Apply: нужен явный свежий TestLab результат с текущей сетью, Evidence v2 service/engine/path/outcome, без negative control/route mismatch и с проверенными timestamps/expiry. Формат и доступ сервиса остаются отдельными результатами; переносимый формат не называется нативным. Смена SHA/revision/generation/network/auth/установки, Stop, failed Apply, свежий отрицательный результат и ошибка чтения удаляют завершённые receipts. Pending скрывает отметки; действия не получают authority из UI. Локальная максимальная свежесть — 120 секунд.

Положительный regression проходит через настоящие UI handlers Stage → Validate → review-bound engine Apply → свежий TestLab probe, затем production renderer отмечает четыре шага. Отдельно проверены старый PASS после Apply, wrong digest/plan/revision/service/engine/network/path, отрицательный контроль, expiry, Stop, pending, отмена, смена профиля и отсутствие hash. Это controlled public DTO fixture, не native/router/network proof. Проверки из check.sh до native supervision: 78/78 RC0 (52 script/build checks и 26 syntax checks), журнал `.review-local/ui-progress-frontend-checks.log`. Go build embedded UI RC0. Реальный Windows HTTP/browser regression: 19/19 RC0, `.review-local/ui-http-WX3kk8/result.json`, browser errors0, config unchanged, policyTransport=false; fixture остановлен.

D12 целиком не закрыт: существующие Validation/TestLab/Apply DTO не связывают trusted service evidence с отдельной engine runtime generation; для sensitive live FileView отсутствует публичный hash. При отсутствии подтверждаемой identity UI не отмечает завершение. Named WG CRUD revision из NET `b60d84b` — идентификатор сохранённого syntax-only профиля, не service/Apply authority. Для полного per-engine пути CORE/VLESS/NET должны предоставить принятую привязку profile revision/hash + runtime generation в своих фактах; UI новую backend authority не добавляет. ARM/native положительный путь здесь не заявлен.

## Named WireGuard CRUD по принятому NET/CORE контракту — 04.10.2026

`wireguard-profiles-ui.js` подключён к обычному WireGuard workspace и embedded assets. При открытии видимого WG раздела выполняется один GET `/api/v1/wireguard/profiles`; таймеров и скрытых чтений нет. Список содержит только public ID/name/revision, syntax-only, route, reserve и references. `reserve` показан как «Сохранён без назначений», без обещания автоматического переключения. Отдельная подпись отличает именованный каталог от прежнего единственного общего файла ниже.

Создание POST `{id,name,content}`, замена полного файла PUT `/{id}` `{name,content,expected_revision}`, удаление DELETE `/{id}` `{expected_revision}`. Замена использует revision выбранной редакции; содержимое приватного файла не читается из backend и не заполняет форму. Удаление используется только после собственного подтверждения, без известных references; backend остаётся владельцем полного CAS/reference/operation fence. References перечислены и повторно проверяются UI после подтверждения. Никаких service writer, check, Apply или разрешений на резерв CRUD не вызывает.

Успех требует точного `saved|deleted:true`, `live_applied:false`, корректного public profile с совпадающими ID/name/revision shape и `verification:syntax-only`. Только после этого выполняется readback каталога. 404/501 не заменяются успехом. 409, 503/unconfirmed, lost reply и неверный success DTO удерживают форму и блокируют следующую mutation до явного чтения; существующий каталог не удаляется оптимистически. CAS после чтения не переходит автоматически на другую редакцию. Двойной submit даёт одну mutation. Logout/уход очищают приватные поля, отзывают epoch/abort; поздние ответы/чтение файла не восстанавливают данные или разрешение записи. В state хранятся только whitelisted public metadata; local/session storage отсутствуют. CRUD отзывает локальные progress receipts WG, но не создаёт service/Apply proof.

Проверки: 79/79 RC0 (78 прежних script/build/syntax checks плюс syntax нового asset); динамический regression нового WG модуля находится в уже подключённом `test-awg-workspace.mjs`. Положительные create/replace/delete, точные CAS тела, references, wrong receipts, unknown outcome, privacy whitelist, single-flight, hidden reads, logout/navigation/file-read fences проверены через production functions. Embedded Go build RC0. Итоговый Windows HTTP/browser: **20/20 RC0**, `.review-local/ui-http-i6aa7k/result.json`, errors0/failure absent/config unchanged/policyTransport=false. Named WG сценарий использует честно обозначенный controlled public DTO transport с четырьмя writes; реальный backend моей прежней UI ветки отвечает404 и интерфейс держит Save выключенным. Это не проверка регистрации нового CORE Handler или native WG.

Снимки `08-wg-profiles-wide.png` и `09-wg-profiles-mobile.png` из того же запуска просмотрены: каталог/форма/ссылки читаемы при1280×900 и390×844, overflow WG0; приватная форма очищена после подтверждённого сохранения. Собственный fixture18851 остановлен. CORE `6c74010` уже принят root в integration `0437ca1`; координатор повторяет реальный Handler/browser после merge UI. Именованный check/Apply с привязкой profile revision + runtime generation по-прежнему требует typed evidence владельцев и не подменён syntax-only CRUD. D12 целиком не закрыт.

### Отдельная actual Handler/browser проверка для ROOT

Runner `scripts/test-wireguard-profile-http-browser.mjs` подключается только к **уже поднятой** пустой приватной Safe Mode копии. Перед ним ROOT собирает integration с NET `b60d84b`, CORE `6c74010` и данным UI checkpoint, создаёт отдельный полный appstate с отключёнными draft/applied services и запускает бинарник со всеми принятыми isolated path flags. Параметр `-dataplane-state <fresh-dir>` задаёт именно тот startup catalog, который находится в `<fresh-dir>/profiles/wireguard`; не использовать retained/shared dataplane state. Аккаунт и session создаёт ROOT существующим fixture workflow. Runner не выполняет setup/reset и не запускает/останавливает сервер.

Пример вызова с Windows/Chrome клиента к существующей ROOT копии (URL заменить на её реальный origin; никакой порт runner не занимает):

```powershell
$env:RAZVILKA_WG_UI_URL='http://127.0.0.1:18854/' # только уже поднятая ROOT disposable copy
$env:RAZVILKA_WG_UI_FIXTURE='empty-private'
$env:RAZVILKA_WG_UI_CHROME='C:/Program Files/Google/Chrome/Application/chrome.exe'
$env:RAZVILKA_WG_UI_SESSION='<абсолютный путь к private Playwright storageState.json>'
$env:NODE_PATH='C:/Users/Artix/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules'
& 'C:/Users/Artix/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe' scripts/test-wireguard-profile-http-browser.mjs
```

Вместо SESSION можно передать `RAZVILKA_WG_UI_USERNAME` + `RAZVILKA_WG_UI_PASSWORD` через private env; SESSION одновременно не передавать. Тогда выполняется один обычный login существующего аккаунта. `RAZVILKA_WG_UI_OUTPUT` — необязательный private output root; default `.review-local/wg-real-ui-*/result.json`. Runner переносим между Windows/Linux при наличии установленного Chromium и Playwright. TLS проверяется штатно.

Проверки по порядку: реальный authenticated status Safe Mode/live inactive + disabled services + пустой WG catalog; открытие обычного WG UI; двойной submit даёт один реальный POST; GET ID возвращает только public syntax-only metadata; замена через UI даёт PUT и новую revision; отдельный **реальный** PUT со старой revision должен получить409 и сохранить новую редакцию; удаление через UI с подтверждением даёт DELETE; GET collection пустой, GET ID404, config revision и disabled services прежние. Уникальный test ID и валидные X25519 ключи генерируются на один run, Endpoint=`fixture.invalid`; профиль не назначается и сетевой трафик через него не запускается. В текущем NET CRUD используется Go `ParsePlainWireGuard`, не нативный `wg` checker, поэтому installed wg/module не являются условием syntax-only CRUD. Нативная проверка/handshake/доступ здесь не заявляются.

Browser route handlers выполняют только `continue`/`abort`, никогда `fulfill`: same-origin reads, единственный login и CRUD только с выбранным generated ID, точным content/name/revision. Apply/Stop/probe/install/чужие ID/внешние origins блокируются и делают run failed. Request/response bodies, headers/cookies, content/ключи, DOM/screenshots и foreign exception details не сохраняются. При failure run RC1 и стадия записаны без частных данных; если profile write мог состояться, result содержит generated ID и `cleanup_required:true`, без автоматического replay. ROOT удаляет свою disposable копию после проверки по обычному lifecycle.

Локально проверены syntax, `--help`, settings и request-boundary отрицательные случаи в уже подключённом `test-awg-workspace.mjs`; actual Handler run этим исполнителем **не заявлен**. ROOT владеет connected/native приёмкой. Controlled DTO browser выше остаётся отдельным UI regression.

## D13 — отдельное представление сохранённых источников — 04.10.2026

UI потребляет finished CLOUD `8ad2533cf9c70b029593953b00421aeba3d89861`: только GET `/api/v1/sources/offline`, точный DTO `{offline:true,read_only:true,sources:[...]}`, каждая строка `offline:true,ready:false`. Коллекция хранится отдельно от обычного `/sources`; копия не заменяет live array, даты, draft/applied выбор или факты о маршрутах. Вход, переключение представления, повторное чтение и возврат после login не вызывают refresh/Apply. Кнопка «Перечитать сведения» выполняет свежий GET.

«Сохранённые копии» показывает banner «Сохранённые данные. Сейчас источники не обновлялись.». Все четыре source mutations закрыты и в DOM, и в handlers. Сохранённый и применённый выбор показаны отдельно от состояния копии: disabled не скрывает legacy/stale/quarantined/LKG warnings. Legacy требует сверки независимо от прежнего ready; LKG с last_error сохраняет предупреждение об отклонённом обновлении; совмещённые предупреждения перечисляются вместе. Reference, обычная сохранённая копия и отсутствие копии нейтральны. Overview считает сохранённые копии и справочные источники, без ready/PASS. Показаны записи, «Загружено», «Срок локальной копии», SHA256 и public provenance; нулевая или неверная дата — «—». HTML экранируется, лишние поля DTO не сохраняются.

401/403/неполный DTO не подменяются другой коллекцией или старым успехом. Существующий panel read epoch отменяет позднее normal/offline body после переключения, ухода или logout; отдельный source action ticket отзывает публикацию старой mutation и её finally. Следующая запись после неподтверждённого результата требует явного чтения. Обычный источник сохраняет прежние draft/refresh/apply/discard действия после подтверждённого normal GET. Автоматического replay нет.

Проверки check.sh до native supervision: 78/78 RC0, `.review-local/ui-source-offline-frontend.log`; новый production-function regression импортируется уже подключённым `test-panel-loading-ui.mjs`, shared `check.sh` не менялся. Проверены семь состояний копий, смешанные warnings, immutable live data/dates, GET-only view entry, четыре запрещённых offline actions, реальные panel/auth epoch guards при ignored abort, поздняя mutation/finally, 401/403 без fallback и возврат к обычным действиям. Embedded Go build RC0. После нейтральной правки подписи overview повторены panel-loading regression и app syntax, RC0.

Windows browser: **21/21 RC0**, `.review-local/ui-http-ZbsroX/result.json`, browser errors0, config unchanged, policyTransport=false. D13 сценарий использует настоящие normal source HTTP и embedded UI, **controlled offline DTO**; прежний Handler UI ветки на новом URL отвечает405, что явно записано в результате. Весь сценарий — GET45/source POST0; normal array/dates не изменены. `10-source-offline.png` просмотрен: warnings, даты и отдельный saved/applied выбор читаемы; замеченная старая подпись «Проверенные локальные данные» заменена нейтральной. Собственный fixture18851 остановлен.

Actual Handler/browser acceptance выполняет ROOT после принятия CLOUD component и exact mux registration CORE. Нужны реальный GET семи состояний, не меняющий TTL/выбор; auth/logout 401 и explicit403 без fallback; отсутствие source POST при входе/переключении/login; действующие normal draft/refresh/apply/discard после возврата. Этот UI checkpoint не закрывает весь D13, trusted provenance gate или USQUE/DNS acceptance. Native/ARM proof не заявлен.

## Именованный WireGuard — обычный service draft writer — 04.10.2026

UI потребляет принятые CORE `560bec54d526645411de805a20fe33917e5a0476` + `3cb49d654f0b8ba45cebb02bb67080ffc4fb21b8`. Ручной выбор находится на странице «Сервисы» внутри «Подробные настройки и ручное применение». Option `kind:wireguard-profile`, `selectable:true` и точный lowercase64 `wireguard_profile_revision` разрешают только сохранение намерения; installed/Ready/Running не превращаются в proof и не запрещают syntax-only draft. Подпись option — «только формат · в черновик». Отсутствующий профиль остаётся видимым, но не получает искусственный selectable.

Обычный PUT `/api/v1/services/<id>` для `wireguard:<id>` передаёт `enabled`, `route`, `sources`, `expected_revision` целого config и `expected_profile_revision` из реально показанного option. Обе редакции заморожены в DOM пункта выбора: фоновое чтение за открытым select не подставляет новый hash/config revision. Неверный/отсутствующий hash, неизвестная config revision и ID-only выбор не отправляют PUT. Backend сохраняет собственный `state.wireguard_profile_revision`; success receipt должен точно совпасть по service ID, route, enabled и profile hash. Затем выполняется независимое чтение status/services без Apply.

Shared body/writer используются также переключателями, обычным `saveService`, service scope и device scope. Сохранение прежнего именованного маршрута использует уже сохранённый hash, а не новую редакцию каталога. Service scope фиксирует route/hash/config revision при открытии; device scope — перед подтверждением. Изменение источников устройств не теряет или подменяет привязку. При выборе другого исполнителя WG metadata не попадает в запрос. Выключение прежнего named route возможно с config CAS даже для legacy без hash, по withdrawal исключению CORE; оно не приобретает новую привязку.

409, потерянный ответ, неверный receipt и неполный readback блокируют дальнейшие изменения этого сервиса до кнопки «Перечитать выбор». Кнопка выполняет три свежих GET status/services/routes-options, не пишет и не выбирает новый профиль автоматически. Read/write ticket и epoch защищают logout/navigation; старый finally или ответ не публикует успех и не открывает fence. В карточке отдельно показаны desired/applied hashes. Успех writer называется сохранённым черновиком; применённый маршрут не меняется оптимистически. Резерв не получает автоматического fallback назначения.

Для named WG прежние ID-only observed/manual service PASS не показываются как доступность: текущие proof DTO не связывают профиль с runtime generation. Это консервативная граница D12; новый writer и syntax-only hash не создают service evidence, разрешение Apply, native handshake или доступ в LAN. Другие engine proof пути не менялись.

Проверки: общие frontend script/build/syntax checks из check.sh до native supervision **78/78 RC0**, плюс syntax WG asset и HTTP runner **2/2 RC0**, `.review-local/ui-wg-draft-frontend.log`. Production-function regression расширен в уже подключённом `test-service-dashboard-ui.mjs`: frozen config/profile CAS, selectable при Ready/installed=false, неверный/uppercase/отсутствующий hash, retained toggle/scope hash при catalog drift, legacy withdrawal, очистка obsolete metadata, неверные receipts/lost reply, явное readback без replay, auth fences и запрет ID-only service PASS. Отдельно вызваны настоящие service/device scope handlers с изменением состояния во время диалога/confirmation; замороженная пара осталась в запросе. После последних receipt/readback guards и новых scope случаев regression повторён, RC0. Shared check.sh не изменён. Embedded Go build RC0.

Итоговый Windows HTTP/browser **22/22 RC0**, `.review-local/ui-http-AGtUSS/result.json`: errors0/failure absent/config unchanged/policyTransport=false. Новый service сценарий — настоящий embedded UI и **controlled service writer DTOs**: GET30/PUT2 (успех +409), два CAS поля, applied unchanged и no automatic replay. Ни native проверка, ни настоящий новый service Handler этим сценарием не подтверждаются. Первые два прогона остановились на скрытых controls, пока runner не стал открывать реальное disclosure ручных настроек; итоговый прогон проходит через видимые controls. `11-wg-service-draft.png` просмотрен: черновик, формат, редакции и неприменённый маршрут читаемы. Собственный fixture18851 остановлен.

### Actual Handler/UI gate для ROOT

Использовать только ROOT disposable Safe Mode копию с принятыми CORE/NET/UI, disabled draft/applied services и отдельным WG catalog. Сначала создать syntax-only профиль обычным WG CRUD и прочитать `/routes/options`. В manual service disclosure выбрать профиль для отключённого сервиса: реальный PUT обязан содержать обе показанные редакции, GET services — тот же desired hash и неизменный applied route/hash. Config revision изменяется только от этой явной записи; компонент не становится Ready/Running. Scope change и retained disable сохраняют пару route/hash.

Отдельно проверить настоящие stale config CAS и stale profile CAS:409 без изменения intent, никаких автоматических PUT, controls закрыты до «Перечитать выбор». После трёх GET новый hash виден в option; только новый ручной выбор создаёт следующую запись. Legacy/missing профиль можно выключить, но ID-only enable/apply не становится разрешённым. При переходе на direct/другой engine obsolete WG metadata отсутствует в body и GET desired state. Logout/уход во время ответа не восстанавливает старые controls. Удаление профиля с references должно оставаться защищённым NET; для cleanup использовать свою disposable копию. Apply/Stop/проверка сервиса не являются частью этого draft gate. Root standalone CRUD runner остаётся отдельным шестишаговым gate с прежним config-unchanged условием; этот новый gate его не заменяет.

### Узкий реальный service writer runner — для запуска ROOT

В существующий `scripts/test-wireguard-profile-http-browser.mjs` добавлен отдельный `--service-draft`. При прежних env URL/FIXTURE=empty-private/CHROME/SESSION либо credentials запускать **только**:

```powershell
& 'C:/Users/Artix/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe' scripts/test-wireguard-profile-http-browser.mjs --service-draft
```

Режим использует уже работающую ROOT disposable Safe Mode копию, пустой WG catalog и выключенные draft/applied services. Встроенный `youtube` должен иметь исходный route auto/direct. Сам runner создаёт один новый случайный `ui-wg-<12hex>` профиль через настоящий UI и X25519/fixture.invalid config. Он **не повторяет** прежний шестишаговый CRUD gate и широкий HTTP suite. Binary должен уже содержать принятую UI `274f24d` и CORE/NET контракты; данный checkpoint меняет только scripts/docs.

Семь шагов: empty-private проверка; создание профиля; реальная замена профиля вне открытого select и старый UI hash →409; реальное изменение disabled direct draft и старый UI config revision →409; свежий ручной выбор →200 с обоими CAS и desired hash readback; реальный scope PUT с disabled service →200, после которого browser delivery прерывается; восстановление исходного disabled intent и удаление собственного профиля с empty/404. После каждого 409/unknown fence попытка production editor не отправляет новый PUT; кнопка «Перечитать выбор» даёт именно свежие status/services/routes-options GET и не повторяет запись. Проверяется старое applied state/scope/hash, Safe Mode=true/live inactive и отсутствие любых Apply/Stop/probe/install/автоматики. Draft config revision здесь меняется от четырёх собственных успешных fixture writes; прежнее CRUD config-unchanged условие к этому режиму не применяется.

Browser request fence разрешает только ожидаемое точное тело одной named service записи с enabled=false, двумя редакциями, одним ID и согласованным scope. Для потери доставки `route.fetch` отправляет настоящий Handler запрос с maxRetries0/maxRedirects0, фиксирует только HTTP200 и вызывает abort; DTO не читается, не подменяется и не передаётся в page. Все остальные browser routes только continue/abort. Контрольные profile/config drift и cleanup PUT выполняются реальным authenticated context.request к собственным generated profile ID и builtin service ID, без retries/redirects. Restore очищает obsolete WG binding; затем profile delete проходит через настоящий UI.

В result.json нет config content/ключей, request/response bodies, headers/cookies, DOM или screenshots. Failure сохраняет bounded diagnostic/stage, `cleanup_required:true` и generated profile/builtin service ID; неизвестная запись автоматически не повторяется и исходный intent при failure не восстанавливается вслепую. ROOT утилизирует свою disposable копию. Default runner остаётся прежним CRUD режимом.

Локально выполнены только syntax, `--help`, существующий AWG regression и расширенные pure request/body boundary negatives, RC0. Actual service Handler/browser run этим исполнителем **не заявлен**; готовый runner передан ROOT. Production UI, backend, VM/router и общий runtime не менялись; широкие suite/build повторно не запускались.

### Исправление scope UI и диагностики узкого gate

ROOT actual run на `5f719966` с UI274/runner615 остановился с TimeoutError в общей стадии `service-real-lost-delivery`: `.review-local/wg-handler-yuwuva35/wg-real-ui-CM7aPZ/result.json` в ROOT integration. Первые **пять** шагов прошли, включая настоящий stale profile/config409, явные GET перечитывания и настоящий named service PUT с обеими редакциями и unchanged applied state. Scope PUT в журнале отсутствует; blocked0/browser errors0/cleanup_required=true. Сервер этой одноразовой копии ROOT остановил; повторное использование не требуется. Семь PASS этим результатом не заявлены.

Проверка source выявила две причины в следующем UI шаге. Runner не открывал `<details>` «Адреса и диапазоны вручную» перед fill. Production form не связывала change выбора all/selected с renderer: после all textarea оставалась disabled, а список устройств hidden. Исправление подключает существующие mode change/manual input/device checkbox handlers; оно не меняет service writer, snapshot/CAS, auth или backend и не выполняет API действий при взаимодействии с формой. Runner открывает настоящее disclosure и проверяет visible/enabled перед fill.

Добавлены отдельные bounded стадии `service-scope-open-dialog`, `select-devices`, `open-addresses`, `fill-addresses`, `authorize-put`, `submit`, `wait-unknown-fence`, `cancel-dialog`, `readback`, `explicit-reread`. `scope_diagnostics` содержит только фиксированные boolean признаки dialog/selection/disclosure/input/config-match/body-authorization/fence/close и integer/null реального HTTP status. DOM/text, значения полей, keys/body/hash/headers туда не попадают. На старом binary disabled input теперь даёт немедленный assertion с `input_enabled:false`, а не непрозрачный 45сек timeout.

Точечные проверки: syntax app/runner, service dashboard regression с настоящими scope control handlers (all→selected, input→checkbox state, снятие checkbox→addresses, selected→all и API0), AWG/boundary regression — RC0. Широкие suite, build и actual сервер исполнителем не запускались. ROOT должен merge исправление **и пересобрать embedded UI binary**, затем повторить только `--service-draft` на новой своей empty-private Safe Mode копии. Шаги 6–7 и потеря доставки ещё требуют реального успешного прогона.

### Исправление явного чтения каталога при cleanup

Следующий ROOT actual run на binary `04a0793` с UI87 подтвердил **шесть** шагов, включая real scope PUT200, lost delivery, unknown fence и explicit GET без replay. `.review-local/wg-handler-sum591do/wg-real-ui-9lg133/result.json`: scope boolean diagnostics все true, handler status200, blocked0/browser errors0. Cleanup service PUT200 и original intent assertion прошли; profile DELETE не отправлялся. Общая стадия cleanup завершилась TimeoutError; disposable app ROOT остановил. Семь PASS ещё не заявлены.

Причина в runner: уход с ранее загруженного WG каталога намеренно выставляет `needsRead:true`, запрещает запись и не запускает скрытое перечитывание. Cleanup ждал `needsRead:false` до нажатия «Перечитать каталог». Теперь он сначала открывает WG workspace, затем выполняет один явный browser GET через `wgProfilesRefresh`, проверяет свежую revision и отсутствие references, доступность Delete и подтверждение удаления. Все прежние restore intent/applied state/DELETE200/empty collection/GET404/network assertions сохранены.

Cleanup разбит на bounded стадии `restore-intent`, `open-engines`, `open-disclosure`, `open-workspace`, `reread-catalog`, `verify-profile`, `request-delete`, `confirm-delete`, `wait-delete`, `verify-empty`, `verify-network` с префиксом `service-cleanup-`. `cleanup_diagnostics` хранит только фиксированные boolean/null результаты этих проверок; DOM/text/body/keys/revision hash не сохраняются. В частности, `catalog_needs_read:true` отражает нормальную защиту retained catalog, а не отключение этой защиты.

Изменены только runner, AWG regression и эта передача; production UI/backend не менялись. Syntax и точечный AWG regression — RC0. Добавленный production-function regression подтверждает: return retains catalog/needsRead, не делает auto GET, держит Delete disabled и открывает его только после одного явного свежего GET. Actual сервер и широкие suite/build исполнителем не запускались. ROOT повторяет только исправленный `--service-draft` на новой своей empty-private копии; уже собранный binary `04a0793` подходит, поскольку этот checkpoint не меняет embedded assets. Последний cleanup шаг всё ещё требует actual PASS.

### ROOT acceptance узкого WG service draft gate — зафиксировано 07.10.2026

ROOT подтвердил принятие `67abc72` и успешный actual Handler/browser `--service-draft` на binary `37b775f` в своей private копии `.review-local/wg-handler-tk85nu45/`. Прогон завершился **04.10.2026, RC0, 7/7 шагов**, browser_errors0, cleanup_required=false. Подтверждены реальные stale profile/config409, обе CAS редакции в service PUT, unchanged applied state, committed scope PUT200 с потерей доставки, unknown fence и explicit GET без replay. Финальная очистка также прошла: восстановлен исходный disabled intent, точный DELETE200, пустой каталог и GET404; сеть осталась неизменной.

Этот результат закрывает узкий actual WG service draft Handler/browser gate и заменяет прежнее ожидание cleanup PASS. Полный D12 остаётся открытым; hardware/native WG/LAN proof этим прогоном не заявлен. Результат получен ROOT, а не новым запуском UI исполнителя. При фиксации изменён только этот handoff; новые тесты и production изменения не выполнялись. Общий VALIDATION обновляет ROOT.

## D12 — один согласованный engine workflow — 07.10.2026

Перед работой сверены finished integration `3dc198a`, TASKS.json D12 и VALIDATION_RU.md. Собственная ветка синхронизирована merge `b995f00`; принятый web UI в integration совпадал с прежним checkpoint. Массовые VLESS проверки/удаление, защищённые назначения, раскрываемая AI группа, WG CRUD и узкий service draft actual gate уже выполнены и не повторялись. TASKS/VALIDATION принадлежат ROOT и не редактировались.

Оставшийся UI разрыв: карточка ожидала live-profile service probe до применения уже проверенного staged файла. Такой probe не проверяет редакторский draft; он не может завершить этот порядок действий. Теперь одна presentation функция используется карточкой и editor progress: dirty/missing профиль → профиль; staged файл с совпадающим format receipt → Apply; после совпадающего Apply без свежего service receipt → проверка сервиса. Все переходы только открывают существующие controls. Первичная проверка фокусирует настоящий `r4Validate`; после matching format receipt — `r4ProbeService`. Actual Stage/Validate/review-bound engine Apply/TestLab handlers, API paths, confirmations, auth/operation/epoch guards не менялись.

Редактор больше не показывает отдельную legacy полосу «установка/процесс/маршруты/проверка», которая могла стать зелёной от running процесса и числа сохранённых маршрутов. Его четыре этапа установка/профиль/проверки/применение используют те же typed receipts, что карточка. Файл выбранного engine сохраняется и на странице карточек: другой файл не получает чужое подтверждение, возврат не заменяет его молча на main. Все прежние URL/DOM IDs остаются; диагностические сведения о процессе/назначениях не становятся service/Apply proof. Есть отдельная подсказка, что service test выполняется после применения подготовленного профиля.

Точечные Node проверки **7/7 RC0**: engine-intent, engine-card-flow, component-cards, interface-contract, interface-home, bundle-integration, node-bulk; interface и HTTP runner syntax **2/2 RC0**. Лог `.review-local/d12-one-workflow-20261007.log`. Дополнены actual production-handler regressions Stage→Validate→Apply→fresh typed TestLab probe с проверкой следующего этапа, одинаковых card/workspace подтверждений, isolation другого файла, dirty/navigation и отсутствия legacy process/route PASS. DTO transport в этих положительных fixtures controlled, не native acceptance. После последней поправки сохранения выбранного файла повторены engine-intent и interface syntax, RC0. Embedded Go build RC0; CSS/новые assets и общий check.sh не менялись.

В существующем Windows HTTP/browser engine case обновлены ожидание реального validator focus и проверки четырёх workspace этапов/совпадения flags; case сохраняет GET-only navigation assertion и dirty profile. Новый actual browser/native прогон этим исполнителем **не заявлен**: ROOT выполняет native UI acceptance перед hour gate, после завершения ordinary runtime wiring. Широкие ранее принятые suite, VLESS/AI HTTP сценарии и WG seven-step gate повторно не запускались.

Этот checkpoint закрывает согласование UI порядка и legacy progress duplicate, не весь D12. Свежая привязка service evidence к profile revision/hash и engine runtime generation, sensitive live FileView hash и hardware/native положительный путь остаются границами существующего API и приёмки владельцев. UI не придумывает active/runtime PASS для карточек или снимков.

## D12 — точные точки оставшейся API привязки — 07.10.2026

ROOT принял UI checkpoint `8e632ae` как integration `acfa9c5250f0bf7a61ecd41fc723a3bbb647fb03`; сообщил RC0 для engine-card-flow 12/12, текущего engine-intent и syntax. Этот раздел уточняет уже записанную границу D12 по read-only коду integration `acfa9c5`. Model checks, actual browser и runtime здесь повторно не запускались. Backend, shared TASKS/VALIDATION и integration checkout не изменены.

- **UI вход/сверка:** `workflowRunProbe()` в `cmd/razvilka/web/workflow-actions.js` захватывает `engineProgressBinding()` и отправляет только services/routes в POST `/api/v1/testlab/routes`; после ответа перечитывает engine configs. `engineProgressBinding()` / `engineProgressSame()` / `engineProgressProbe()` в `cmd/razvilka/web/interface.js` сверяют локальные engine/file/SHA/config revision, сеть и наблюдаемую `state.nodes.generation`. Последняя — generation каталога nodes, не отдельный runtime identity движка. Ответ не содержит подтверждённой пары выбранный file/profile revision → runtime passport; совпадение локального before/after эту пару не доказывает.
- **CORE HTTP/DTO:** `(*App).testLabRoutes()` (`internal/app/app.go`) принимает только services/routes. `(*App).probeRoutesInCurrentNetwork()` (`internal/app/network.go`) и `(*Runner).RecordRoutesForProfile()` (`internal/testlab/testlab.go`) удерживают WAN network profile до/после проверки. `testlab.Result`, `(*Result).NormalizeEvidence()` и `evidence.ProbeEvidence` (`internal/evidence/evidence.go`) публикуют service/engine/network/path/timestamps/outcome, но не выбранный engine file ID, его profile revision/hash и отдельную сравнимую текущую runtime identity. Здесь нужен принятый владельцами публичный контракт привязки и способ его последующей сверки; название новых полей этим handoff не утверждается.
- **Уже существующая runtime защита:** `(*routeprobe.Manager).socksClient()` / `socksPassport()` / `Probe()` (`internal/routeprobe/routeprobe.go`) вызывают `routeidentity.Verify()` (`internal/routeidentity/runtime.go`) до/после SOCKS probe и отвергают смену passport. Его ID зависит от runtime receipt/config/restart/listener; `Passport.ConfigHash` уже существует внутри backend. При успехе ID попадает в expected/observed route path, но его связь с редакторским file/profile и текущая identity для UI readback отсутствуют. Поэтому задача CORE/VLESS — связать и опубликовать существующие факты, сохранив эти проверки. Runtime config может быть сгенерирован из профиля: простое приравнивание runtime config SHA к SHA файла редактора не является принятым контрактом. `(*App).bindApplyReview()` / `(*applyReviewBinding).checkReviewedSources()` (`internal/app/apply_review.go`) уже удерживают reviewed draft hashes внутри Apply; UI не извлекает такую связь из opaque digest.
- **CORE чтение sensitive файла:** `(*engineconfig.Manager).fileView()` (`internal/engineconfig/engineconfig.go`) выдаёт live SHA только при `!f.Sensitive`; `readLocked(..., false)` возвращает sensitive/redacted без SHA. `(*App).engineConfigs()` / `engineConfigAction()` (`internal/app/app.go`) публикуют эти DTO. `ReadExpert()` может вернуть hash вместе с приватным content после отдельной авторизации, но UI не выполняет автоматическое раскрытие ради зелёного шага. Нужен согласованный metadata-only способ подтвердить актуальную редакцию sensitive профиля и runtime binding; staged Stage receipt остаётся подтверждением только staged content.
- **NET named WG:** syntax-only catalog revision и сохранённый `wireguard_profile_revision` уже приняты в draft writer. Ограничение ID-only service proof в `cmd/razvilka/web/service-dashboard-ui.js` остаётся: ни CRUD receipt, ни route ID не подтверждают текущий runtime/handshake/LAN. Для named WG владельцы должны предоставить ту же подтверждаемую связь профиля и runtime с service evidence.

Ожидаемая граница приёмки CORE/ROOT: свежий service receipt должен однозначно относиться к выбранному engine/file/profile и тому runtime, который его исполнил; смена профиля либо restart/runtime identity во время проверки или после неё должна отзывать completion. Неизвестная/отсутствующая identity не заменяется timestamp, running, node catalog generation или сохранённым маршрутом. Этот раздел — передача зависимости владельцам, без нового UI grant, backend реализации или заявления native PASS; actual browser existing runner выполняет ROOT.

## Actual UI122 — node import admission и точная ошибка runner — 07.10.2026

ROOT запустил binary из `acfa9c5` через настоящий Chrome headless/HTTP без `--policy-transport`. Read-only просмотр `.review-local/ui-http-7Ldl7u/result.json` подтверждает 7 завершённых сценариев, включая новый engine card/workspace, AI disclosure и mobile 390×844; browser errors пусты. Восьмой all-VLESS сценарий остановился на прежней строке 390: ожидал четыре импортированных узла и получил timeout 30 секунд. `audit.jsonl` фиксирует POST `/api/v1/nodes/import` с HTTP 409; в disposable nodes каталоге сохранённого snapshot нет. Старый report не содержит response body/code, поэтому конкретный code этого actual ответа не заявлен.

Read-only код integration показывает зависимость CORE/OPS: `cmd/razvilka/main.go` создаёт `updatecheck.NewNodeHistoryAdmission()` и через `bindNodeHistoryWriteAdmission()` (`cmd/razvilka/node_history_binding.go`) ставит `(*App).NodeHistoryWriteGuard`. `(*App).nodeImport()` (`internal/app/nodes.go`) после разбора вызывает `nodestore.RequiredImportReadVersion()` → `(*App).nodeHistoryMaterialAdmission()` (`internal/app/node_history_material_admission.go`) → `(*NodeHistoryAdmission).CheckWrite()` (`internal/updatecheck/node_history_admission.go`). В последнем `checkNodeHistoryControllerIdentity()` требует Linux, root, `/opt/bin/razvilka` и совпадение установленного inode с `/proc/self/exe`; production guard на Windows отказывает до записи. Ошибка этой ветки handler возвращается как HTTP 409 `NODE_HISTORY_ADMISSION_REQUIRED`. Это объясняет несовместимость текущего Windows fixture с новым startup admission; обход guard или ослабление backend из UI не выполняется.

Узкая правка `scripts/test-ui-http-browser.mjs`: all-VLESS case захватывает настоящий ответ единственного пользовательского POST import и до ожидания state требует HTTP 200, `ok:true`, точное `accepted_nodes` и `working_routes_changed:false`. При отказе report сразу получает bounded HTTP status и whitelisted typed code; полный response body, URI/private profile и headers не печатаются. UI readback assertion сохранён после receipt. Endpoint, fixture profiles, auth, порядок mutations и transport не подменены. Дефект production UI этим actual артефактом не доказан; production UI не менялся.

Проверки этого follow-up: runner syntax RC0, `git diff --check` RC0. Новый server/browser/live прогон UI исполнителем не запускался; следующий реальный прогон и решение совместимости fixture/admission принадлежат ROOT/CORE/OPS. Прежние семь PASS не закрывают all-VLESS или весь D12.

## D12 — standalone client для coordinator-owned Linux QA — 07.10.2026

Добавлены отдельные `scripts/test-ui-real-http-browser.mjs` (client/entry point), `scripts/ui-real-http-scenarios.mjs` (повторно используемые actual HTTP/browser scenarios) и `scripts/test-ui-real-http-client.mjs` (только pure admission/privacy checks). Текущий Windows `scripts/test-ui-http-browser.mjs`, общий check.sh/build.sh и production UI/backend не изменены. Client работает с уже поднятым ROOT экземпляром; не запускает/останавливает сервер, VM или tunnel, не копирует appstate, не устанавливает binary/browser и по умолчанию не выполняет account setup. Дополнительный явный QA setup по последующей инструкции ROOT описан ниже; production router credentials не входят в этот gate.

Принятый контракт CORE: ROOT готовит отдельную Linux VM, root-процесс из реально установленного `/opt/bin/razvilka`, совпадающий с `/proc/self/exe`, и защищённые `/opt/etc/razvilka` + `/opt/var/lib/razvilka`. `-config` override не переносит NodeHistoryAdmission в другое дерево. Client не меняет эти пути и не ослабляет Windows 409; успешный import должен пройти настоящий startup admission. Ordinary Xray runtime wiring и default runtime wiring имеют разные состояния приёмки; metadata/navigation gate не объявляет их проверенными.

Параметры передаёт ROOT в приватном окружении client:

- `RAZVILKA_QA_UI_URL`: точный HTTP(S) origin QA instance, без embedded credentials/path/query/hash; допускается уже подготовленный ROOT tunnel.
- `RAZVILKA_QA_UI_FIXTURE=disposable-linux` и `RAZVILKA_QA_UI_INSTANCE`: ожидаемый публичный 32-hex instance ID из настоящего `/api/v1/panel/snapshot` данного процесса.
- `RAZVILKA_QA_UI_CHROME`: установленный локальный Chromium/Chrome; Playwright доступен через обычный NODE_PATH.
- Либо `RAZVILKA_QA_UI_SESSION`: приватный Playwright storageState file, который читает библиотека; либо пара `RAZVILKA_QA_UI_USERNAME` / `RAZVILKA_QA_UI_PASSWORD` из env для существующего QA аккаунта. Client выполняет только обычный login, не создаёт аккаунт. Secret artifact поля не инспектируются и не выводятся.
- Необязательный `RAZVILKA_QA_UI_OUTPUT`: локальная папка для bounded `ui-linux-real-*/result.json`.

Перед сценариями client проверяет реальную authenticated session, свежие snapshot/inventory с ожидаемым instance ID, opt_ready/kernel metadata, Safe Mode/live_active=false, отключённые desired/applied services, пустые nodes/groups, recovery_required=false. Autonomy должен быть заранее настроен ROOT: setup_complete=true, enabled=false, inherit_new_services=false, application/components mode=off; check_seconds 60..3600, reserve_seconds >= max(600, check_seconds). Для перенесённого AI сценария ROOT заранее включает в disposable catalog три отдельные AI записи ChatGPT/Claude/Gemini с уникальными именами, как в Windows fixture; client catalog definitions не создаёт. Чистый journal и пустой node store нужны и read-only режиму; fixture mismatch завершает проверку до изменений.

Запуск `node scripts/test-ui-real-http-browser.mjs` выполняет preflight + 8 read-only сценариев: прежние семь принятых чтений/navigation/component recovery/engine card+workspace/AI/mobile и настоящий saved Sources offline GET. Добавление `--draft-mutations` разрешает только три дополнительные сценария на данном QA store: реальный import четырёх .invalid профилей, создание защищающей группы, all-VLESS preview/commit с проверкой точных удалённых ID и сохранением других протоколов; duplicate UI Save с одним настоящим PUT и независимым readback; CAS 409 от настоящего второго HTTP writer, сохранение dirty полей, явное чтение/reset и восстановление прежнего disabled policy tuning после успешных ответов. UI bulk check confirmation отменяется, probe/Apply/package mutations не запускаются. Instance сверяется снова перед каждой управляемой mutation. В конце сверяются прежние service intent/applied state/config revision, Safe Mode и выключенная автоматика.

Нет page.route/context.route, fetch/state/DTO replacements, controlled response delivery или --policy-transport. Все HTTP статусы выдаёт целевой сервер; CAS создаётся реальной записью, а не response interceptor. CAS сценарий требует, чтобы старый редактор не получил пассивную новую редакцию до submit: если такое обновление уже отключило Save, runner сообщает failure, не подставляет старое состояние и не фабрикует 409. Отчёт хранит только фиксированные имена сценариев, pass/fail, метод/путь/HTTP status и известные typed codes; неизвестный typed code заменяется UNKNOWN_TYPED_CODE. Исключения, DTO bodies, config/private profiles, cookies, headers, credentials, DOM dumps, traces и screenshots не сохраняются.

После draft сценариев остаются два fixture узла и защищающая группа; `cleanup_required:true` передаёт ROOT обязательный disposal/reset QA instance. При failure неизвестная mutation не повторяется и автоматическое удаление/восстановление не запускается. Client закрывает только свой browser. Linux instance ID после restart изменится; повторный запуск требует свежего ROOT ID и, для данного empty gate, нового/reset store.

Локальная проверка первого client checkpoint `fae13ff`: 32 pure client admission/privacy checks RC0, syntax трёх новых модулей RC0, diff check RC0. Настоящий server/browser/VM прогон не запускался: endpoint ROOT ещё не предоставлен. Это готовый client для следующего ROOT gate, не native/runtime PASS и не закрытие всего D12; profile↔runtime service evidence остаётся отдельной принятой зависимостью CORE/VLESS/NET.

## Linux QA packet — private mount namespace и finite lifecycle — 07.10.2026

По следующей явной инструкции ROOT добавлен отдельный `scripts/launch-ui-linux-qa.sh`. ROOT готовит/запускает его только в своей disposable Linux VM; UI исполнитель VM, server и mount операции не запускал. Helper принимает root-owned absolute `--binary`, `--binary-sha256`, `--repository`, `--run-parent`, необязательные `--port` (default 18852) и `--lifetime-seconds` (default 900; 60..3600). Source binary должен быть текущим build ROOT; ожидаемый SHA передаёт ROOT, helper сверяет его до и после копии. Input/run-parent paths не должны иметь symlink или writable group/other ancestors. Требуются уже существующие защищённые directory mountpoints `/opt/etc/razvilka`, `/opt/var/lib/razvilka` и regular file `/opt/bin/razvilka`: helper не создаёт/не заменяет их в underlying VM tree.

ROOT запускает helper в собственном parent shell/session, например с заранее заданными публичными путями/хешем:

```bash
bash scripts/launch-ui-linux-qa.sh \
  --binary "$qa_binary" --binary-sha256 "$qa_sha" \
  --repository "$qa_checkout" --run-parent "$qa_parent" \
  --port 18852 --lifetime-seconds 900
```

Helper создаёт только новый private `ui-linux-qa.XXXXXXXX` под переданным run-parent (0700), копию binary (0700) и fresh config/state directories. JSON fixture строится из публичных configs repository: пустые desired/applied services, Safe Mode=true, тот же service catalog + три AI записи, sources/community catalog. Это реальные файлы отдельного QA startup, а не API/DTO fake. Token/credentials заранее не копируются. Server defaults сохраняются: cloudflare/node/feed/private restore state beside config и остальные startup stores под private canonical config/state binds. Inherited RAZVILKA path env не передаётся: небольшой Python child делает execve с новым окружением только PATH/GOMAXPROCS и `-listen 127.0.0.1:18852`.

`unshare --mount --propagation private` оставляет VM network namespace прежним. В новой mount namespace helper bind-ит fresh config/state и readonly binary на три canonical `/opt` target. После запуска он требует совпадение inode `/proc/<owned server pid>/exe` с установленным `/opt/bin/razvilka`; NodeHistoryAdmission продолжает реальные Linux/root/path/inode проверки. Helper не выполняет package install, probe, Apply, service runtime Stop, firewall/DNS/route commands или self-update. Он наблюдает существующий VM inventory; никакие positive runtime/health факты не подставляются.

Публичный stdout содержит только QA_RUN_DIR, QA_READY/QA_STOPPED status и typed failure codes; private server/launcher logs находятся внутри run directory. Helper пишет только public lifecycle identity в launcher.pid/starttime, server.pid/starttime, mount.namespace, binary.sha256 и lifecycle.status. Recovery token после startup находится в private `<run>/config/admin.token`. ROOT переносит его в локальный private token file без вывода bytes, отдельно выбирает username/password для этого fresh QA аккаунта и получает публичный instance ID из настоящего `/api/v1/panel/snapshot`. До first account setup read-only API разрешён текущим security gate; после setup для чтения нужен QA login/session.

Client расширен только отдельными флагами: `--setup-account` требует username/password env (не session) и `RAZVILKA_QA_UI_SETUP_TOKEN` — путь к local private token file. Он проверяет instance ID с этим bearer token, требует setup_required=true/using_recovery_key=true, затем один настоящий POST `/api/v1/auth/setup` и обычный login. `--prepare-policy` после проверки настоящего private/empty/Safe Mode fixture требует свежий setup_complete=false/enabled=false policy и выполняет один настоящий PUT с текущим expected_revision, setup_complete=true, enabled=false, fixed QA sources/tuning, application/components mode=off, release_safe_mode=false. Затем делает независимый readback; разрешения live runtime не выдаются. По умолчанию обе операции выключены, существующий QA аккаунт/policy не переинициализируются. ROOT может выполнить fresh полный client gate командой `node scripts/test-ui-real-http-browser.mjs --setup-account --prepare-policy --draft-mutations` с уже переданным приватным env. Token bytes/headers/account secret fields не выводятся и не сохраняются в report.

Обычный lifecycle конечен: 45 секунд readiness, затем заданный lifetime. Для раннего завершения ROOT посылает TERM только своему launcher PID из текущего owning session; если identity берётся из файлов, сначала сверяет текущие `/proc/<pid>/stat` starttime и mount namespace с сохранёнными public values. Нельзя использовать stale pidfile, pkill/killall, сигналы process group или broad process matching. Launcher при TERM/INT/EXIT сверяет server PID/PPID/starttime, посылает TERM только своему child, даёт до 8 секунд на завершение, при необходимости KILL только тому же child и обязательно wait/join до unmount. Python child перед execve ставит Linux parent-death TERM и проверяет PPID, чтобы ограничить orphan/race при смерти launcher; отдельная версия setpriv не требуется. ROOT ожидает завершение launcher через тот parent shell/tool session, где запустил его; нормальный TERM возвращает 143, finite expiry — 0.

Unmount идёт строго в обратном порядке только для успешно созданных binds, без lazy/force. После join/unmount сравниваются stat device/inode трёх underlying mountpoints до/после; mismatch или cleanup error возвращает failure. Fresh private run directory и logs не удаляются автоматически. ROOT сохраняет нужные bounded результаты и после доказанного process join/namespace release удаляет/архивирует только этот принадлежащий QA run directory; underlying VM config/state/binary остаются прежними. Client также сообщает cleanup_required при account/policy/catalog mutations. Незавершённая/unknown mutation не повторяется ради cleanup или PASS.

Локальная проверка packet: 37 pure client admission/privacy checks RC0, Node syntax client/scenarios/tests RC0, `bash --noprofile --norc -n scripts/launch-ui-linux-qa.sh` RC0, AST syntax двух embedded Python blocks RC0 без исполнения, diff check RC0. Shell проверен только синтаксически на Git Bash: Linux mount/parent-death/lifecycle и настоящий HTTP/browser ещё не исполнялись. ROOT должен review packet и выполнить actual gate с текущим Linux build; D12/native/runtime PASS этим packet не заявлен.

## Actual UI135 — fresh config revision 0 в client preflight — 07.10.2026

ROOT принял client/launcher как integration `4bb49c3` / `ad3944b` и выполнил настоящий Linux Safe Mode/private-bind startup. По сообщению ROOT account setup/login вернули HTTP 200, authenticated snapshot принят; настоящий status содержит safe_mode=true/live_active=false/revision=0/applied_revision=0/pending_changes=false. Read-only bounded `.review-local/ui-linux-real-6tWwiI/result.json` подтверждает failure `QA_PRIVATE_SAFE_MODE_REQUIRED` на prepare-disabled-QA-policy, browser_errors=0. Account setup уже выполнен; policy setup запись ещё не отправлялась. Production UI bug и native runtime PASS этим результатом не заявлены.

Узкая ошибка client: `realHTTPPrivateFixture()` ошибочно требовал config revision >=1. В `internal/config/config.go` `Config.Revision` — uint64 с omitempty; `Config.Default()` не задаёт revision, а fresh Load/Save оставляет 0 до явной mutation. Публичный config.example.json также не содержит revision. Client теперь принимает safe integer >=0, сохраняя точные проверки Safe Mode/live_active, отключённых desired/applied services, empty nodes/groups, instance/inventory и recovery. Изменён только client preflight; production config revision не повышается ради fixture, production progress receipts и отдельные policy/service revision контракты не менялись.

Regression: fresh config/applied revision 0 принят при остальных точных условиях; negative/fractional/unsafe/missing revision отклоняются. 42 pure client admission/privacy checks RC0, syntax client/tests RC0, diff check RC0. Новый HTTP/browser/VM прогон не запускался. ROOT повторяет на том же известном QA аккаунте с `--prepare-policy --draft-mutations`, без `--setup-account` и без env `RAZVILKA_QA_UI_SETUP_TOKEN` (token file повторно не читается); account mutation не повторяется, policy пишется только после собственного verified preflight/expected revision. Actual acceptance остаётся за ROOT.

## Actual UI135b — Sources navigation до первого HTTP — 07.10.2026

ROOT повторил настоящий Linux HTTP/browser gate с client integration `82d53d2` и embedded Linux product source `ad3944b`. Read-only bounded `.review-local/ui-linux-real-mDAvMH/result.json` подтверждает восемь passed steps (preflight + семь прежних read-only сценариев), browser_errors=0, затем TIMEOUT в saved Sources. В report нет ни одного запроса `/api/v1/sources*`. Единственные non-GET — обычный login POST 200 и explicit QA policy setup PUT 200; import/group/delete и draft policy сценарии ещё не начинались. Account повторно не создавался, disabled policy уже инициализирована; неизвестных node mutations для replay нет.

Причина находится в standalone client: `navTo(page,'sources')` искал `.nav[data-view="sources"]`, которой нет в текущем `index.html`. `sources` принадлежит Settings в `interface-model.js`; пользовательский переход — кнопка «Списки сайтов» в advanced disclosure `#view-settings`, обрабатываемая настоящим `consoleNavigate`. Сценарий теперь кликает sidebar Settings, раскрывает соответствующий details только если он закрыт, кликает настоящий `[data-rz-nav="sources"]` и ждёт currentView/обычного source GET readback ready. GET-only boundary начинается до navigation. Production UI/handler, API, state и ответы не менялись и не подставлялись.

Локальная проверка: 42 pure client admission/privacy checks RC0, Node syntax client/scenarios/tests RC0, diff check RC0. Новый server/browser/VM прогон здесь не запускался. ROOT завершает прежний finite fixture и выполняет следующий actual gate на свежем QA store; настройки account/policy выполняются только для подтверждённого fresh fixture. Native/runtime PASS и завершение всего D12 этим client исправлением не заявлены.

## Actual UI140 — регистр protocol в финальном node readback — 07.10.2026

По сообщению ROOT прежний UI135 fixture завершён с QA_STOPPED=0/RC0. Новый actual Linux gate source `2475c2c` прошёл fresh setup/login и девять report steps (preflight + восемь read-only сценариев), включая saved Sources actual GET после исправления navigation. Read-only bounded `.review-local/ui-linux-real-oKJCJS/result.json` подтверждает browser_errors=0, cleanup_required=true и ASSERTION_FAILED в all-VLESS сценарии после последнего verification GET nodes 200. Перед ним import POST 200, group POST 201, preview/commit POST 200. Сценарии duplicate Save и policy CAS ещё не начинались. Записи или удаления здесь не повторялись.

ROOT отдельно подтвердил read-only summary: ровно два узла с uppercase protocol `VLESS`/`SHADOWSOCKS`, одна группа содержит оставшийся VLESS, safe_mode=true/live_active=false/revision=applied_revision=0. Узкая ошибка standalone client: две финальные проверки `remaining.nodes` сравнивали protocol с lowercase `vless`/`shadowsocks` без нормализации. Настоящий producer `internal/nodestore/document.go:snapshot()` присваивает `strings.ToUpper(material.Type)`; первая lowercase проверка не принимает сохранённый VLESS. Прежний Windows runner и первоначальный import readback в новом client уже использовали `String(...).trim().toLowerCase()`. Обе финальные проверки теперь используют ту же нормализацию; количество двух оставшихся узлов, одной группы с защищённым участником, точный ID участника, по одному VLESS/Shadowsocks, matching deleted IDs и working_routes_changed=false остаются обязательными. API/producer/production UI не менялись.

По следующей инструкции ROOT client добавляет только allowlisted static checkpoint ID в failure.stage, сохраняя прежний failure.code для assertion/timeout/HTTP rejection. Например UI_NODE_REMAINING_VLESS и UI_NODE_REMAINING_SHADOWSOCKS различают финальные проверки; UI_POLICY_CAS_STALE_EDITOR_READY обозначает passive read, уже оградивший stale редактор; отдельные IDs отмечают second writer, настоящий CAS receipt, сохранение dirty полей, explicit read/no replay/reset и restore readback. Private actual/expected values, exceptions, DTO/DOM, headers и credentials по-прежнему не сохраняются. Unknown/dynamic diagnostic ID отклоняется до action. Следующие duplicate Save/CAS assertions сверены с `autopilot-settings.js` и `autonomy_api.go`: inputValue строковые, check_seconds числовой, 409 message содержит «изменились», explicit read с dirty draft оставляет Save disabled/«Ваши поля сохранены», reset загружает 300. Их поведение ещё требует настоящего ROOT gate; second writer не перехватывается, stale UI при пассивном обновлении не подменяется.

Локальная проверка: 47 pure client admission/privacy checks RC0, включая static ID/result, assertion и timeout privacy, сохранение HTTP code и rejection dynamic ID до action; 24 существующих pure policy-editor tests RC0; Node syntax client/scenarios/tests RC0, diff check RC0. Actual gate здесь не повторялся; свежий fixture, read-only сверка оставшихся данных и disposal принадлежат ROOT. Успешные HTTP ответы не записаны как завершённый all-VLESS PASS до повторного matching readback; весь D12 и native/runtime доказательства остаются открытыми.

## Actual UI144 — snapshot identity facts в точке отказа — 07.10.2026

По сообщению ROOT UI140 fixture завершён. Новый fresh actual Linux gate source `68b25bb` имеет девять passed report steps, browser_errors=0, затем failure.stage=UI_NODE_IMPORT/code=QA_INSTANCE_MISMATCH_OR_STALE. Read-only bounded `.review-local/ui-linux-real-DcQVfX/result.json` показывает последним verification GET `/api/v1/panel/snapshot` 200, без POST nodes/import, group или delete; non-GET выполнены только fresh account setup/login и disabled policy setup, все 200. Отказ возник на `beforeMutation()` до import action. Никакая запись здесь не повторялась.

ROOT отдельно прочитал текущий snapshot того же UI144: data_age_ms=453/max_age_seconds=900. Это последующее чтение, а не envelope в точке failure; оно не устанавливает, какая проверка отказала. `StartPanelSnapshots()` запускает publisher с периодом 2 секунды; `panelSnapshotAt()` задаёт lifetime 900 секунд и выставляет retained при age>=10 секунд, Exclusive или Fenced. Client по-прежнему требует точный ожидаемый instance/schema/dataplane, state=available и age<min(server limit,120000ms). Причина actual отказа (instance, shape, retained/admission или возраст) не предположена по одному позднему чтению.

В bounded client report добавлен `identity_checks`: до проверки каждого verification snapshot/inventory GET сохраняется только path и whitelist metadata — schema_valid, instance_matches, разрешённый state, dataplane_valid, числовые data_age_ms/max_age_seconds, age_valid/within_age_limit, разрешённый admission_state и boolean Exclusive/Fenced. Максимум 64 последних записей; actual/expected instance strings, publication data, operation labels, DTO bodies, headers/tokens/credentials не записываются. Теперь последняя identity запись относится к самому ответу, который отказал перед mutation, и вместе со static checkpoint позволяет отличить mismatch от transient retained и устаревания. Gates и лимиты, порядок запросов, producer и mutation действия не менялись; retries или ожидание admission не добавлялись без actual evidence.

Локальная проверка: 49 pure client admission/privacy checks RC0 (включая projection свежего 453/900 envelope и отбрасывание private/unrecognized metadata), Node syntax client/scenarios/tests RC0, diff check RC0. Actual HTTP/browser/VM здесь не запускались. Следующая точная diagnosis и finite fixture disposal остаются за ROOT; native/runtime PASS и завершение D12 не заявлены.
