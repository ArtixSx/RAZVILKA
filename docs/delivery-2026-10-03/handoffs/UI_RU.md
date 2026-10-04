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

Положительный regression проходит через настоящие UI handlers Stage → Validate → review-bound engine Apply → свежий TestLab probe, затем production renderer отмечает четыре шага. Отдельно проверены старый PASS после Apply, wrong digest/plan/revision/service/engine/network/path, отрицательный контроль, expiry, Stop, pending, отмена, смена профиля и отсутствие hash. Это controlled public DTO fixture, не native/router/network proof. Проверки из check.sh до native supervision: 78/78 RC0 (51 проверочный script и 27 syntax/build checks), журнал `.review-local/ui-progress-frontend-checks.log`. Go build embedded UI RC0. Реальный Windows HTTP/browser regression: 19/19 RC0, `.review-local/ui-http-WX3kk8/result.json`, browser errors0, config unchanged, policyTransport=false; fixture остановлен.

D12 целиком не закрыт: существующие Validation/TestLab/Apply DTO не связывают trusted service evidence с отдельной engine runtime generation; для sensitive live FileView отсутствует публичный hash. При отсутствии подтверждаемой identity UI не отмечает завершение. Named WG CRUD revision из NET `b60d84b` — идентификатор сохранённого syntax-only профиля, не service/Apply authority. Для полного per-engine пути CORE/VLESS/NET должны предоставить принятую привязку profile revision/hash + runtime generation в своих фактах; UI новую backend authority не добавляет. ARM/native положительный путь здесь не заявлен.
