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

- [Главная — 1280 × 900](../../../.review-local/ui-http-MyMyJX/01-home.png): отдельная тестовая копия catalog/config, Safe Mode включён, автоматика выключена, native engines отсутствуют. Показаны настоящие пустые/ещё не загруженные данные, успех не имитирован.
- [Обходы/recovery — 1280 × 900](../../../.review-local/ui-http-MyMyJX/02-component-recovery.png): настоящие HTTP и интерфейс; только `upgrade-started` журнал является одноразовой заготовкой. Видны неизвестный исход, версии, чтение и отсутствие replay.
- [Подключения — 390 × 844](../../../.review-local/ui-http-MyMyJX/03-connections-narrow.png): настоящая пустая библиотека в отдельном состоянии; узкий экран с закрытым меню. Full-page PNG длиннее viewport. Общие счётчики, controls и сообщения взяты из приложения.

Абсолютный каталог всех снимков: `C:/Projects/RAZVILKA/worktrees/sol-ui/.review-local/ui-http-MyMyJX/`. Поля `screenshots[].source` и viewport также записаны в `result.json`. PNG и частные run logs остаются игнорируемыми локальными артефактами.

OPS WIP контракт прочитан по указанию координатора: `accept-installed-idle`, terminal `accepted-installed-idle`, `installed_idle_accepted=true`, `live_accepted=false`; exact version/config + trusted inactivity/quiescence. В текущей интегрированной базе action/phase ещё нет, UI не отправляет его по догадке. Будущая idle отметка должна означать установленную неактивную версию, не live и не сервисный PASS. `awaiting-rollback-acceptance` уже имеет отдельную проверку результата отката; candidate callback не используется UI как доказательство принятия.

Эта порция готова к review; весь D12 не закрыт. Следующие шаги: подключить принятый CORE/OPS idle contract, затем полный card workflow, массовые подключения/AI и legacy-дубли. Linux/native/HIL/race/weak-router CPU/RSS/render-cost остаются за координатором.
