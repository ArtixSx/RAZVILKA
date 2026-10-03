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
