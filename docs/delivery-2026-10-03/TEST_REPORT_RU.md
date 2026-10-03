# Фактическая проверка — 03.10.2026

## Основание

Полная копия распакована из пользовательского RAZVILKA-main.zip. Комментарий архива и запрошенный main: 817783493f0c2784ccc70aa73868cd64e9437634. Сохранены go.mod/go.sum/VERSION. .git создавался только локально для diff от неизменённого входа и не входит в поставку.

## Результаты

| Набор | Фактический результат | Граница |
|---|---|---|
| Исходный frontend | 50/50 команд Node из scripts/check.sh | До внесения изменений |
| Изменённый frontend | 53/53 команды | Существующие и новые UI-контракты, модели, bundle и CSS |
| JS/shell syntax, gofmt, git diff --check | 55/55 команд | Статика, не исполнение shell на роутере |
| Go-core | 59 test-функций, go test -v; race×3; go vet | Полные выбранные файлы из рабочей копии; временный go1.23-модуль |
| VLESS adapters | 34 test-функции; race×3; vet | Точные функции + явно объявленные модели App/NodeStore/IO |
| Maintenance adapters | 44 test-функции; race×3; vet | Точный adapter/config-method + test doubles Store/package IO |
| Go embedded web-layout | 21/21 test-функций; race×3; vet | Настоящие assets и полный web_layout_test.go, только embed declaration вместо main/server |
| Chromium fixture | 16/16 проверок, 0 uncaught, 0 uiRenderIssues | Настоящие JS/CSS, но искусственные API/storage/EventSource |
| Go1.26.5 full-project CI | BLOCKED / not_run | Загрузка toolchain не состоялась: DNS/network refused |
| Native engines / opkg / router / HIL / soak | not_run | Ни один живой обход или клиент здесь не испытывался |

**59/34/44 пересекаются: это НЕ 137 уникальных проверок и НЕ 137 новых тестов.** Логи каждого набора и manifest точных скопированных исходников приложены отдельно.

## Воспроизводимость

В CODEX_REVIEW/checks лежат runner-скрипты. Каждый читает полную рабочую копию и проверяет отдельные production-файлы в новом временном модуле; исходный go.mod не трогается. Test doubles не маскируются под приложение.

```sh
python CODEX_REVIEW/checks/run_frontend.py RAZVILKA CODEX_REVIEW/logs/js-repeat
python CODEX_REVIEW/checks/run_core_tests.py RAZVILKA
python CODEX_REVIEW/checks/run_embedded_layout.py RAZVILKA
python CODEX_REVIEW/checks/run_adapter_tests.py RAZVILKA vless
python CODEX_REVIEW/checks/run_adapter_tests.py RAZVILKA maintenance
python CODEX_REVIEW/checks/browser_fixture.py RAZVILKA CODEX_REVIEW
```

Полный приёмочный gate у Codex — штатный `go version`, `go mod verify`, `sh scripts/check.sh`, затем настоящий HTTP-сервер и native/lab. Временная совместимость отдельных модулей с Go1.23 не доказывает компиляцию всей RAZVILKA.

## Что проверял браузер

Использован системный Chromium и Playwright. Среда блокирует навигацию к локальному HTTP и тестовому hostname (ERR_BLOCKED_BY_ADMINISTRATOR). Политику не обходили. Стенд загружает HTML на about:blank и встраивает **точные** production scripts/styles; только API, storage и EventSource заменены.

Проверены отсутствие writes при открытии Home, applied-счётчики, видимость настройки, явный PUT параметров и сохранение источников, сохранность грязного поля при новой ревизии, запрет конфликтующей записи, 390px без горизонтального переполнения, переходы 6 разделов, отсутствие случайных PUT/POST и JS-исключений.

Поэтому не проверены настоящий login/session-cookie/CSRF/CSP/HTTP routing, сеть роутера, SSE-disconnect серверной реализации. Скриншоты показывают тестовые YouTube/Telegram/ChatGPT состояния, а НЕ результаты обходов.

## Изменения старых тестов

Ожидаемое число основного меню обновлено с 7 до 8. Сохранены все 21 внутренних view/ID. Тесты зависимых виджетов теперь выбирают соответствующий view явно; скрытая форма не обязана перерисовываться. Изменена устаревшая подпись latency, оставлены проверки 401, late reply, cancellation, confirmation и отсутствие ложного Apply.

Первый перенос выявил падения прежних контрактов, скрытый render engineconfig и ошибку разметки details. Они устранены до итогового 53/53 и браузерного прогона. Проверки не вырезались ради зелёного результата.

## Ограничения отчёта

Не измерялись CPU/RSS на пользовательском устройстве. Число 6 вместо23 относится только к списку запросов главного загрузчика на Home, не ко всей странице и не к коэффициенту ускорения. Не утверждается, что все legacy-таймеры удалены. Отдельные unit/helper-тесты warm failover не заменяют интеграцию worker B→rollback→C.

Дополнительно полный существующий Go web_layout_test.go запущен в независимом embed-стенде. Он выявил старую подпись «Пинг · TCP»; требование обновлено на два явных показателя «TCP до сервера» и «Ответ через узел», остальные проверки сохранены. После правки 21 функция, race×3 и vet проходят. main.go/backend в этом стенде не компилировались.
