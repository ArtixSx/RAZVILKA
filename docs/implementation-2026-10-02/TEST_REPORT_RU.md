# Отчёт фактической проверки

## Среда и границы

Go1.23.2 linux/amd64, Node22.16.0, Python3.11+, Git2.47.3. Проект требует go1.26.0/toolchain1.26.5; production go.mod НЕ менялся. Попытка получить toolchain завершилась сетевой ошибкой, лог toolchain-attempt.log. Полный checkout через Git/archive в runtime недоступен; использован подключённый GitHub для чтения.

**Полный CI, компиляция всех пакетов вместе, установщик на настоящем устройстве, Xray/Sing-box/WG/AWG native peers, HIL/soak — NOT_RUN.** Нет независимого второго автора-reviewer; есть повторная самопроверка и отрицательные controls. Подагенты не запускались.

## Выполнено

1. `python tests/run_isolated.py`: 41 test-функция (62 с учётом именованных subtests) для прежнего H00; `go test -v -count=1 ./...`, `go test -race -count=3 ./...`, `go vet ./...` — exit0. Полные новые dependency-free модули, точные функции config/netresolve/resources; App/Store/package IO моделируются. Это не полное приложение. Фактические журналы isolated-1/2/3.log и isolated-results.json.
2. `python harness/run.py`: 26 функций. Полные nodequality и неизменённый upstream evidence.go (Git blob проверен), точный изменённый autonomy_ranking.go, настоящие новые adapters. App/NodeStore/catalog/runtime shape и network hooks — явные doubles в harness/stubs. Те же test/race×3/vet — exit0. Есть настоящее loopback TCP-соединение для выбора IP, НЕ VPN. Логи new-go-1/2/3.log.
3. `node overlay/scripts/test-node-measurements-ui.mjs tests/node_metrics_model.js`: 23 сценария — exit0. Модель дословно совпадает с payload node-browser.js. При запуске в полном checkout тест читает реальный node-browser.js. DOM, layout, старые UI-тесты и полный frontend bundle здесь не запускались.
4. `python tests/test_assembler.py`: 16 тестов — exit0. Реальный локальный синтетический Git: исходная копия не меняется, новый checkout/diff/ZIP создаются; другой HEAD, dirty, overlay conflict, symlink, несовпадающий/неоднозначный anchor отклонены. Это не получение настоящего полного RAZVILKA.
5. `python tests/mutation_checks.py`: 4 намеренные регрессии обнаружены ожидаемыми падающими тестами: возврат неверного IP; Available=true после неизвестного контроля; штраф за ERROR; игнорирование TTL. Ненулевой exit является ожидаемым результатом мутанта, немутированный код тесты проходит.
6. gofmt новых Go и изменённых доступных полных Go-файлов, проверка JS-синтаксиса, структурный валидатор пакета, SHA256 и целостность ZIP.

## Что не означают результаты

Модельные тесты не доказывают действующий dataplane, аппаратную совместимость, результат реального igareck source, корректность всех integration calls или безопасность полного reboot. Приватная схема неизменна, но полный downgrade и обновление исходниками ещё не испытаны. Тесты отдельных пакетов не заменяют проверку их объединения на штатном Go.

Новый node_measurements_api_research_test.go намеренно предназначен для полного App, а не включён в модельный harness; его статус NOT_RUN здесь. Остальные repo integration тесты H00 тоже сначала выполнить в целом checkout. Новые тесты не должны использоваться для сокрытия прежних ошибок baseline.

## Что запустить первым в Codex

Проверить чистую базу текущего проекта на требуемом toolchain; затем отдельную копию с этим payload. Сопоставить прежние ошибки baseline и новые регрессии. Выполнить `gofmt -l cmd internal`, `go test ./...`, `go test -race ./...`, `go vet ./...`, все JS и shell checks через `sh scripts/check.sh`. Отдельно изменённые ranking tests: fixture «fail» теперь означает remote BLOCKED, не поломку проверяющего ERROR; старые lifecycle milliseconds не сортируются как RTT. Это осознанная коррекция semantics, не удаление негативного теста.
