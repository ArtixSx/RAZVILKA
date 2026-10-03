# D02: отдельная проверка Xray

Исходная база: `76d94b6`. Реализация: ветка `feature/delivery-d02-xray`, первые изменения `91c3b2b`, строгие параметры `d3360da`. Общие app/store/worker-контракты и подключение диспетчера остаются у координатора.

## Подключение

- `dataplane.NewExactXrayNodeCheckerSlots(root, slots)` создаёт отдельный Xray checker с 1–4 слотами. Нужен собственный абсолютный каталог; порты по умолчанию 19185–19188 не пересекаются с прежним Sing-box checker.
- `EngineID()` возвращает фиксированный движок. Запрос остаётся `NodeCheckRequest`: в `Outbound` передаётся один приватный канонический outbound NodeStore без tag/detour. Формат результата не менялся; его путь строго `xray:<node-id>`, `Evidence.Engine=xray`.
- Для проверки способности компилятора: `providerprofile.VLESSProfileFromJSON(material)`, затем `CompileXrayConfig(profile)`. Ошибка означает отсутствие поддержки этого профиля; Xray не должен заменять незнакомый транспорт на TCP. `ErrExactNodeUnsupported` возвращается до DNS/слота и не должен создавать запись о неудаче узла.
- У приложения остаются самостоятельные обязанности: точная проверка engine/path перед сохранением и применение только тем исполнителем, который получил доказательство. Доказательство Xray не разрешает применение через Sing-box. Диспетчер не должен увеличивать общую параллельность двух движков сверх установленного лимита.

## Реализация

Проверка использует настоящий `xray run -test -config` и `xray run -config`. В конфигурации ровно один VLESS outbound, локальный SOCKS без UDP; нет импортированных DNS, routing, API и DIRECT. В endpoint подставляется именно успешный IP предварительного TCP-теста, исходное имя TLS сохраняется. Слоты, процесс, PID receipt, конфигурация, владелец сокета, сетевой epoch, одинаковый HTTPS endpoint прямого/проксированного контроля и сервисные запросы по имени/IP остаются обязательными.

Перед удалением временного процесса receipt проверяется повторно. Изменение процесса/конфигурации отменяет положительный ответ, очищает адрес выхода и делает evidence неопределённым. Неподтверждённая очистка блокирует новые проверки до Recover; чужой PID не считается своим.

Канонический Xray compiler поддерживает TLS и REALITY поверх RAW/TCP, с `xtls-rprx-vision` или без flow. URI `type=raw` нормализуется в TCP. XHTTP/splithttp, другие транспорты, mux, неотображённые TLS ограничения и несовместимые опции отклоняются. Неизвестные поля VLESS/TLS, сертификатные pins/пути и chaining теперь не пропадают при импорте. Это намеренно меняет прежнее поведение удаления `certificate_path`: такой профиль требует поддерживаемого способа сохранения доверия.

## Проверки

Windows/amd64, Go 1.26.5, production go.mod без изменений:

| Команда | Результат |
|---|---|
| `go test ./internal/providerprofile ./internal/dataplane ./internal/nodestore ./internal/nodequality` | RC 0 |
| `go vet ./internal/providerprofile ./internal/dataplane` | RC 0 |
| `go test ./internal/app -run 'Test.*(Xray\|VLESS\|Profile)' -count=1` | RC 0 |
| `go build ./...` | RC 0 |
| `GOOS=linux GOARCH=amd64 go test -c ./internal/dataplane` | RC 0, только сборка |

Нативный сценарий запускает только координатор: `RAZVILKA_XRAY_NATIVE=/absolute/path/xray GO=/absolute/path/go sh scripts/check-xray-native.sh`. Нужны Linux, unshare, iproute2 и право создать network namespace; Go dependencies должны быть предварительно доступны. Сценарий не скачивает runtime и не изменяет маршруты, firewall или uplink существующего namespace.

В новом namespace только loopback и три локальных адреса публичного формата. Настоящие Xray server/client, временный CA, HTTPS сервер и TLS 1.3/H2 REALITY target проверяют весь checker. Адрес выхода определяется по настоящему source IP сокета на fixture. Resolver/CA/HTTPS measurement endpoints — тестовые; process, SOCKS, TLS, request parsing и receipt — настоящие.

Первый Linux запуск координатора (`native-xray-01.log`) подтвердил TLS positive path и остановку/перезапуск сервера/неверный UUID. Общий RC 1: тест слишком узко ожидал код ошибки при кратковременном zombie после kill; REALITY не завершил egress. Следующий harness commit `ee3a583` учитывает fail-closed cleanup fence и ждёт завершения фонового REALITY target discovery. Его успех здесь пока не заявлен. Upstream detector читает target до пяти секунд и намеренно проверяет реакцию на CCS: [исходник версии зависимости Xray 26.3.27](https://github.com/XTLS/REALITY/blob/9234c772ba8f/record_detect.go).

Это не доказательство выхода в Интернет, TUN, выбранного и контрольного LAN-клиента, перезапуска приложения/роутера или аппаратного rollback. Эти подэтапы D03 остаются отдельными от native fixture.
