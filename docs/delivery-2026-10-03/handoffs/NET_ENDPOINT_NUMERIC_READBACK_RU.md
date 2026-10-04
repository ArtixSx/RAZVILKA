# NET: точный числовой readback WG endpoint

Законченная порция для обязательного `ip -N` общего default-dependency guard.
Рабочая ветка `sol/net-20261003`. Содержит только NET endpoint JSON reader,
его регрессии и исправление dispatch тестового WG runner. Остальная WG network
policy / owned-runtime canary / D05 catalog preparation остаётся отдельным WIP.

## Что исправлено

`numericPolicyReadRunner` CORE передаёт `-N` и в RPDB, и в JSON host-pin readback.
Старый тестовый runner пропускал этот аргумент в неправильную ветку и возвращал
`ok` вместо JSON; реальный iproute2 дополнительно возвращает числовой protocol
и scope. Обе причины исправлены без снятия `-N`.

Endpoint reader принимает точный protocol `static`, `4` или `"4"`. Если scope
присутствует, маршрут через gateway требует global/universe/0, direct маршрут
без gateway — link/253. Неизвестные протоколы, чужой scope, дробные/экспоненциальные
числа, нек canonical decimal строки, null и неподходящие JSON-типы не дают
ownership. Старый допустимый JSON без scope сохраняется. Остальные поля полного
pin tuple, числовая таблица, приоритет, mark и отсутствие дополнительных селекторов
по-прежнему обязательны. JSON `null` не считается отсутствующей таблицей.

WG fixture снимает начальный `-N` для dispatch, сохраняя исходную команду в call
log и numeric режим общего RPDB fixture. IPv6 после `-N` остаётся IPv6. В numeric
JSON fixture возвращает protocol=4 и scope=0/253, поэтому тест не скрывает
production несовместимость строковым `static`.

## Проверки

- До fixture исправления общий WG receipt набор отказывал при endpoint JSON:
  `ip -N -j route show table 206 exact ...` попадал в fallback `ok`.
- После исправления: `go test ./internal/dataplane -run
  '^TestWGEndpointNumeric|^TestWGPolicyReceipt|^TestWGEndpointCaptured|^TestWGEndpointExact'
  -count=1` — PASS, обе семьи, числовые/string representations, foreign/malformed
  protocol/scope и полноценные receipt rollback/cleanup сценарии.
- Windows `go vet ./internal/dataplane` — RC 0.
- Linux amd64 dataplane test cross-compile и Linux vet — RC 0.
- Native kernel, Linux execution, race и router/HIL новой порции не запускались
  NET; приёмочный runtime выполняет только Root.

Зависимость: принятый CORE numeric guard `89966b3` и fixture foundation
`7745a0b` (включает `5454c3a`/`788ea34`). Для этого исправления не требуется
включать незавершённый NET network-policy WIP или held CORE EndpointTable порцию.
Законченный коммит может переноситься отдельно. Следующая задача NET — actual
dedicated transport table occupancy/readback и network lifecycle.
