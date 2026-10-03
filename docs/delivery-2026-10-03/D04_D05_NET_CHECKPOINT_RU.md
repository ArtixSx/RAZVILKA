# NET checkpoint: D04 и ограниченный шаг D05

Дата: 03.10.2026. Исполнитель: `/root/d04_wireguard`.
Вход: `76d94b6`; worktree `worktrees/d04-wireguard`, ветка `feature/delivery-d04-wireguard`.
Никаких изменений роутера, VM, общих портов или GitHub этот исполнитель не выполнял.

## Что реализовано

- D04: сокеты кандидата привязаны к его устройству через SO_BINDTODEVICE; временное RPDB-правило содержит source **и oif**. Совпадающий Address рабочего интерфейса не разрешает использовать его путь. Поддержаны IPv4/IPv6, общий helper TCP/UDP.
- Временный интерфейс всегда создаётся native-путём с точным именем; connected routes не добавляются в main. Очистка удаляет точный default и правило, без flush таблицы. На холодном Linux отсутствующая FIB-таблица допускается только при соответствующем ответе ядра.
- Инициирующая сервисная проба предшествует handshake также после Activate нового live-интерфейса. Sources не удаляются и не подменяются адресом LAN-клиента. Keepalive необязателен. Смена WARP-порта использует `wg set peer endpoint`, сохраняя интерфейс/маршруты.
- Generic WireGuard имеет отдельное приватное хранилище `internal/wireguardprofile`: несколько явно импортированных профилей, секреты не выводятся в metadata/fmt/JSON, строгая проверка конфигурации, CAS по revision, отказ от чужого существующего файла. Хуки, дубликаты и AWG-поля отклоняются. Generic WG не получает WARP fallback ports.
- `WARPWireGuardAdapter.Profiles` принимает provider с `Get(ctx,id)`. Маршрут `wireguard:<id>` сохраняет выбранный профиль/revision в snapshot. Stage/Activate/Commit проверяют неизменность. Два разных profile ID в одном плане одного интерфейса отклоняются. Named-профили не перезаписываются активацией/откатом.
- D05 endpoint **только Generic WireGuard**: приватная запись связывает hostname, выбранный IP, срок DNS-ответа, WAN device/gateway/source и точные rule/route tuples с digest runtime. Транспорт получает mark `0x04000000`; правило priority 52 совпадает с полным mark и единственным endpoint, lookup 206. Host-route использует точные gateway/device/source, proto static, metric 1. Глобальное endpoint-исключение не добавляется.
- Зарезервированы согласованные координатором пары priority/mark: WARP 50/0x01000000, AWG 51/0x02000000, WG 52/0x04000000. Новые pin lifecycle для WARP/AWG ещё не включены.
- Перед запуском/восстановлением проверяется WAN и DNS lease. Без TTL-aware callback ответ считается непригодным для кэширования и повторно разрешается. Изменившийся IP/WAN требует новой транзакции кандидата; работающий LKG не пересоздаётся этим решением. Expiry не продлевается выдуманным fixed TTL.
- Stop/rollback endpoint-пина проверяют полные tuples и сохраняют foreign/ambiguous записи. Активный Generic WG дополнительно сверяет public key и socket mark перед удалением интерфейса. Runtime Stop не удаляет каталог профилей.
- Engine Lab распознаёт endpoint rule/route только через callbacks к приватному state. Новый `OwnsPolicyRoute` необходимо подключить в application wiring рядом с `OwnsPolicyRule`.

## Коммиты

- `400c29f`: D04 device-bound candidate, точная очистка, Linux harness.
- `5caa251`: холодный live handshake и смена endpoint без потери маршрутов.
- `3f7b4d8`: разделение Noise-сессий native fixture между семействами.
- `633409e`: named Generic WG profiles и revision selection.
- Endpoint lifecycle и исправления изоляции unit fixtures — следующий checkpoint-коммит с этим документом.
- `65fe87d` — только cherry-pick **коммита координатора `ab00695`** для локальной проверки: общая очистка default routes без flush. Повторно переносить его в ветку координатора не нужно.

## Проверки этого исполнителя

Production go.mod/go.sum не менялись. Использован `C:/Projects/RAZVILKA/tools/go/bin/go.exe`.

| Проверка | Результат |
|---|---|
| `go test ./internal/dataplane ./internal/enginelab ./internal/wireguardprofile ./internal/tunnelcheck ./internal/awgprofile` | RC 0; перед финальными узкими ownership-правками |
| `go test ./internal/dataplane ./internal/enginelab ./internal/wireguardprofile -run 'WG\|WARP\|WireGuard\|CloudflareScan\|Profile\|Policy' -count=1` | RC 0 после финальных правок |
| `go vet ./internal/dataplane ./internal/wireguardprofile ./internal/enginelab` | RC 0 |
| Linux/amd64 `go test -c ./internal/dataplane` | RC 0; это сборка, не Linux runtime |
| `git diff --check` | RC 0 |

Unit endpoint-сценарии проверяют Stage/Activate/Commit/Stop, восстановление после потери kernel-state, TTL/noncacheable DNS, смену WAN, IPv6 endpoint, сохранение foreign near-match и чужого интерфейса при failed creation. Это stateful fixtures, **не native endpoint/HIL**.

Координатор сообщил RC 0 native-round-03 для D04 TCP/UDP IPv4/IPv6 в двух собственных namespace. Он запускал Linux harness эксклюзивно в VM. AppArmor `wg` запрещает /tmp; для проверки он использовал принадлежащий тесту TMPDIR под /etc/wireguard, не выключая защиту. Первый native прогон выявил эту средовую проблему, второй — переиспользованную Noise-сессию теста.

Linux CI координатора после установки настоящего wg также обнаружил ранее скрытую зависимость fixtures от host PATH: два WARP unit-теста не задавали NativeOnly, AWG receipt фиксировал "wg" вместо выбранного CLI. В этом шаге fixtures задают NativeOnly и отдельный mock CLI path; production ownership не ослаблена.

## Незакрытые требования для следующего чата NET

1. **Одинаковые ключи/peer могут повлиять на LKG на удалённой стороне.** Linux proof подтверждает локальную изоляцию candidate и отрицательную проверку wrong key. Он не подтверждает пригодность live после успешного candidate с тем же peer/key: новый Noise session/endpoint roaming способен вытеснить рабочую сессию. Между семействами fixture сбрасывает только свой live-интерфейс. Нужны live-after-success/wrong-key проверки и запрет такой одновременной проверки либо согласованный проверяемый протокол восстановления. Не объявлять canary полностью недеструктивным для same-peer LKG.
2. Подключить Store/provider к application/API и выбору резервов. Сейчас несколько профилей/резервов доступны как модуль и adapter callback; пользовательский CRUD, active/transaction-selected delete guard, scheduler резервов и UI не подключены.
3. Подключить `EndpointResolver(ctx,host) -> addresses, expiresAt, error` к существующему DNS owner с реальным минимальным TTL всей CNAME-цепочки; `OwnsPolicyRoute` — к Engine Lab. До этого TTL fallback всегда повторно разрешает hostname перед стартом/восстановлением.
4. Native endpoint lifecycle ещё не запускался: нужны exact marked-route/readback, Stop, WAN/endpoint changes, restart/reboot/rollback и foreign fixtures на Linux/реальном устройстве. Требуется iproute2 JSON; BusyBox без `ip -j` отклоняется, его совместимость не заявлена.
5. Полная crash/power-cut приёмка не выполнена. Между kernel mutation и записью transaction marker остаётся окно неопределённости. Отсутствующий marker не разрешает удалять потенциально чужой ресурс; повторное использование занятого tuple отклоняется. Требуется общий recovery/journal этап, не автоматическое присвоение orphan.
6. Рабочий state старой схемы не получает новые endpoint-права неявно. Новый lifecycle WARP/AWG, проверка AWG module/ABI/server, service/LAN forwarding/NAT, DNS/LAN exclusions, NFQWS2 и D14 остаются вне этого checkpoint.
7. Native harness доказывает локальные HTTP/TCP и UDP echo пути. Он не доказывает настоящий клиент LAN, весь интернет, media/voice, 24h/72h устойчивость или hardware ARM/MIPS.

После этого checkpoint исполнитель остановлен для общего integration gate и передачи работы в отдельный чат NET.
