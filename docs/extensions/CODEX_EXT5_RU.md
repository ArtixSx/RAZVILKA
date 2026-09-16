# Codex: продолжить единую EXT5, не собирать её из старых фрагментов

Использовать полный source или Git bundle из EXT5. База — UPDATE4
`98b37263aa6446679c88f5e222f94e39e2e27eb6`. Точный commit кандидата записан в COMMIT
внешней поставки и build metadata. Проверить git status и AGENTS.md. Не reset чужих
изменений, не применять прежние starter/bulk патчи повторно.

## Сначала воспроизвести

Go 1.26.5 из go.mod; требования не понижать. На изолированном Linux, не live-router:

```sh
go version
go mod verify
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
node scripts/build-interface.mjs --check
node scripts/test-extension-lab.mjs
sh scripts/check.sh
```

Пакеты и проверки: backendprofile/*, strategylab/packs_test.go, dataplane/hev_sidecar*,
app/extension_lab_test.go, cmd/strategy-pack, web/extension-lab.js. Полный gate должен
оставаться обязательным; конвертация YAML и fake runner не заменяют native/hardware.

## 1. Mihomo — закончить вертикальный маршрут

1. Закрепить точную supported-версию core и безопасный метод доставки. Собрать под
архитектуры, проверить checksum/signature/происхождение. Новейшая схема не означает
совместимость установленной версии.
2. Конфигуратор сейчас экспортирует один static proxy с loopback SOCKS. Не обещать
полный Mihomo YAML importer: штатные DNS/providers/routes/listeners намеренно отброшены.
Расширять `mihomoNode` только с отрицательными тестами и без потери обязательных полей.
3. Выполнить реальный `mihomo -t` с изолированной домашней папкой, без сети/побочных
автозагрузок. Проверить Reality, TCP, WS, gRPC, HY2, TUIC5, SS. HTTP/QUIC ошибки —
отдельно. Во время raw native validation не разрешить вытащить произвольный DNS/geodata.
4. Подключить существующий NodeStore, identity exact checker и scoped транзакцию.
Не заводить вторую subscription БД/планировщик и не expose controller LAN.
5. Не включать native URL-test как разрешение на Apply; подтвердить конкретный
service+source scope+network epoch+egress. Сохранить LKG и резерв.
6. После подтверждения добавить настоящий engine registry/card и техническое
разрешение выбора в мастере.
Пока «Конфигуратор» в Обходах не объявляется установленным движком.

## 2. HEV — закончить opt-in исполнителя

1. `NewProxyTunnelAdapterWithHev` сохраняет default Sing-box. Добавить отдельный
конфигурационный selector после доверенной установки. Не менять SidecarKind во
время жизни объекта/транзакции. Снимок содержит конкретный вид sidecar.
2. Сравнить generated JSON со схемой 2.17.1 или выбранной новой фиксированнойверсии.
Уточнить фактический netmask TUN, IPv4 addresses и policy route readback. Сейчас
IPv6 не генерируется; никаких IPv6 PASS по сборке.
3. Настоящие Start/Stop/health/Cancel/rollback: процесс foreground, argv [config],
loopback SOCKS, без daemon/pidfile/scripts/mapdns. Фиктивный ICMP reply выключен.
4. Нативного `--check` не выдумывать. Проверить layout/core parser и запуск только
в network namespace или отдельном роутере. Проверить все платформенные guards,
symlinks/identity, changed runtime, crash/cleanup, lost NDM firewall.
5. Миграция old Sing-box→HEV требует отдельной transactional stop/snapshot/start/check;
сейчас она запрещена. Не снимать этот guard ради кнопки.
6. TCP/UDP, SOCKS UDP ASSOCIATE, MTU, FD/RSS/max-sessions, abort/second LAN client.
Сравнить один и тот же сервер/протокол до заявления о скорости/стабильности.

## 3. Пакеты стратегий — будущие публикация и автоматика

1. Текущий импорт сохраняет старые кандидаты и проверки, additive update. Требуется
retention старых неиспользуемых версий с защитой selected/frozen/rollback refs; не
удалять автоматически всё после истечения сетевой metadata.
2. Ключи публичные только owner-provisioned. Использовать раздельные keygen/sign/
verify; signer приватный ключ на компьютере издателя. Не хранить PAT, privatekey,
сбор посещённых доменов или тестовые trust keys на роутерах.
3. Подписанный загрузчик: fixed URL, publicfetch bounds, ETag, durable cooldown,
sequence+digest+expiry+revocation, trusted clock handling, cached LKG при отказе.
Тот же каталог не создаёт новую независимую telemetry-систему.
4. Миграция/rollback старого приложения и private backup не должны сбрасывать
receipt highwater. До этого не включать feed/unattended как защищённую функцию.
5. Взаимная совместимость engine/Lua/blob версии: нынешний compatibility_id — только
ограниченный формат pack, НЕ доказательство native ABI или наличия blob. Добавить
compatibility manifest, нативную валидацию и canary на сети пользователя.
6. Стратегии z2k/custom Lua не переносить как автоматически исполняемые файлы.
Поддержанные комбинации компилировать из типизированных полей. Особо UDP/Discord и
QUIC: отдельные predicates. Не убрать `<` blacklist и не превратить JSON в shell.
7. Подписка на пакеты, рекомендации, отправка результата — раздельные разрешения.
Своё имя/SNI в экспортируемой строке видно: требуется предпросмотр, не обещать абсолютную
анонимность. Community percentages лишь shortlist, не разрешение применять путь.
8. Готовый candidate проверяется в общей priority queue, сохраняет LKG, не вытесняет
здоровый вариант. Отказ update не стирает user стратегии. Не создавать отдельный cron.

## 4. Ранее найденные задачи остаются

- USQUE: оригинальное ядро отдельным owned binary, закреплённая версия, H2 с правильным
endpoint/argv, текущая конфигурация не перезаписывается, certpin обязательный,
register отдельно от enroll, неопределённая регистрация durable и без слепых повторов.
- Обычная selected-партия до64 и all-vless должны уступать аварийному восстановлению
на границе cleanup. Новые EXT5-профили не чинят прежний hardware incident.
- Actual nightly install: signed compatible manifests, полная предыдущая зависимость,
out-of-process rollback, guard на ownership/SafeMode/Stop/окно, обновление running identity.
- Per-domain DNS TTL/grace и endpoint: старый весь-набор на NXDOMAIN может блокировать
refresh. Не объявлять DNS PASS доказательством услуг. Общие DNS/WARP конфликты отдельно.
- Native authenticated browser→HTTP, hardware VLESS A/B, WAN/reboot, второйклиент,
MIPSel низкая память, 24–72 часа приёмки. Ошибки, тесты и неподтверждённые ветки писать честно.

## Что передать следующим

Полный source, patch, commit, новые бинарники только из этой ревизии, хеши, логи
реальных test/race/vet/install/browser запусков. Указать отдельно native endpoints,
hardware, фикстуры. Не публиковать stable/main без согласованной приёмки.
