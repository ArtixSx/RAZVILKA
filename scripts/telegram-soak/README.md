# Telegram soak: SOCKS или выбранный LAN-клиент

CLI проверяет фиксированную HTTPS-страницу `telegram.org` и, с `-mtproto`,
один публичный unauth `req_pq_multi` к прежнему DC2 `149.154.167.51:443` за цикл.
Проверяется nonce в `resPQ`; авторизация, аккаунт и отправка сообщений не выполняются.

Сборка из корня репозитория:

```sh
go build -trimpath -o telegram-soak ./scripts/telegram-soak
```

Выбрать нужно ровно один режим:

```sh
./telegram-soak -socks 127.0.0.1:1080 -mtproto -duration 1h -interval 30s > telegram-socks.json
./telegram-soak --lan-client 192.168.1.100 -mtproto -duration 1h -interval 30s > telegram-lan.json
```

LAN-адрес в примере заменяют на существующий IPv4 выбранного PC. Он должен
принадлежать включённому интерфейсу, отличному от loopback. Обе LAN-пробы используют
`net.Dialer.LocalAddr` и IPv4 системную сеть. Ошибка привязки или исчезновение адреса
не запускает повторную попытку без привязки, SOCKS или другой режим. Переменные
proxy environment игнорируются. Маршруты, DNS и настройки ОС не меняются.
LAN использует системное разрешение имени, SOCKS передаёт имя своему endpoint.

Необязательный `-telegram-ip PUBLIC_IPV4` сохраняет исходные HTTP Host и TLS SNI
`telegram.org`. Проверка TLS обязательна. Как и прежде, публичный IP предварительно
проверяет оператор; CLI не принимает приватный IP вместо Telegram.

`-duration 1h` означает час **sampling после начального контроля**, а не час со
старта процесса. Начальный и конечный контроль учитываются в общей длительности
отдельно. Значения по умолчанию: interval 30s, HTTPS budget 10s, control budget 2s;
unauth MTProto budget остаётся 3s. Цикл начинается только при достаточном оставшемся
времени для полных budgets. Завершение последней пробы раньше часа не сокращает окно.

В JSON `connection_mode` равен `socks` или `lan-client`. SOCKS отчёт содержит
`loopback_socks_endpoint`, LAN — `lan_client_ipv4`. SOCKS controls проверяют greeting,
LAN controls — наличие адреса на включённом nonloopback интерфейсе.
`requested_sampling_seconds`, `sampling_elapsed_seconds`, `window_completed`,
`outcome` и `exit_code` показывают полноту окна. Прерывание или частичное окно
не дают PASS: exit 130 — отмена, 1 — отказ/неполное окно/deadline, 2 — завершённое
окно с отказами проб или конечного контроля, 0 — полное окно с успешными проверками.

**Успех LAN-проб и наличие адреса не доказывают proxy/VLESS или пакетный путь.**
ROOT отдельно проверяет оригинального App owner, iptables counters, процесс и путь
выбранного клиента после настоящего Apply. Ни один режим не подтверждает работу
авторизованного Telegram, медиа, звонков или приёмку релиза.

Подготовка выполнена от исходников `18a4efff1da471a399f44d2458ea989d97c8283e`.
Локальные тесты используют только сокеты этого PC: HTTPS fixture с исходным SNI,
unauth nonce/resPQ fixture, реальную привязку IPv4 и отказ bind занятого порта.
При отсутствии подходящего интерфейса socket fixtures явно SKIP; это не native-приёмка.
Команды проверки: `go test ./scripts/telegram-soak -count=1` и
`go vet ./scripts/telegram-soak`. Интернет, часовой тест, роутер и VM здесь не проверяются.
