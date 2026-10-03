# NET — исправления по native-wg-06

Base: `3eaf5331eab798642225fa2ba3c4479fbc1b22bd`, ветка `sol/net-20261003`.
Источник: предоставленный координатором read-only `delivery-review/.review-local/native-wg-06.log`. Независимые IPv4/IPv6 namespaces воспроизвели оба отказа D05; загрязнение состояния между семействами исключено этой повторной проверкой. Новый native запуск из рабочего чата не выполнялся.

## IPv6: воспроизведённый production дефект

Один корректный результат `ip -6 -j route get 2606:4700::1111 mark 0` содержит `from:"::"`, gateway `2001:db8:1::1`, dev `wan-c`, prefsrc `2001:db8:1::2`. Allowlist отклонял стандартное поле `from`, а вызывающий код скрывал причину под сообщением о неуникальном маршруте.

Теперь `from` разобран как отдельный source selector. Допустимы только неопределённый адрес либо нулевой префикс того же семейства, что destination. Source-specific host/network, ограниченный префикс `::/128`, неверное семейство, zone, пустое/null/нестроковое/невалидное значение отклоняются. `prefsrc` остаётся выбранным WAN source. Это общее правило действует и при чтении маршрута до сервера, и при проверке точного endpoint pin перед cleanup. Неизвестные атрибуты по-прежнему отклоняются; ошибка разбора теперь отличается от отсутствующего/неуникального результата.

Unit Stage с точным JSON из native capture **FAIL до исправления / PASS после**. Отдельно проверены допустимые IPv4/IPv6 значения, отрицательные selectors и чужой pin с source-specific selector: удаление запрещено до первой мутации.

## IPv4: исправлена неполная WAN topology стенда

В capture перед Canary cleanup: `rz-wg-canary` поднят; source+oif lookup выбирает table219; WG handshake ненулевой с обеих сторон; client transfer 956/820, server 820/956. На client `rp_filter all/default/wan-c=2`, но main содержит только connected сети и host route до endpoint, без default/обратного маршрута к service `198.51.100.10`.

Вывод из capture и кода ядра: loose reverse-path validation не находит source сервиса. В первом lookup ядро использует `flowi4_oif=0`, поэтому candidate правило с `oif rz-wg-canary` не помогает; при неуспешном lookup и ненулевом rpf пакет отвергается. Это объясняет handshake+transfer вместе с TCP timeout и разницу с D04, где source policy работающего туннеля могла обеспечить обратный lookup. Сам drop не снимался отдельным трассировщиком; окончательное подтверждение исправления требует нового независимого native запуска. Основания: [Linux v7.0 fib_frontend.c](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/ipv4/fib_frontend.c), [описание rp_filter](https://docs.kernel.org/networking/ip-sysctl.html).

Только D05 fixture теперь создаёт обычные IPv4/IPv6 WAN defaults в своих namespaces. Никакой global/per-interface sysctl не меняется. Перед позитивным Canary оба семейства дополнительно проверяют:

1. HTTP сервис достижим с WAN source `192.0.2.2` без proxy, candidate binding и tunnel source.
2. Canary с правильным локальным private key, но неверным server public key возвращает именно `tunnelcheck.ErrHandshake`, несмотря на доступный WAN сервис.
3. После отказа отсутствуют canary interface и временные правила/table219; staged профиль восстановлен.
4. Правильный изолированный кандидат проходит service+handshake; затем остаются прежние Activate/Health/Commit, fresh-process Reconcile, DNS/WAN rejection + live-after, kernel-loss recovery, rollback/Stop и preservation чужого host route.

Успешные контрольные шаги явно пишутся в native log. При неожиданном отказе capture теперь также содержит service route-get с tunnel source **без oif**, для проверки обратного lookup.

## Локальная проверка

Go 1.26.5, `GOMAXPROCS=2`, `GOFLAGS=-p=2`:

- `go test ./internal/dataplane -run '^TestWGEndpoint' -count=1`: RC0.
- `go test ./internal/dataplane ./internal/wireguardprofile ./internal/awgprofile ./internal/dnscontrol ./internal/netresolve ./internal/strategylab -count=1`: все шесть пакетов RC0.
- `go vet` тех же шести пакетов: RC0.
- Linux/amd64 `CGO_ENABLED=0 go test -c ./internal/dataplane`: RC0; временный бинарник удалён.
- gofmt и `git diff --check`: RC0.

Production go.mod/go.sum/VERSION не изменены. Race не выполнялся в этом checkpoint. Native PASS D05 не заявляется. D04 сохраняет ранее полученный независимый PASS, его topology не меняется.

## Следующая независимая проверка

После интеграции этого коммита повторить только `RAZVILKA_WG_NATIVE=1 go test ./internal/dataplane -run '^TestWGNativeEndpointLifecycle$' -count=1 -v -timeout=4m` в exclusive Linux окне с одобренным TMPDIR. Не наследовать `RAZVILKA_WG_NATIVE_ROLE/ROOT/READY/RECOVER_ROOT/ENDPOINT/NOW/TEST_ENDPOINT/SERVER_NS`. Передать read-only лог.

Критерий: оба семейства проходят WAN control, wrong-key handshake rejection, positive isolated Canary и весь оставшийся lifecycle, включая committed pin с точным tuple, процесс восстановления, live-after rejected DNS/WAN и exact rollback/Stop с сохранением чужого маршрута. При отказе сохранить bounded capture до удаления кандидата.

Следующий отдельный D05 аудит: mutation→marker crash boundaries и rollback прежнего отличающегося live peer. D06 strict loaded-module/kernel/ABI/CLI, D08 DNS TTL/scoped DNS и D09 bounded NFQWS2 остаются последующими задачами; этот checkpoint не объявляет их выполненными.
