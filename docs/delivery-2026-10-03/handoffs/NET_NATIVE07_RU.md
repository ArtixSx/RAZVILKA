# NET — semantic table readback по native-wg-07

Base: `be5e399b1bdc590c1e0d292eaa7223ef6765a5d6`, ветка `sol/net-20261003`.
Прочитан предоставленный координатором read-only `delivery-review/.review-local/native-wg-07.log`.

## Независимый результат на предыдущем коммите

D04 снова **PASS IPv4/IPv6**. Обе отдельные topology D05 проходят WAN service control, wrong-key rejection с handshake error, valid isolated candidate service+handshake и Activate/Health/Commit. Затем оба случая останавливаются на assertion marked transport, поэтому fresh-process Reconcile, DNS/WAN rejected-change live-after, kernel-loss recovery и rollback/Stop в этом запуске ещё не выполнялись. Полный D05 PASS не заявляется.

Причина следующего отказа подтверждена JSON: IPv4 и IPv6 возвращают `table:"206"`, тогда как assertion сравнивал raw JSON со строкой `206`, то есть ожидал JSON-число. Device/gateway совпадают с WAN pin; это ошибочное сравнение формы представления таблицы.

## Изменение

- Общий строгий helper сравнивает ID таблицы, принимая JSON-число и каноническую десятичную JSON-строку. `main` принимается только для ID254. Чужая таблица, неизвестное имя, leading zeros/sign/пробелы внутри строки, дробь, exponent, overflow, null, массив или объект не приобретают полномочия.
- Native assertion сохранён и дополнительно проверяет destination и prefsrc, вместе с device/gateway/table. Exact JSON обоих capture воспроизведён в unit regressions. IPv4 route-get cache metadata и IPv6 protocol/metric не подменяют проверку установленного route tuple: перед этим по-прежнему выполняется production `verifyWGEndpoint`.
- Production WAN main readback использует то же сравнение ID254. При проверке endpoint route перед cleanup явно возвращённая таблица теперь обязана совпасть с owned ID; отсутствие table в table-scoped route-show остаётся допустимым. Чужое `"205"` блокирует удаление до первой мутации. Позитивный exact cleanup с `"206"` проверен.

## Проверка

Go1.26.5, `GOMAXPROCS=2`, `GOFLAGS=-p=2`:

- `go test ./internal/dataplane -run '^TestWG(Endpoint|Canary)' -count=1`: RC0.
- Windows и Linux/amd64 `go vet ./internal/dataplane`: RC0.
- Linux/amd64 `CGO_ENABLED=0 go test -c ./internal/dataplane`: RC0; временный бинарник удалён.
- gofmt / `git diff --check`: RC0.

Native запуск рабочий чат не выполнял. Production go.mod/go.sum/VERSION не менялись. Race в этом checkpoint не выполнялся.

## Следующий запуск координатора

После интеграции повторить **только D05** в exclusive Linux окне и одобренном TMPDIR:

`RAZVILKA_WG_NATIVE=1 go test ./internal/dataplane -run '^TestWGNativeEndpointLifecycle$' -count=1 -v -timeout=4m`

Не наследовать `RAZVILKA_WG_NATIVE_ROLE/ROOT/READY/RECOVER_ROOT/ENDPOINT/NOW/TEST_ENDPOINT/SERVER_NS`. Критерий — оба семейства проходят сохранённую проверку exact marked WAN pin и все последующие lifecycle assertions. При новом отказе передать read-only log с capture. D06 не смешан с этой адресной правкой; mutation→marker и old-live rollback остаются отдельным D05 аудитом.
