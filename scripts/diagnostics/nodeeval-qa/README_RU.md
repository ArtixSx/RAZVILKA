# MTProto/Stop QA для текущего nodeeval

Это отдельный диагностический Go overlay, а не production API и не приёмка D10.
Обычная сборка не включает `.go.txt`. Генератор не правит исходники, не запускает
движок, не устанавливает runtime, не подключается к сети и не создаёт разрешения
на маршруты/историю. Все настоящие VM/router/Telegram проверки выполняет Root.

## Проверенный перенос исходника

Первый payload из `.review-local/nodeeval-mtproto-qa` и `nodeeval-stop-qa` был
привязан к `616abe95dc59f41d664419ba377a5e1ea1498bae`. Старые файлы и pins не
изменены. Новый `source-pins.json` хранит старые и новые SHA256; active pins
соответствуют исходникам `f7f886621f3f1d11bc285211d1e1b09609060369` после
нормализации CRLF→LF. Это pins двух изменяемых virtual файлов, не подпись всего
дерева зависимостей. Собирать нужно из независимо принятого checkout.

Полный `source-port.diff` (без context строк, для review) показывает изменения
production между этими версиями:
73 добавленные строки в checker (resource guards и сохранение cancellation
cause) и 2 в CLI (фиксированная классификация early checker error). Новый
генератор накладывает прежние точечные hooks поверх **нового** исходника;
старый полный `nodecheck.qa.go` не используется. Сгенерированный `hooks.diff`
показывает только актуальные QA hooks. Изменённый SHA, отсутствующий/повторённый
anchor, существующий virtual target или занятый output дают отказ до записи.
Флага обхода pin нет. Новый port/pin требует нового diff review.

## Сборка и безопасные тесты

Нужны Python3.10+ и Go версии проекта. Output должен быть новым, его родитель —
существующим private каталогом. Сгенерированные absolute mappings нужно создавать
на хосте сборки: Windows overlay нельзя копировать как готовый Linux overlay.
Внутри checkout output разрешён только под `.review-local`; лучше использовать
отдельный private QA каталог. В output создаются каталог0700 и файлы0600.

Из checkout на Linux (пример путей, не команда для роутера):

```sh
python3 -m unittest discover -s scripts/diagnostics/nodeeval-qa -p 'test_*.py' -v
python3 scripts/diagnostics/nodeeval-qa/prepare_overlay.py "$PWD" /qa-private/mtproto-new
go test -overlay /qa-private/mtproto-new/overlay.json -count=1 \
  -run '^Test(QAMT|ExactNode|NodeResourceGuard|NodeCheckResource|NodeCheckCancellation)' ./internal/dataplane
go test -overlay /qa-private/mtproto-new/overlay.json -count=1 ./cmd/nodeeval
go test -race -overlay /qa-private/mtproto-new/overlay.json -count=1 \
  -run '^Test(QAMT|QA)' ./internal/dataplane ./cmd/nodeeval
go vet -overlay /qa-private/mtproto-new/overlay.json ./internal/dataplane ./cmd/nodeeval
go build -overlay /qa-private/mtproto-new/overlay.json \
  -o /qa-private/mtproto-new/nodeeval-qa ./cmd/nodeeval
```

Это unit/contract проверки с фикстурами и `net.Pipe`; они не вызывают настоящие
VLESS/Telegram. Linux тест FIFO использует только свой subprocess и private
FIFO без writer; родитель завершает зависший child по deadline. Для cross-build
добавить `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` (VM) или `GOARCH=arm64`
(роутер); это не исполнение Linux тестов и не native PASS.

## Настоящее сравнение — только отдельный запуск Root

Сохраняются исходные аргументы `cmd/nodeeval`: новый private `-root`, ровно один
из `-preset APPROVED_ID` / `-store PRIVATE_STORE`, проверенный абсолютный `-binary`,
движок, свободный loopback-порт и конечные budgets. Никакого TUN/Apply/iptables,
копирования live Store или обхода lease. Windows WAN observer не поддерживается:
для реальной проверки нужна Linux VM либо отдельно допущенный запуск на роутере.
После неподтверждённого native retirement запуск на том же роутере запрещён до
разрешения Root; QA не исправляет и не переоткрывает чужой cleanup owner.

Пример одного **будущего Root-only** fresh-feed запуска в Linux VM:

```sh
/qa-private/mtproto-new/nodeeval-qa \
  -root /qa-private/result-new -preset igareck-black-vless \
  -engine xray -binary /qa-private/verified-runtime/xray \
  -limit 12 -duration 8m -check-timeout 45s -port 19301
```

Для одинакового сравнения повторять последовательно с новыми root и одинаковыми
лимитами для `igareck-reality-mobile`, `kort0881-ru-sni`, `tiagorrg-vless`.
Наличие preset не доказывает текущую доступность; unsupported transport остаётся
inconclusive и расходует исходный candidate limit. Упавший cleanup останавливает
исходный CLI; дополнительная QA не разрешает продолжение/повтор.

## Сессия, Stop и интерпретация

Исходная HTTPS serviceProbe вызывается ровно один раз и возвращает своё исходное
evidence/error. Только `custom-telegram-https` с исходным URL допускает один
MTProto exchange на Check. Hook находится внутри уже работающей **той же**
точной сессии. Перед/после обмена проверяются исходный passport процесса,
конфигурации/argv и WAN. Дополнительный числовой DC проходит действующий sticky
resource guard; отказ остаётся отказом, а не новым полномочием. Внешний final
observer зарегистрирован первым, поэтому публикует результат после исходных
identity, cleanup, WAN/resource closing, cancel и slot-release defers.

Единственный TCP dial идёт к уже принадлежащему сессии literal loopback SOCKS.
SOCKS CONNECT содержит только фиксированный Telegram DC2 `149.154.167.51:443`.
Нет другого proxy process, прямого fallback или DNS имени для DC. Budget обмена
3s вложен в исходные deadlines. Cancellation закрывает socket; повторов нет.

Stop decorator вызывает исходный Start/Running/Stop, Stop ровно один раз с
исходным context/spec/error. PID/proc observations — только диагностика, не
receipt/authority. На Linux PID открывается через held workspace root с
NONBLOCK/NOFOLLOW и проверкой regular-file; лимиты PID64, proc stat4KiB,
cmdline16KiB. FIFO не задерживает настоящий Stop. Не меняются process-global
umask, flags stdout или границы исходного cleanup.

Во время Stop/Recover строки только складываются в preallocated queue до1024
событий; diagnostic I/O на этих путях отсутствует. Flush происходит один раз
**после возврата исходного evaluate**, включая его настоящий bounded Recover.
Flush не держит capture lock, не создаёт publisher goroutine и не владеет
cleanup. Заблокированный writer не может предотвратить Stop. Root должен
дренировать stdout, как и для исходных CLI report rows. Отсутствующий final
marker означает неполный output.

Строки stdout:

- `qa-mtproto`: отдельное наблюдение после cleanup, не health/history. В
  исходный `results.jsonl` не записывается. `mtproto_reply` — форматный ответ
  с совпавшим nonce и immediate guards; `mtproto_accepted` дополнительно
  требует исходный свежий HTTPS PASS по имени/IP и подтверждённое закрытие.
- `qa-stop`, `qa-recovery`: исходный порядок обозначают `call_index`,
  `check_call`, `recovery_call`, `phase`; выводятся после исходного evaluate,
  поэтому файл не является realtime timeline. Эти строки есть и в исходном
  `results.jsonl` через его исходный writer.
- `qa-diagnostics`, `phase:complete`, `success:true`: queue полностью выведена
  без overflow. Публикуется **после** исходного summary; не путать с его
  `finished:true`. Ошибка записи не меняет исходный exit code, но QA incomplete.

Для принятия QA нужны исходные `finished:true`, соответствующий exit code0,
свежий HTTPS PASS нужного NodeID/engine, `qa-diagnostics success:true` и
`qa-mtproto mtproto_accepted:true` того же узла. Если был Recover, нужна его
успешная строка, но она не исправляет ранее неполный исходный запуск. MTProto
отказ не заменяет исходное HTTPS evidence и сам по себе не доказывает гибель
VLESS. Никаких endpoints, credentials, private URL, nonce, raw error или configs
в QA rows нет. Private feed/store/runtime файлы остаются private.

Проверены official resPQ bytes, nonce/envelope/TL/time/frame bounds, numeric
SOCKS без direct dial, cancellation/stall, same-owner/resource отрицания,
последующий service-IP отказ, WAN/cleanup closing, foreign service/route/address
и unbound context,
Stop error forwarding, output failure/blocking и bounded capture overflow.

## Протокол и предел результата

Основа протокола: [authorization flow](https://core.telegram.org/mtproto/auth_key),
[message envelope](https://core.telegram.org/mtproto/description),
[abridged transport](https://core.telegram.org/mtproto/mtproto-transports#abridged),
[TL serialization](https://core.telegram.org/mtproto/serialize),
[официальный wire example](https://core.telegram.org/mtproto/samples-auth_key).
Числовой DC взят из
[Telegram Desktop built-in DC options](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/mtproto/mtproto_dc_options.cpp)
прежнего reviewed payload от07.10.2026; QA не синхронизирует время и не меняет
список DC. Перенос сохраняет прежние bytes/ограничения, не объявляет повторную
внешнюю проверку endpoint.

`resPQ` не аутентифицирует сервер: RSA/DH проверяются позже. Нет auth key,
логина, аккаунта, сообщений, медиа, голоса, whole-LAN/TUN или Selectable.
Одноразовое сравнение публичных источников не доказывает AUTO failover/refill.
Полный D10 остаётся существующим `TestXraySelectedAutoFetchNativeHTTP` с
настоящими A→exhausted AB→fresh C, Apply и Stop, отдельной допущенной приёмкой.

## Локальная проверка порта16.10.2026

Windows:8 Python contracts PASS0.277s; overlay checker/adjacent focused tests
PASS3.648s, весь overlay `cmd/nodeeval` PASS1.163s. Linux amd64 обе test binaries
и CLI cross-build PASS, overlay vet PASS; Linux arm64 CLI и cmd test binary
cross-build PASS. Это не Linux execution/race, FIFO execution, native VLESS или
Telegram PASS. Такие запуски остаются отдельной проверкой Root.
