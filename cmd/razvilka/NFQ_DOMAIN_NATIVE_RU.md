# Native domain compatibility fixture

`TestManagedNFQDomainCompatibilityInstalled` запускается только координатором
на root ARM64 Linux с существующим настоящим installer-produced NFQ bundle.
Без opt-in тест SKIP. После opt-in отсутствие платформы, private root,
installer receipt или существующего unstopped production control — FAIL с
точным `stage/code`. Fixture не устанавливает bundle и не создаёт control.

Подготовить новый пустой каталог с mode0700 в защищённой ancestry. Указать
его в `RAZVILKA_NATIVE_NFQ_DOMAIN_ROOT`, действующий component state в
`RAZVILKA_COMPONENT_STATE`, установить `RAZVILKA_NATIVE_NFQ_DOMAIN_COMPAT=1`.
Запускать заранее собранный native test executable из protected path:

```sh
RAZVILKA_NATIVE_NFQ_DOMAIN_COMPAT=1 \
RAZVILKA_NATIVE_NFQ_DOMAIN_ROOT="$fresh_private_root" \
RAZVILKA_COMPONENT_STATE="$existing_component_state" \
  "$native_test_binary" \
  -test.run '^TestManagedNFQDomainCompatibilityInstalled$' \
  -test.count=1 -test.v -test.timeout=0
```

Не оборачивать запуск внешним timeout и не убивать pending процесс.
Неизвестный Join сохраняет исходные admission/control/material/leases и
повторяется штатным `retainManagedListRetirement`; timeout body не является
cleanup. Новый каталог и оба child receipt остаются после выполнения для
разбора, не удаляются через TempDir cleanup.

Порядок: original Gate exclusive admission → existing production control →
genuine baseline no-intercept validation/RetireKnown → новый retained source
runtime → настоящий SelectManual/SelectedCandidateReview → независимый второй
Acquire обязан отказать (тот же exclusive writer) → owner-issued
ForkValidation → domain constructor с include/exclude → actual dry-run/Lua
receipt/ACK/final argv → подмена receipt теми же bytes на новом inode должна
отозвать Current при сохранении source → оригинальный Close/Join.

Refusal проверяется настоящими входами: один source lease вместо отдельной
ветви; пустой include с настоящей ветвью. Unknown не инъецируется фальшивыми
callbacks или поддельным payload. Если возникает настоящий unknown, fixture
остаётся с исходным владельцем до подтверждённого Join. Отдельная проверка
того, как воспроизводимо вызвать native unknown без убийства owner, остаётся
координатору; зеленый success не считается её выполнением.

Это проверка CORE compatibility API, не App HTTP Apply. Возможны временные
процессы и raw sockets настоящего payload; argv требует `--intercept=0`.
Нет queue/scope/маршрутов/DNS/client probes. Имена `video.example` и
`private.video.example` — только hostlist bytes, запросы к ним не выполняются.
SNI-пакеты, доступность сервиса, baseline неизвестного/исключённого трафика и
D07–D09 этим fixture не доказываются.
