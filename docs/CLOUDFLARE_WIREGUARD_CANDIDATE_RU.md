# Cloudflare WireGuard candidate: безопасный builder

1 сентября 2026 года · локальная разработка, без установки и публикации.

Этот блок превращает локально зарегистрированную запись Provider Store во
временный типизированный WireGuard-кандидат. Он нужен следующему Endpoint
Scanner, но сам ничего не подключает.

## Гарантии

- candidate живёт только внутри `WithWireGuardCandidate` и стирает ключевые
  буферы после возврата callback;
- используются только server-issued endpoint и адреса сохранённого аккаунта;
- endpoint выбирается по индексу, MTU ограничен `576..1500`, keepalive —
  `1..120`; defaults: MTU `1280`, keepalive `25`;
- AllowedIPs фиксированы как full-tunnel будущей изолированной среды;
- DNS и shell hooks не поддерживаются, поэтому конфиг не может менять DNS или
  выполнять команды;
- JSON и форматирование содержат только redacted/public preview;
- полный конфиг выдаётся только явным `WriteConfig` доверенному runner;
- после завершения lease повторный export возвращает `ErrCandidateExpired`.

## Чего здесь нет

- сетевого namespace, WireGuard interface или userspace process;
- handshake, egress, Cloudflare trace или проверки Telegram;
- записи конфига на диск, публичного API и UI;
- изменения firewall, PBR, default route или DNS;
- автоматического выбора/активации endpoint.

Следующий gate — изолированный runner с owned path/listener, timeout и cleanup,
после него Endpoint Scanner должен отдельно подтвердить handshake, egress,
`warp=on` и целевой сервис.

## Проверка на целевом устройстве

Candidate-тесты кросс-собраны и выполнены на ARM64 Keenetic: inert/default
builder, redaction, истечение lease, запрет DNS/hooks, bounds двух endpoints и
передача ошибки runner прошли. SHA-256 локального и загруженного теста совпал.
Временный бинарник удалён; рабочая RAZVILKA осталась `0.18.0` и не
перезапускалась.
