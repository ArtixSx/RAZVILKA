# WARP: отдельный генератор и изолированный HIL

6 сентября 2026 года. `cmd/warp-candidate` — разовый инструмент для проверки
кандидатов. Он не вызывает Apply/Restore, не меняет действующее enrollment и
не повышает результат до разрешения AUTO. Команды генерации разрешены
пользователем отдельно от установки кандидата в рабочую сеть.

## Что готово

**WireGuard:** локальный X25519 key, один HTTPS POST, private checkpoint ключа
до сети и успешного ответа до разбора, закрытый Provider Store, экспорт
конфига, offline reconciliation и существующий `CloudflareScanRunner`.
Сетевой адаптер отправляет только public key и сведения о клиенте. Он не имеет
команд изменения аккаунта, лицензии или enrollment; не повторяет POST,
не следует redirects и не использует proxy environment. TLS проверяет CA и
hostname; запрос ограничен 20 секундами, ответ — 64 KiB.

Используется consumer-схема `v0a4471`, наблюдаемая в
[USQUE 4.2.1](https://github.com/Diniboy1123/usque/blob/v4.2.1/api/cloudflare.go)
и его [константах](https://github.com/Diniboy1123/usque/blob/v4.2.1/internal/consts.go).
Это не обещание стабильности API от Cloudflare. Тип ключа, transport, echoed
public key, единственный peer, адреса и endpoints проверяются до экспорта.
Текущий ответ может содержать `IP:0` и отдельный `ports`: раскрываются только
порты, выданные этим же ответом, максимум восемь на IP. Неизвестная схема
остаётся `remote-creation-uncertain`; она не превращается в рабочий профиль.

**MASQUE:** отдельный upstream USQUE 4.2.1, обязательные совпадение SHA256 и
версия/capabilities, новая регистрация в новый private work-root. WG и MASQUE
используют разные регистрации и ключи. Для canary запускается только отдельный
процесс `socks`, привязанный к случайному loopback-порту. Он не создаёт OS TUN,
не меняет routes/DNS/firewall и не включает hooks. Флаг `--insecure` отсутствует:
структурно валидный P-256 server pin обязателен. Это соответствует
[upstream SOCKS mode](https://github.com/Diniboy1123/usque/blob/v4.2.1/cmd/socks.go).

H2 и H3 проверяются раздельно, по две попытки с новыми процессами. Требуются
`warp=on`, иной egress относительно прямого контроля с `warp=off`, успешный
первичный catalog probe, завершённый принадлежащий попытке процесс и
отрицательный контроль через уже закрытый SOCKS. Raw egress IP и содержимое
HTTP-ответов в публичный отчёт не попадают. Это IPv4/TCP primary-probe HIL;
UDP, IPv6 и все обязательные сценарии сервиса этим инструментом не доказаны.

## Подготовленные локальные артефакты

Приватные файлы и исполняемые кандидаты находятся в игнорируемой `.hil`, а не
в Git. Конкретные ключи, токены, Cloudflare device IDs здесь не приводятся.

- `.hil/warp-wg-registration-20260906-b/wireguard.conf`: собственный реальный
  профиль, серверный UDP-порт `2408`. В том же каталоге
  `wireguard-endpoint-1.conf`, `-2.conf`, `-3.conf`: отдельно выданные API порты
  `500`, `1701`, `4500`. Их экспорт не обращался к сети.
- `.hil/warp-masque-registration-20260906-a/masque.json`: собственное новое
  MASQUE enrollment, успешно зарегистрировано и структурно проверено.
- `.hil/warp-candidate-linux-arm64`: кросс-собранный HIL инструмент.
- `.hil/usque-4.2.1-arm64/usque`: отдельный upstream ARM64 release candidate.

Оба профиля остаются `registered-unverified` для применения: HIL ниже не
подтвердил устойчивый повторный результат. В ходе проверки WG подтверждена новая
форма `IP:0 + ports`; сохранённый ответ второй попытки восстановлен offline.
У первой диагностической попытки ответ не сохранялся, поэтому возможное
удалённое устройство не имеет локального подтверждённого состояния. Адаптер
не выполнял автоматических повторов POST.

ARM64 release ZIP проверен по digest, опубликованному
[GitHub release API](https://api.github.com/repos/Diniboy1123/usque/releases/tags/v4.2.1):
`c88b061c2a567f30813d7505637d1fb6fe7ec5898b5b61fd05122409fa5ad925`.
SHA256 извлечённого бинарника:
`8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002`.
Это проверка опубликованного upstream asset, а не завершение собственной
воспроизводимой сборки/SBOM из ADR_NATIVE_USQUE.

## Команды для контролируемого запуска на роутере

Ниже предполагается, что оператор уже создал закрытый каталог
`/opt/tmp/razvilka-warp-hil`, перенёс туда бинарники `warp-candidate`,
`usque-4.2.1`, каталог `wg-a` с WG-профилями и `masque-a` с новым `masque.json`.
Каталоги должны иметь mode `0700`, конфиги — `0600`, бинарники — `0700`.
Путь каталога сервисов заменяется фактическим установленным путём. Существующий
`/opt/bin/usque` и его профиль не заменяются.

Сначала read-only inventory:

```sh
/opt/tmp/razvilka-warp-hil/warp-candidate capabilities \
  --usque /opt/tmp/razvilka-warp-hil/usque-4.2.1 \
  --usque-sha256 8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002
```

WG требует Linux WireGuard и рабочие `wg`/`ip`. При необходимости явные пути
передаются через `--wg` и `--ip`. Флаг module-loaded в inventory означает
только наличие `/sys/module/wireguard`, а не проведённую canary.

```sh
/opt/tmp/razvilka-warp-hil/warp-candidate scan-wg \
  --work-root /opt/tmp/razvilka-warp-hil/wg-a \
  --profile /opt/tmp/razvilka-warp-hil/wg-a/wireguard.conf \
  --catalog /opt/etc/razvilka/service-catalog.json --service telegram \
  --allow-isolated-runtime
```

Другой server-issued порт проверяется отдельной командой с соответствующим
`wireguard-endpoint-N.conf`. Scanner владеет только `rz-cf-scan`, table `220`
и source rule priority `18060`; он проверяет отсутствие конфликтов до запуска.
Он должен убрать временную сеть и подтвердить cleanup после каждой попытки.
Совпадение назначенного IPv4 с существующим OS-интерфейсом — отказ. Останавливать
ради этого рабочий USQUE нельзя: понадобится отдельный userspace WG runner.

```sh
/opt/tmp/razvilka-warp-hil/warp-candidate scan-masque \
  --work-root /opt/tmp/razvilka-warp-hil/masque-a \
  --usque /opt/tmp/razvilka-warp-hil/usque-4.2.1 \
  --usque-sha256 8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002 \
  --catalog /opt/etc/razvilka/service-catalog.json --service telegram \
  --mode both --allow-isolated-runtime
```

`--mode h2` или `h3` ограничивает проверку одним transport. Все реальные
runtime-запуски централизует оператор текущего HIL: инструмент сам не вызывает
production service manager. Перед/после canary проверяется текущая WAN epoch.
Отмена, смена сети и неподтверждённый cleanup отзывают положительный результат.

## Новая генерация и recovery

`generate-*` принимает только ещё не существующий private work-root. Наличие
директории после ошибки — повод разобрать локальный результат, а не повторить
регистрацию. HTTP timeout после POST не доказывает отсутствие устройства.

```sh
warp-candidate generate-wg --work-root /opt/tmp/new-wg --accept-tos
warp-candidate recover-wg --work-root /opt/tmp/interrupted-wg
warp-candidate export-wg --work-root /opt/tmp/new-wg --endpoint-index 1
warp-candidate generate-masque --work-root /opt/tmp/new-masque --accept-tos \
  --usque /opt/tmp/razvilka-warp-hil/usque-4.2.1 \
  --usque-sha256 8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002
```

`recover-wg` выполняет **ноль сетевых запросов**: сверяет исходный локальный
ключ с echoed public key в сохранённом ответе, проверяет схему и сохраняет
неактивный candidate. Состояние без полученного ответа таким образом не
восстановить. MASQUE registration выполняется upstream отдельным процессом;
при частичном remote registration/enrollment сохраняется неопределённый исход
и закрытый лог, автоматической повторной регистрации нет.

## Проверки кода

`go test ./cmd/warp-candidate ./internal/cloudflareprovider` и `go vet` прошли.
Добавлены тесты body/key/schema/ports/checkpoint gates, отсутствия повторного
POST и утечки API-ошибок, offline восстановления без сети, отказа при занятом
work-root, checksum/version gate, отсутствия direct fallback у SOCKS,
отмены только собственного процесса, очистки временного приватного конфига и
неповышения HTTP 403 до PASS. Linux ARM64 бинарник успешно кросс-собран.

## Фактический HIL 2026-09-06

На текущем ARM64-роутере capabilities подтвердил наличие native WireGuard
tool/module и обоих MASQUE transports. В первом полном запуске собственный
новый MASQUE-профиль прошёл по две отдельные попытки HTTP/2 и HTTP/3: Cloudflare trace `warp=on`,
изменение исходящего адреса, основной catalog-запрос Telegram HTTP 200,
завершение собственного процесса и отрицательная проверка после остановки.
Это доказательство только основного IPv4/TCP запроса на этой WAN epoch;
оно не подтверждает все сценарии Telegram, UDP/IPv6 или путь с компьютера.

Первый native WG scan завершился до HTTP-проверок. Старый отчёт скрывал
причину под `runner-failed` и нулевым временем: теперь runner всегда завершает
временную отметку попытки, передаёт безопасные `stage`, `reason_code`,
`system_code`/`http_status` и не выдаёт `valid_until` для проваленного scan.
Сырые сообщения команд, строки конфига и HTTP-body в эти DTO не входят.
В окончательном повторе native WG все четыре выданных Cloudflare UDP-порта
завершились `trace-request-failed`. Наличие модуля не является подтверждением
handshake или доступа к сервису.

Повтор MASQUE не воспроизвёл две успешные попытки подряд: HTTP/2 дал ошибку
trace и один PASS 200; HTTP/3 дал один PASS 200 и `service-not-confirmed`.
Во всех попытках cleanup и отрицательный контроль подтверждены, но
`working_modes` пуст и общий результат отрицательный. Первый положительный
запуск не доказывает устойчивость: автоматическое применение и promotion
по этим данным недопустимы.

После первого MASQUE HIL усилен cleanup control: перед отрицательной
SOCKS-проверкой требуется отсутствие listener на точном временном порту.
Добавлены тесты surviving-listener и отмены частичного native WG start:
успешное создание интерфейса отслеживается отдельно, очистка получает новый
ограниченный контекст; ошибка создания не даёт права удалять чужой интерфейс.

## Встроенный пользовательский генератор

Обычный `/api/v1/warp/generate` теперь использует тот же native consumer API.
`wgcf` не требуется для создания нового аккаунта и черновика; WireGuard
runtime по-прежнему нужен для проверки и применения. Регистрация не повышает
доказательство доступности, не меняет маршруты и не включает AUTO.

В `warp-state/native-enrollment.private.json` сохраняются все приватные
checkpoints попыток: исходный ключ, сохранённый ответ и registration/provider
snapshots. Это один атомарный файл с общей lease для генерации и restore.
До единственного POST синхронно фиксируется pending. `fresh=false` использует проверенный
сохранённый аккаунт без сети. После прерывания следующий запрос восстанавливает
тот же аккаунт только из original key и ответа, даже если указан `fresh=true`.
Без ответа новые регистрации заблокированы, API возвращает
`WARP_REGISTRATION_PENDING`, `retryable=false`; секреты в ответ не входят.

Результат записывается только в черновик EngineConfigs. Старые каталоги
аккаунтов, исходный wgcf account и рабочий профиль сохраняются при ротации.
Native enrollment включён в общий зашифрованный private backup. Typed restore
не выполняет POST и сохраняет более новый pending при конфликте со старой
копией. Старые каталоги мигрируют copy-only; downgrade к бинарнику без schema
capability блокируется. Полный контракт и локальные crash/rollback тесты —
в [NATIVE_WARP_BACKUP_RESTORE_RU.md](NATIVE_WARP_BACKUP_RESTORE_RU.md).
Имеющийся wgcf account при
`fresh=false` использует прежний генератор; если его нет, потребуется установить
wgcf или явно создать новый аккаунт встроенным генератором.

Обычный app API на роутере выполнил один реальный POST и сохранил только
черновик. Повтор `fresh=false`, `accept_tos=false` вернул тот же account/profile
hash без второго запроса и новой attempt-директории: `.hil/warp-native-app-hil.json`.
Аппаратная legacy → canonical миграция с offline reuse прошла с неизменными
original legacy/profile/key hashes (`.hil/native-migration-router-results.json`).
Общий encrypted export/preview/import в отдельный control plane тоже PASS:
canonical SHA совпал, account восстановлен, offline reuse не изменил image;
AppliedServices/AppliedRevision сохранены, service runtime STOPPED
(`.hil/native-backup-router-results.json`). Interrupted-recovery подтверждён
локальными process-crash тестами.
Подтверждённый native VLESS lifecycle с PC (A, rollback-A, B и HTTP 200) не
повышает WARP evidence. Поэтому ручной MVP может использовать проверенный
VLESS-путь, сохраняя WARP как явно непроверенный или неустойчивый кандидат.

## Остановка адаптера и подтверждение владения

Обычный WARP/AWG adapter теперь проверяет собственную пару policy/runtime до
любого обращения к интерфейсам. Если оба файла отсутствуют, Deactivate ничего
не делает: одно имя `rz-warp` или `rz-awg` не даёт права останавливать интерфейс.
Runtime без policy тоже не подтверждает владение: он записывается до создания
интерфейса и может остаться после отказа из-за уже существующего чужого link.

Частичная, повреждённая, подменённая символической ссылкой или старая пара
без digest вызывает отказ с сохранением файлов. Для очистки нужны совпадение
interface/table/priority, допустимые точные правила и SHA-256 фактического
sanitized runtime. Commit записывает digest выбранного endpoint; refresh и
rollback сохраняют его. Refresh не наделяет старую запись новыми полномочиями.
Если остановка или проверка отсутствия интерфейса не удалась, файлы владения
сохраняются для повторной попытки.

Regression проверяет отсутствие kernel-команд без own state, чужой интерфейс
после неудачного `ip link add`, partial/corrupt/mismatched state, нормальную
очистку и повтор после ошибки остановки. Полные dataplane tests и vet прошли
локально. Это исправление границы cleanup; оно не повышает WARP transport
evidence и не обещает успешную очистку ранее созданного неполного состояния.
