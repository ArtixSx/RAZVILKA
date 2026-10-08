# VLESS: отрицательные границы кандидатов активного списка

08.10.2026. Отдельный потребитель готового CORE-контракта. Зависимости Root
`8f51b17` и `73de0ab`, без изменений перенесённые в этой ветке как `93720d2`
и `cca3e84`. Старый TCP binder/TUN из `9a2a027` остаётся только сохранённой
работой прежнего контракта и сюда не включён.

## Поведение

- Общий `checkAndRecordNodeForEngine`/screen требует фактический Store,
  `cfg.Services[primary].Enabled`, неизменный полный конфиг и определения.
  Отсутствующий/неактивный сервис и текущий negative отказывают до Check.
- `Store.WithResourceExclusionObservation` проверяет фактические байты и
  полный конфиг в коротких наблюдениях. Вызов протокола выполняется вне его
  read lock. Перед RecordCheck повторяются проверки; только ограниченная
  запись независимой истории помещена под это наблюдение. Callback не
  вызывает Store, App gate или внешнюю проверку. Ошибка закрытия не выдаёт
  usable proof и не добавляет measurement в память.
- Первая отрицательная причина в `dataplane.WithNodeResourceGuard` остаётся
  до окончания исходного контекста. Это только дополнительный запрет,
  без positive/source/client/process/effect разрешений или нового issuer.
- Проверяются primary service ID, все известные required URLs, hostname
  каждого используемого диагностического endpoint, полный возвращённый
  адресный набор и фактический pinned IP перед соединением. Известная
  catalog-классификация auxiliary hostname тоже учитывает service negative.
- Fixed CF/ipify endpoint не обязан быть positive клиентской записью.
  Исключённый CF рецепт останавливает проверку без подстановки ipify;
  отказ во время измерения тоже не превращается в общую сетевую ошибку.
- App-кандидат не отдаёт непрозрачный DNS сервисного запроса SOCKS:
  hostname-проверка использует локально полученный допустимый pin с исходным
  TLS именем. Проверки IP пути сохраняют полный bounded IPv4 набор.
  Redirect остаётся в исходном host/TLS/pin и повторяет negative boundary.
- Отказ — INCONCLUSIVE, без записи bad node/health failure. Неопределённый
  device-scoped legacy negative не отменяется отсутствующим DeviceID.
  Неудостоверенная очистка имеет приоритет и сохраняет poison/fence.
- Node preview/pin больше не включает библиотечный/удалённый/disabled сервис.
  Fallback/recovery проверяют текущую активность и negatives, даже если старый
  committed/applied маршрут сохранился. Recovery сохраняет исходную очистку
  старых owned DNS redirects; negatives блокируют следующие пробы и restore.
  Смена exclusion revision отзывает прежнюю queued Apply через уже
  существующую revision/intent проверку; новый ledger не добавлен.

## Границы и последующие владельцы

Это source/admission slice, не общий route executor и не доказательство
LAN-клиента. Существующие provider/source/path/operation/process/TLS/egress
проверки не заменены решением `!excluded`. Positive compiler и фактический
client/path scope остаются DEFAULT/NET. Общий отказ кандидата не создаёт
маршрут к primary или auxiliary endpoint.

Resolver здесь возвращает адреса без удостоверенного CNAME/TTL lease.
Наблюдения known hostname и resolved IP не удостоверяют aliases, сроки,
shared-CDN capture, физическую membership или переход существующих TCP/UDP
сессий. Эти части остаются у NET/DEFAULT/OPS; global conntrack flush нет.
Нативный Linux/router/VM запуск здесь не выполнялся. Cross-build не runtime
PASS. При current NetworkPolicy прежний общий executor capability fence
сохраняется до подключения готового положительного потребителя.

`autonomy_worker.go` не изменён. Его owned eligibility/skip UI остаются
AUTOPILOT. Общие App проверки уже отказывают его кандидату при inactive
primary. Старый `autonomousIntegrationFixture` в owned
`autonomy_integration_test.go` лишь наследует библиотечный сервис, не включает
его в cfg.Services до кандидата; владельцу нужно явно моделировать active
list и новое поведение inheritance. Full App/AUTO suite PASS здесь не заявлен.
В `nfqws2_standard_test.go` изменена только общая fixture: явное включение
фактической записи перед AUTO, без изменений production worker.

## Проверка

Meaningful portable tests покрывают manual/RU/service/exact/suffix/CIDR,
required scenario, actual exclusion CAS во время кандидата, отсутствие
Check/Record/runtime у excluded/inactive primary, изменение in-place
definition/Store owner, отзыв очереди, запрет CF fallback, DNS set/pin,
закрывающий guard после очистки. Существующие queue/retry/rollback/source
и node/fallback/recovery тесты сохранены с явно активными fixture primary;
черновики маршрута/адресов по-прежнему сохраняются.

Окончательная проверка выполняется по самостоятельному архиву точного base
плюс staged binary patch. Все изменённые index blobs сверяются до тестов,
HEAD blobs — после коммита. Артефакт:
`.review-local/list-resource-admission-proof-20261008/source-proof.json`.
В нём фиксируется список исходников; результаты Windows focused App/node
dataplane, vet и Linux amd64/arm64 compile сохраняются рядом.

## Дополнение: сохранённые manual до настройки scope

Готовые Root CORE-пины `bf5958a`, `a4383bf`, `c563a48` подключены без изменений
как `53ebbdf`, `7289a68`, `78603f6`. Новый `InactiveResourceExclusions`
учитывается общим node consumer через тот же фактический
`Store.WithResourceExclusionObservation`; p-only helper здесь не используется.
Production node код не потребовал нового API или обхода scope fence.

Отдельные тесты выполняют реальный manual CAS при nil NetworkPolicy:
service/exact исключение останавливает Check/Record/runtime, не создаёт scope,
consent или positive intent. Такой CAS во время кандидата закрывает исходный
результат как INCONCLUSIVE до RecordCheck. Архив точного исходника дополнения:
`.review-local/list-resource-inactive-proof-20261008-v3/source-proof.json`.

В этом дополнении также исправлен порядок recovery: PrepareDNSRecovery только
снимает старые owned redirects, поэтому negative не отзывает его cleanup
authority. Первый slice ошибочно поставил preflight перед этой очисткой.
Интегрировать первый slice вместе с дополнением; затем negative отказывает
до нового Check/Record/restore. Отдельная модель проверяет фактический Manager
cleanup и отсутствие новых проб у исключённого primary.

Классификация auxiliary endpoint по service ID использует канонизацию
`config.PolicyDomain` и для hostname, и для catalog domain. Trailing dot,
регистр, Unicode/IDN и punycode не обходят service negative; suffix проверяется
только на границе DNS label. Отдельные тесты защищают эти эквивалентности и
похожие, но другие имена. DTO по-прежнему не даёт positive permission.
