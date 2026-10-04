# Разовый HTTPS-клиент для измерения LAN-пути

`dataplane.RunNodeLANHTTPSProbe(ctx, NodeLANHTTPSRequest)` — готовый библиотечный шаг для запуска на настоящем выбранном или контрольном LAN-клиенте. Постоянный агент не требуется. CORE владеет одноразовым CLI, выдачей challenge и collector; эти части здесь не реализованы.

Запрос содержит `RuntimeID`, одноразовый `Challenge` (оба lowercase hex64), исходный публичный HTTPS URL, закреплённый публичный `Destination` и явно выбранный локальный `Source`. Source должен реально принадлежать поднятому non-loopback интерфейсу именно запускающего клиента, совпадать с destination по семье и сохраняться до завершения измерения. IPv4-mapped, zone, loopback, link-local и неоднозначное назначение адреса отвергаются.

Клиент делает один GET к literal destination:443 с локальным Source, исходными Host/SNI и обычной проверкой сертификата. Environment proxy, redirect, alternate IP, retry и TLS bypass отсутствуют. Общий срок — 15 секунд, dial и TLS — до 5 секунд, headers — до 16 KiB. Сервисный ответ проверяет существующий `strictServiceResponse`; hash относится только к ограниченному образцу тела (до 32 KiB). Отмена вызывающего context прерывает также dial.

Результат содержит фактические TCP source/destination AddrPort, локальные interface/index, время, HTTP status, принятие ответа сервиса и hash/размер образца. `ServiceAccepted` устанавливается только после успешной проверки HTTPS-ответа и повторной проверки локального source. Runtime/challenge — данные для сопоставления, а не разрешение на Apply. JSON от клиента сам по себе не является доверенным наблюдением роутера.

## Следующий обычный пользовательский шаг

1. CORE выдаёт bounded одноразовый challenge для текущего runtime, точного сервиса и pinned destination. Выбранный и реальный excluded/control клиент получают разные challenges. Чтение challenge и ожидание результата происходят вне долгого Manager operation lock.
2. Пользователь запускает одноразовый helper на каждом из этих клиентов. Helper вызывает данный API и возвращает результат; процесс завершает работу после запроса.
3. Доверенный router collector сопоставляет nonce, срок, runtime, boot, owned ifindex/config/receipt и точный flow с наблюдением на physical LAN ingress и owned TUN. Для control требуется независимое подтверждение прямого WAN-пути и NAT join. Потери capture, offload, fragment или неоднозначный join дают unknown.
4. Только после всех независимых проверок factory может сформировать существующий `NodeTUNObservation`. DTO с boolean, счётчики интерфейса, cached node-check и успешный SOCKS-запрос этого права не дают.

Текущий `NodeTUNObservation` также требует разные публичные egress выбранного и контрольного клиента на **том же закреплённом сервисном destination**. Обычный HTTPS-сервис часто не сообщает peer IP, а TLS скрывает ответ от router capture. Тогда полного proof нет: нужен разрешённый same-scope endpoint/witness, связывающий nonce, результат сервиса и observed peer с тем же captured TLS flow, либо иной доверенный provider такого же доказательства. Отдельный запрос к IP-echo не заполняет эти поля и не расширяет ServiceScope.

## Проверки и граница готовности

Private per-call fixtures подменяют только интерфейсные адреса, local TLS socket и CA roots; exported production API этих опций не имеет. Тесты проверяют обе семьи, pin и bind, исходные Host/SNI, сертификаты, actual socket tuple, response semantics, bounds, смену source и отмену. Внешняя сеть, router/VM и native kernel acceptance в этой работе не использовались.

Это завершённый producer клиентского артефакта. Production `NodeTUNProbe`, kernel collector, remote egress witness и app/CLI wiring ещё нужны; общий Xray selectable/Apply и D03/D10/DEFAULT readiness из этого API не следуют.
