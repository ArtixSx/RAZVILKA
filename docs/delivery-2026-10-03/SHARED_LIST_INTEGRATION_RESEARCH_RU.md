# Подключение общего LIST: исследование и порядок B/C

Дата: 13.10.2026. Проверенный исходник RAZVILKA:
`60d0d88b3a958054744d4e4c8b733f9191db3154`.
Учтён независимый аудит NFQ `f54055db27052973622fee5c9da54126060a8236`
на исходнике `1da53661d1a89a3a8a8099455bd64dd2428fd15b`.
Номера строк ниже относятся к указанным исходникам. Документ содержит
read-only выводы и предложение интеграции; он не подтверждает выполнение
Apply, аппаратную работу, часовой тест или готовность выпуска.

## Главное

Общий активный список сервисов для выбранных домашних сегментов, приоритет
исключений сайтов и устройств и сохранение обычной политики роутера вне
списка — требования продукта 0.20. Обычная политика может уже включать VPN;
её нельзя заменять принудительным WAN или выходом `direct` из прокси.

A — настоящий one-PC Apply → трафик → Stop → часовой сценарий.
Это промежуточная аппаратная приёмка. B расширяет общий список и жизненный
цикл клиентов. C подключает домены, DNS и идентичность потока в существующем
Manager. B/C не заменяются успехом A и не переносятся целиком в будущие версии.

Большая часть правил уже существует. Основные пробелы — штатная App-сборка,
общий владелец нескольких сервисов, защищённый переход при появлении клиентов
и расширение нынешнего доменного leaf за пределы одного клиента/назначения.

## Что подтверждено в первичных проектах

| Проект и закреплённый исходник | Полезный механизм | Ограничение для RAZVILKA |
| --- | --- | --- |
| zapret2, `a1adf7b868e65c8a77aab608c8bbd9ec8b30a256` | Hostlist исключения проверяются перед включениями; непустой список требует известного имени. | Пустые include-листы снимают фильтр имени, auto-hostlist добавляет новые сайты. Ни одно поведение не определяет полномочия нашего LIST. |
| sing-box v1.14.2, `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` | Sniff/resolve перед выбором маршрута; FakeIP mapping; netlink-обновления соседей и наблюдение DHCP-файлов. | DNS reverse-map по IP не доказывает имя конкретного потока. Lease/EUI64 fallback и best-effort обработка потерь не заменяют нашу original identity. |
| OpenWrt PBR 1.2.2, `0ef6da7f7b9ff953226bf73f38cd7c448aa14839` | MAC/IP source selectors, DNS → nft sets, обновление при событиях интерфейса; matching policy отдельно от default route. | DNS sets дают кандидатные адреса, а не доменную идентичность на shared IP. Чужие метки, глобальное управление DNS и правила прошивки не копируются. |

Первичные ссылки:

- zapret2 [HostlistCheck, строки 249–279](https://github.com/bol-van/zapret2/blob/a1adf7b868e65c8a77aab608c8bbd9ec8b30a256/nfq2/hostlist.c#L249)
  и [описание hostlist, строки 859–877](https://github.com/bol-van/zapret2/blob/a1adf7b868e65c8a77aab608c8bbd9ec8b30a256/docs/manual.en.md#L859).
  Для explicit exact нужен `^name`, для suffix — `name`.
- sing-box [FakeIP/reverse-map, строки 564–583](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/route/route.go#L564),
  [sniff и terminal routing, строки 671–704](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/route/route.go#L671),
  [DHCP watcher и lookup, строки 64–114](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/route/neighbor_resolver_linux.go#L64)
  и [netlink updates, строки 174–219](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/route/neighbor_resolver_linux.go#L174).
- PBR [MAC selector, строки 1196–1200](https://github.com/stangri/pbr/blob/0ef6da7f7b9ff953226bf73f38cd7c448aa14839/files/etc/init.d/pbr#L1196)
  и [interface hook](https://github.com/stangri/pbr/blob/0ef6da7f7b9ff953226bf73f38cd7c448aa14839/files/etc/hotplug.d/iface/70-pbr).
  [Документация автора](https://docs.mossdef.org/pbr/#a-word-about-default-routing)
  описывает unchanged default route; разделы Ignore Target и DNS-over-HTTPS
  показывают порядок исключений и ограничения DNS sets. Документация
  обновляется независимо; воспроизводимые исходники закреплены выше.

## B — общий список и новые клиенты

1. **Сохранение общей области.** Использовать original реальные SegmentID и
   DeviceID и существующий whole-policy CAS writer. Для общего продукта —
   `lan_except + NewDevices=inherit`, с явными negative ID/CIDR.
   `ServiceState.Sources` из текущих DHCP IP не заменяет общую область.
   Offline исключения сохраняются; observed, desired и applied показываются
   раздельно. Точки: [default_consent.go](../../internal/app/default_consent.go),
   [list_scope_binding.go](../../internal/app/list_scope_binding.go),
   [network_policy.go](../../internal/config/network_policy.go).

2. **Одна транзакция нескольких сервисов.** Собрать все enabled услуги и
   отдельный original retained proof/material каждого пути в общем
   compiler/Manager. `compileIngress` уже поддерживает sources сегмента,
   `Membership=all` и ранние MAC/IP negatives.
   [default_route_executor_compile.go](../../internal/app/default_route_executor_compile.go),
   строки 373–419; App seams:
   [list_nfqws_runtime_review.go](../../internal/app/list_nfqws_runtime_review.go)
   и [list_xray_runtime_assembly.go](../../internal/app/list_xray_runtime_assembly.go).
   Не размножать один service PASS на другие услуги; не расширять finite
   one-PC issuer. При пустом LIST отозвать owned effects, а не запускать
   профиль nfqws2 с пустым include/catch-all. Во всех NFQ профилях сохранять
   effective resource negatives; device MAC/iif negatives — перед NFQUEUE.
   Обучение стратегии не добавляет active resources.

3. **Защищённое обновление состава.** Новый observed member сейчас отзывает
   original full scope; `DecideWithScope` также сравнивает весь состав.
   [wire.go](../../internal/physicalscope/wire.go), строки 350–395;
   [domain_policy.go](../../internal/dataplane/domain_policy.go), строки 170–175.
   Нужен новый original review и replacement через тот же Manager/operationgate
   в рамках сохранённого segment/inherit intent, с current bindings,
   перепроверкой отрицаний и завершением старых leases/effects.
   До перехода новый клиент остаётся на baseline либо получает явный
   unavailable. Не снимать сравнение целиком, не добавлять правила вне receipt
   и не переиспользовать finite `/32` proof для full LAN. Изменение обычного
   клиента не должно оставлять продукт навсегда revoked; изменение
   инфраструктуры, конфликты и потеря событий сохраняют отказ.

## C — домены, DNS и реальный поток

1. **Собрать готовые участники в App.** Подключить
   `NewListDNSResourceBinding` → `FreezeDomainPolicyRuntimePlan` →
   `NetworkPolicyDNSResolverForPlan` и original DNS/synthetic/capture
   execution resources в одной generation/receipt.
   [list_dns_resources.go](../../internal/app/list_dns_resources.go),
   [domain_policy_plan.go](../../internal/dataplane/domain_policy_plan.go),
   [network_policy.go](../../internal/dnscontrol/network_policy.go).
   [domain_policy.go](../../internal/dataplane/domain_policy.go), строки
   201–278, уже проверяет client/resource/service negatives перед positives.
   Disabled catalogue identities остаются для отрицательной классификации.
   Нынешний IP compiler правильно отказывает на domain/service exclusions
   при оставшихся positives; отказ заменяется работающим consumer, не waiver.

2. **Разделить IP и name-aware исполнение.** IP/CIDR branch сохраняется для
   подходящих услуг, включая непрозрачный TCP MTProto. DNS-ответ не превращает
   домен в полномочие bypass всего IP. Для proxy при shared-IP конфликте
   использовать [DomainPolicy.HandleTCP](../../internal/dataplane/domain_policy_tcp.go)
   и original mapping/capture до Dial: видимый Host/SNI, current client/MAC/iif,
   числовой real target из reviewed answer. Synthetic mapping ограничивает
   capture положительными именами; unmatched traffic не получает owned path.
   Native NFQ hostlist может выбрать имя до Lua mutation, но сам факт
   generic queue admission не обещает, что исключённый hostname вообще не
   попал в NFQUEUE. Это разные уровни покрытия.

3. **Расширить существующий leaf, а не только включить App-флаг.**
   [domain_policy_tcp_capture.go](../../internal/dataplane/domain_policy_tcp_capture.go),
   строки 29–35, хранит один Client;
   [domain_policy_tcp_xray.go](../../internal/dataplane/domain_policy_tcp_xray.go),
   строки 22–29, — один Name/RealIP/ServiceID/NodeID.
   [synthetic_baseline_transition_plan.go](../../internal/dataplane/synthetic_baseline_transition_plan.go),
   строки 88–127, допускает exact names и один node.
   Обобщить их в том же owner до bounded original mapping table:
   client + ingress + name + family + service/path + realIP + TTL + generation.
   Использовать существующие mapping/publication/retirement и engine process
   ownership, не отдельный процесс или Manager на каждый домен.
   Suffix остаётся явным правилом; каждое фактическое имя проходит admission.

4. **Сохранить настоящий firmware baseline.** Для незахваченных packets —
   RETURN/no owned effect, включая уже настроенный VPN роутера.
   Для захваченного flow `BaselineDial` требует original source-specific
   baseline grant: [domain_policy_tcp.go](../../internal/dataplane/domain_policy_tcp.go),
   строки 35–40 и 125–131. Обычный `net.Dial` и loopback DNS не доказывают
   прежнюю per-client политику.
   Текущий synthetic handler, строки 272–288
   [domain_policy_tcp_capture.go](../../internal/dataplane/domain_policy_tcp_capture.go),
   не задаёт BaselineDial и принимает только positive mapping.
   При исключении/Stop сохранять prepared baseline transition/standby DNAT
   до cache/conntrack retirement; отменять и join потоки до остановки процесса.
   Это обязательная интеграция, а не готовый baseline по наличию helper.

## Приёмка и граница транспорта

Для B/C нужны реальные packets: две услуги, два allowed клиента в двух
выбранных сетях, новый DHCP клиент, исключённый MAC с новым IP и
offline/reconnect, guest/WAN/OUTPUT вне capture. Отдельно — included и excluded
имена на одном IP, exact/suffix, CNAME/TTL/cache/DoH miss, unmatched путь при
firmware VPN, атомарное исключение во время DNS/flow, AUTO, Stop/rollback/cleanup.
Часовой one-PC сценарий A сохраняется отдельным доказательством.

Первое доменное исполнение этих leaves ограничено IPv4 A и TCP HTTP/visible
TLS. UDP/QUIC/voice, managed IPv6 AAAA, ECH/opaque names и HTTP/2 coalescing
не подтверждены этой интеграцией; им нужны отдельные admitted paths и
аппаратная приёмка. Неизвестность не расширяет IP bypass и не даёт service PASS.
Эта транспортная граница не отменяет нынешнее требование 0.20 собрать общий
LIST и доменные исключения в поддержанном TCP пути.

Auth, CAS, ownership, recovery, Stop, known infrastructure negatives и
ambiguity/router fences сохраняются. Общий conntrack flush, молчаливый broad-IP
bypass, catch-all upstream hostlist и новый универсальный controller не входят
в предложенный порядок.
