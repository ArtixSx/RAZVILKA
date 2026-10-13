# Общий LIST и приоритет исключений

Дата: 13.10.2026. Исходник аудита: `1da53661d1a89a3a8a8099455bd64dd2428fd15b`.
Номера строк ниже относятся к этому commit, а не к последующим изменениям.

Конечный контракт продукта: один общий активный список сервисов действует на
выбранные домашние сети, кроме приоритетных исключений сайтов и устройств.
Остальные сайты следуют обычной политике роутера. Проверка одного ПК —
промежуточный аппаратный сценарий, который не закрывает эту область продукта.

Конфиг и отдельные компоненты реализуют существенную часть семантики, но полного
пути UI → сохранение области → общий compiler/DNS → Apply runtime пока нет.
Общий LIST и доменные исключения остаются работой до выпуска, а не только QA.

## Что реализовано и чего не хватает

| Участок | Реализовано и покрыто | Незакрытая часть |
| --- | --- | --- |
| Общая область | `ClientScope` хранит `lan_except`, выбранные сегменты, `NewDevices`, исключённые ID устройств и CIDR. | UI не редактирует эту область; мастер автоматики сохраняет другой документ с `all_lan/default_sources`. |
| API области | GET/POST `/api/v1/networkpolicy/review` сохраняет whole policy с exact config/policy CAS и явным подтверждением. Сохранение не означает применение. | Нет законченного UI выбора реальных домашних SegmentID и устройств-исключений. Discovery interface не даёт права угадывать SegmentID. |
| Исключения ресурсов | Отдельный CAS API сохраняет ручные записи и принятый российский каталог. UI независимо перечитывает результат. | Сохранённый домен ещё не имеет общего исполняемого пути с активной LIST. Старые NFQWS2 exclude-list/POLICY_EXCLUDE — отдельная authority. |
| Домены и поддомены | DomainPolicy проверяет отрицания до активных positives, включая пересечения сервисов. `exact` совпадает только с именем; `suffix` включает apex и поддомены через границу точки. | Действующий IP compiler отказывает при активных positives и доменных исключениях: требуется идентичность потока. Отказ не равен работающему применению. |
| IP и устройства | IP/CIDR исключения вычитаются из positive destinations. Известный исключённый MAC остаётся отрицанием при новом IP. | Потеря подтверждённой отрицательной идентичности вызывает отказ. Непрерывная работа с offline устройством-исключением не доказана. |
| DNS | Есть отрицания раньше pinned binding/исторического кеша и повторная проверка во время ответа. | Эти компоненты ещё не собраны в общий App Apply с DomainPolicy, flow capture и доказанной firmware baseline. |
| Managed runtime | NFQWS принимает один CIDR-only сервис; Xray — одно устройство, один IPv4 `/32`; WG source также CIDR-only. | Несколько сервисов общей домашней LIST и доменные определения этим не покрыты. |
| Новые устройства | `lan_except + inherit` допускает пакет неизвестного клиента внутри выбранной сети, сохраняя MAC/IP отрицания. | Новое устройство в физическом составе отзывает исходного владельца области; нужен отдельный защищённый переход к новой области. |

## Точный путь UI и API

- [console-autonomy.js](../../cmd/razvilka/web/console-autonomy.js), строки
  155, 166, 302, 317: `all_lan/default_sources/sources` через `/autonomy` и
  `/autonomy/services`; это не `NetworkPolicy.Clients`.
- [resource-exclusions-ui.js](../../cmd/razvilka/web/resource-exclusions-ui.js),
  строка 67: исключения устройств показаны текстом и кнопкой в devices.
  Строки 95–112: site CAS POST и независимый GET с отметкой непроверенного Apply.
- [app.js](../../cmd/razvilka/web/app.js), строки 4020–4034: устройства/группы
  разворачиваются в текущие IP и сохраняются как `ServiceState.Sources`.
  Это область отдельного сервиса, не общий negative ID устройства.
- [app.go](../../internal/app/app.go), строки 2905–2944, 2961–2988:
  GET `/devices` возвращает discovery и прежние service scope labels;
  PUT `/devices/{id}` меняет только name/group.
  [devices.go](../../internal/devices/devices.go), строки 42–52: discovery имеет
  ID/MAC/interface/IPs, но не подтверждённый canonical home SegmentID.
- [default_consent.go](../../internal/app/default_consent.go), строки 117–135,
  147–165, 188–201: существующий whole scope writer, сохранение ресурсов,
  `APPROVE_NETWORK_POLICY`, `live_applied:false`.
- [resource_exclusions.go](../../internal/app/resource_exclusions.go), строки
  37–43, 106, 147–152: отдельный resource patch; `ClientScope` им не меняется.
- [exclusions-ui.js](../../cmd/razvilka/web/exclusions-ui.js), строки 26–31,
  115, 133–137: отдельные NFQWS2 engine drafts. Общий typed LIST не получает
  автоматическую синхронизацию этих записей.

## Compiler, DNS и original runtime

- [resource_exclusions.go](../../internal/config/resource_exclusions.go),
  строки 347–360: exact/suffix/IP/CIDR matching.
  [network_policy.go](../../internal/autonomy/network_policy.go), строки
  127–155: отрицательные client identities/CIDR раньше positives; неизвестный
  либо неподтверждённый negative делает область unavailable.
- [domain_policy.go](../../internal/dataplane/domain_policy.go), строки 201–243:
  client/domain и все совпавшие service-negative identities проверяются до
  активных сервисов. Tests в `domain_policy_test.go`: строки 63, 90, 117,
  199, 209, 217, 247.
- [default_route_executor_compile.go](../../internal/app/default_route_executor_compile.go):
  строки 154–171 удаляют полностью исключённый сервис из active list;
  173–195 отказывают domain/service negatives при оставшихся IP positives;
  373–387 дают `lan_except + inherit` источники сегмента без MAC whitelist;
  388–419 сохраняют device/CIDR early negatives; 454–485 вычитают IP negatives.
  Tests в `default_route_executor_compile_test.go`: строки 154, 192, 217,
  427, 449, 459, 469. Последние два ожидают capability refusal.
- [list_dns_resources.go](../../internal/app/list_dns_resources.go), строки
  45–84: original catalog/store negative participant.
  [network_policy_exclusion_test.go](../../internal/dnscontrol/network_policy_exclusion_test.go),
  строки 58, 98: pinned/historical и in-flight отрицания.
  В non-test App/startup на этом pin нет сборки `NewListDNSResourceBinding`,
  `FreezeDomainPolicyRuntimePlan` и `NetworkPolicyDNSResolverForPlan`.
  IP compiler требует `DNSMode:baseline` (строки 132–133), а прежний App plan
  явно требует unified executor: `app.go`, строки 3829–3832.
- [domain_policy_tcp.go](../../internal/dataplane/domain_policy_tcp.go), строки
  35–40: обычный direct socket не подтверждает физическую firmware baseline.
- [list_nfqws_runtime_review.go](../../internal/app/list_nfqws_runtime_review.go),
  строки 24, 49–62: full physical scope и ровно один сервис без Domains/SourceRefs.
  [list_xray_runtime.go](../../internal/app/list_xray_runtime.go), строки 66–93:
  finite owner и IPv4 `/32`; `list_xray_finite_scope_binding.go`, строка 153:
  selected_devices/base/одно устройство. `list_xray_runtime_review.go`, строки
  111–126: отказ multiple Xray/других active non-direct services.
  `list_xray_runtime_source.go`, строка 133, и `list_wg_runtime_source.go`, строка
  92, также запрещают доменные определения.
- [list_scope_binding.go](../../internal/app/list_scope_binding.go), строки
  200–214, и [observer.go](../../internal/physicalscope/observer.go), строки
  375–378: изменение original selection/physical facts отзывает область.
  `inherit` не отменяет эту проверку. Finite исключение одного ПК не даёт
  full-LAN полномочий при unresolved-router UNKNOWN.

## Локальные доказательства и границы

Windows Go проверки на исходном pin прошли:

- выбранные App compiler/LAN negative tests: `1.126s`;
- DomainPolicy, ListPolicy и DNS negatives: dataplane `2.012s`, autonomy
  `0.450s`, dnscontrol `0.782s`;
- config resource exclusions и actual HTTP tests: `0.505s` и `1.198s`;
- две дополнительные scratch модели через Go overlay: `1.030s`.

Первая модель использует настоящий compiler с моделируемыми client facts:
новый in-LAN MAC наследует IPv4/IPv6 selected destinations, исключённый MAC
с новым адресом остаётся negative, IP negative побеждает активный CIDR,
несовпавшее направление остаётся baseline, missing excluded identity
отказывает. Вторая использует настоящие Store/control/ListScope owners с
явно моделируемыми physical facts: новый observed member отзывает owner,
возврат прежних фактов его не оживляет. Scratch не входит в этот commit.

Production не изменён. Эти проверки не подтверждают native packets, router/VM,
Linux race либо завершение cleanup. Прежний native436 FAIL не закрыт этим аудитом.

## Приоритет и зависимости до выпуска

1. UI/backend подготовка: bounded authenticated read source реальных домашних
   сегментов и устройств; explicit editor общей области через существующий
   whole policy CAS writer. Не угадывать SegmentID, сохранять неизвестные,
   исключённые и offline ID, разделять observed/desired/applied.
2. Общий original LAN owner для нескольких сервисов; защищённый переход при
   изменении состава с повторным review и завершением прежних effects. Не
   расширять guards finite `/32` и не убирать ambiguity/router/WAN отказы.
3. В той же Manager transaction/generation собрать domain/DNS, original flow
   capture и доказанную firmware baseline. Только после этого заменять
   capability refusals соответствующего пути.
4. Сквозная проверка UI save → независимый GET → plan → reviewed Apply →
   packets двух клиентов, нового клиента, excluded клиента и вне LIST;
   service↔exact/suffix/IP конфликты, shared CDN, DNS pinned/CNAME/rebind,
   atomic negative update, Stop/rollback и cleanup.
