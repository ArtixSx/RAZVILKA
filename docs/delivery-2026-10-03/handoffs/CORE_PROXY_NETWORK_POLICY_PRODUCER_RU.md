# CORE: managed PolicyState в публичных Stage / Refresh

База: `288064ae16ab4c61a2a62d3cf36eef9e9867a374`, ветка
`sol/core-main-wiring-20261007`. Независимая предыдущая порция ordinary Xray
уже принята координатором как `0f94de7`; новый коммит можно переносить после неё.

## Исправление

`ProxyTunnelAdapter.Stage` получает generation и признак default через
`NetworkPolicyRouteAuthority(plan, a.ID())`, записывает их в новый `PolicyState`
и вызывает `initializePolicyLayout` **до** `prepareForwarding`.
Раньше resolver уже создавал managed правила, но forwarding видел state без
generation и без обязательного layout 2, поэтому отказывал в staging.

`RefreshPolicy` повторно получает authority из плана и требует точного
совпадения generation и default-роли с записанным состоянием. Их изменение,
включая переход legacy → managed, требует нового проверенного Apply.
Новый state сохраняет эти поля и исходные `RuleLayout` / `SharedPriorityBase`;
refresh не мигрирует записанные kernel coordinates.

Интерфейсы и валидаторы не ослаблены. Shape/generation в PolicyState сами по
себе не дают разрешения на эффекты: свежие review, физический LAN, admission,
classifier и подтверждения владельцев остаются обязанностью существующих
Manager / App / конкретных runtime owners.

## Регрессии и проверки

Новый `proxy_network_policy_producer_test.go` вызывает публичные Stage и Refresh
с существующей stateful моделью RPDB/firewall:

- Sing-box и generic Xray, default / override, IPv4 и IPv6;
- Stage сохраняет generation, роль, layout и managed ingress без изменений kernel;
- одинаковый Refresh проверяет подтверждения без эффектов;
- изменённые selectors сохраняют managed authority и точные recorded coordinates,
  новый committed state имеет реальные подтверждения команд внутри модели;
- другая / malformed generation, смена роли и downgrade в legacy отказывают до
  эффектов, сохраняя policy, binding, forwarding и прежнюю квитанцию;
- legacy Refresh сохраняет старые координаты и отказывает в managed migration.

Windows: полный пакет `internal/dataplane` PASS **266.194s**; после дополнения
legacy/refusal регрессий их отдельный прогон PASS **1.570s**.
Windows vet dataplane / app / main: RC 0.
Связанные App ordinary Xray / node Apply / retained модели: PASS **10.149s**.
Linux amd64 и arm64: vet dataplane / app / main и полный dataplane test cross-build
RC 0. Native Linux/race, router/VM и kernel-сценарии выполняет только координатор.

## Граница порции

Только `proxy.go`, новый тест и этот handoff. Нет изменений main, DEFAULT,
NFQ, netidentity, NET, VERSION, go.mod / go.sum.
Это не готовность default exact-node transport: отдельный фактический
egress/TUN proof producer назначен VLESS, tool lease — OPS, физический scope —
NET, all-row / retire checks — DEFAULT. Их отсутствие по-прежнему означает отказ,
а не разрешение через literal `default`, каталоговый predicate или test callback.
