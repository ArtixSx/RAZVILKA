# DEFAULT: adapter boundary и destination ownership

04.10.2026. Узкая законченная порция поверх `7ce1f0c`: общий pure NodeStore validator `ValidateRouteDestinationOwners([]RouteBinding)` используется MaterializeSingBox/MaterializeXray до чтения private material и независимым scoped Xray config validator. Нет второго policy parser, нового worker/journal или новой DEFAULT authority.

Один managed TUN передаёт поток fixed SOCKS listener. Этот переход не передаёт исходный LAN source в routing engine. Поэтому source-disjoint RPDB cells с пересекающимися CIDR/domain назначениями **разных nodes** не дают исполнимый per-source выбор exit. Теперь вложенные/равные IPv4/IPv6 prefixes и пересекающиеся нормализованные domain suffixes разных owners отклоняются независимо от порядка. Один node может иметь вложенные scopes; разные nodes с disjoint destinations допускаются. Destination validator не заменяет exact engine/service/WAN/origin proof.

Вход bounded до128 bindings и512 raw domains+destinations суммарно, до deduplication. Строки до256 bytes, DNS labels валидируются, mapped IPv4 не принимается. Эти bounds не повышают common forwarding capacity и не объявляют широкие CIDR public complement. Adapter scoped route limit64 сохранён. Refusal происходит до engine/process/RPDB mutation.

Проверки: полный Windows NodeStore PASS; scoped Xray/proxy generation/rollback retry group PASS (11.348s); Windows vet и Linux amd64 compile/vet обоих packages PASS. Новые tests обоих engines: prefix/domain nesting, reversed ordering, label boundary, same-owner/disjoint acceptance, raw bounds, fresh/expired/wrong-engine proof isolation. Adapter проверяет тот же shared validator.

## Следующие согласованные зависимости

CORE готовит Route.NetworkPolicyGeneration/NetworkPolicyRole/Ingress и PolicyRule.Ingress, PolicyState.NetworkPolicyGeneration/NetworkDefault, `CORENetworkPolicyRouteAuthority`. DEFAULT consumer возвращает source×destination×ingress cells, negative source/MAC gates исполняет общий owner. Generation/role сами по себе не являются service/default consent или LAN proof.

Common policy_forwarding/policy_lan capacity128 превышается public complement ещё до fanout. Его изменение и единый pre-mutation budget принадлежат CORE; здесь bound не повышен. Полный multi-node default на одном adapter требует source-aware sidecar contexts или отдельных owned engine instances/ports, а не сортировки destination rules. DOMAIN-flow bridge остаётся отдельным contract: DNS IP map не является flow identity.

Current scoped Xray inbound UDP disabled; Health/NodeTUNProbe и существующий native fixture проверяют IPv4 HTTPS/TCP. Generic source-scoped Health проверяет FIB/firewall и может делать literal SOCKS probe, но не доказывает forwarded TCP/UDP × IPv4/IPv6 default. Synthetic default service ID не приобретает NodeStore proof/consent из одного service PASS. Полная DEFAULT materialization/forwarded health и production LAN verifier продолжаются после shared primitives/authority API; NETWORK_POLICY_EXECUTOR_REQUIRED и generic Xray node-capability не снимаются.

CORE actual effect admission должен стоять вокруг bounded exec.Cmd.Start, с sealed InstallationID+Sequence+effectID из trusted context. Весь ProcessController.Start содержит fs writes/readiness и не удерживается под control lock. VLESS own callsites: canary, Activate/Reconcile/rollback pair, package init start, node-check child/syntax/version commands. Cleanup/read authority отделяется общим CORE action API.

Координатор сообщил native-kernel12/source31 `d010e13` RC0:12 real receipt os.Exit boundaries, foreign kernel preservation, native scoped Xray A/B failure→A rollback с selected/control и stock Sing-box1.14.2/Xray26.3.27; WG actual rollback retry также RC0. Это evidence прежнего proxy receipt lifecycle, не full DEFAULT/D03/D10/app/router HIL. CORE отдельно исправляет два ранее переданных fixture boundaries без ownership fallback.
