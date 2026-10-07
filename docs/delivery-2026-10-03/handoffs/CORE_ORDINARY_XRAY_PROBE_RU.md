# CORE: обычный Xray node plan сохраняет каталоговый predicate

Законченная независимая порция на accepted `c0c235255f32069f87765fe2f755641f3fe434b0`, ветка `sol/core-main-wiring-20261007`. Ordinary main/default wiring продолжается отдельно; эта порция не выдаёт default transport или новые process/tool capabilities.

`App.buildDataplanePlanWithDNSContext` для exact `xray:node-*` сохраняет `LogicalServiceID` и полный глубокий clone текущего `catalog.Service` в `Route.ProbeService`, включая выбранные сценарии, вложенные ожидания и provenance. Источник — существующий каталог App. Поля не поступают из HTTP. Existing Build/FrozenProbeService validation и node/autonomy revision, catalogue-definition, WAN и node-generation guards остаются обязательными.

Это устраняет конкретный producer gap: actual Xray Stage/nodeRequestServiceID требовал FrozenProbeService, но обычный App/autonomy plan передавал только ProbeURL. Прежние per-service и retained/autonomy пути используют тот же builder. Sing-box candidate failure attribution не расширена; Xray error/403 без independently typed matching receipt сохраняет conservative halt/no-next-candidate.

Регрессия проверяет обычный builder с реальным строгим predicate validator: nested catalogue drift не изменяет sealed plan и отказывает existing review guard до effects. Existing Xray HTTP Apply, stale/replayed review, changed engine/history/WAN, rollback, retained plan и D10 модели проходят. Xray-only fixture дополнена обязательными Category/Strategy существующего validated catalog schema; валидатор production не ослаблен.

Проверки: адресные Windows App tests PASS5.987s; весь Windows App package PASS227.578s; Windows app/cmd vet RC0; Linux amd64/arm64 app/cmd vet и App test binary cross-compile RC0, временные binaries удалены. Native/Linux/race/router/VM здесь не запускались. VERSION, main, DEFAULT/NFQ/NET/netidentity не изменены.
