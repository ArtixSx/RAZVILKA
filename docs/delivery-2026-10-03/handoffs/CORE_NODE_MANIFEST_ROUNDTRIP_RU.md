# CORE: сравнение scoped Xray после manifest round trip

База: `a3adc52f601eca300a7b75836a11e46535d6d8f5`, уже принята Root как
`733db77`. Ветка `sol/core-main-wiring-20261007`. Порция независима от WIP
DEFAULT / VLESS / NET / OPS.

`BuildAt` возвращает непустые представления пустых optional списков Domains,
SourceRefs и Ingress. JSON `omitempty` не записывает их, и чтение реального
`nodes.json` возвращает nil. Прежний `checkScopedNodeState` сравнивал эти Go
представления напрямую и ошибочно возвращал `ErrNodeEndpointChanged`.
То же происходит с optional каталоговым Probes и пустыми ожиданиями probes.

Фикс ограничен **одним сравнением** scoped routes. Его приватная canonical
копия нормализует только пустые optional списки, у которых manifest JSON
действительно использует `omitempty`. Полные scalar/pointer/catalog/source/
generation/node/transport поля и порядок непустых списков сохраняются.
Обязательные каталоговые Domains / Strategy не нормализуются. План и прочитанный
manifest не переписываются; остальные `reflect.DeepEqual` не меняются.

Регрессия вызывает настоящий `BuildAt`, публичные Snapshot / Stage, запись
`nodes.staged.json`, чтение через `readNodeManifest` и `checkScopedNodeState` с
проверкой runtime config/sidecar/endpoint/profile. Используется существующая
stateful OS модель; native Linux и сетевой доступ не выполняются.
Отдельно проверены обычный web predicate без named probes, named predicate,
сохранение исходного плана и отказы при изменении body marker, status,
provenance, strategy или её порядка, source refs/source, generation, role,
ingress, node, profile и transport reference. Обязательные catalog null / []
остаются различными.

Доказательства:

- До фикса обе реальные compiled serialize/read регрессии воспроизводили
  `ErrNodeEndpointChanged`; после фикса финальный focused прогон PASS **0.226s**.
- Windows scoped Xray / dispatch / retirement / XHTTP / node router / transit /
  predicate модели PASS **92.498s**.
- Связанные App ordinary Xray модели PASS **1.149s**.
- Windows vet dataplane / app / main RC 0.
- Linux amd64 / arm64 vet и полный dataplane test cross-build RC 0.
- gofmt / diff check: чисто. Native Linux/race/router/VM — только Root.

Scope: только `proxy_nodes.go`, новый test и этот handoff. Ни default consent,
ни actual default transport proof / LAN grant этим сравнением не выдаются.
Новый default source owner VLESS остаётся отдельным prerequisite без service
PASS или разрешения на эффекты.
