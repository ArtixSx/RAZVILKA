# CORE: активный список и отдельные исключения, 2026-10-08

Это законченный первый контракт конфигурации/API по пользовательскому файлу
`RAZVILKA_LIST_MODE_EXCLUSIONS_CORRECTION_2026-10-07.md`. Он не является
приёмкой всего runtime list mode, DNS, Apply, восстановления или клиента LAN.

Ветка: `sol/core-list-exclusions-20261008`. Прямой родитель:
`0438dd9377ffcf8f0c2b5d311d94a060d14f66ec` — retained consent owner,
исходный контекст операции и control/source bookends. Root интегрирует родителя
вместе с этой коррекцией, без отдельного включения прежнего `all_except` writer.
Остальные незавершённые изменения других веток не входят в пакет.

## Сохранённая конфигурация

В том же фактическом `config.json`, внутри `NetworkPolicy`:

```text
resource_exclusions: {
  schema: 1,
  revision: uint64,
  manual: [{kind, value}],
  russian_snapshot?: {catalog_id, revision, digest, entries: [{kind, value}]}
}
```

`ResourceMatch.Kind`: `service`, `exact`, `suffix`, `ip`, `cidr`. `suffix`
явно включает базовый домен и поддомены по границам меток. Домены/IDN
канонизируются, URL/маски/TLD запрещены; точный IP и CIDR проверяются, CIDR
не исправляется скрытым маскированием. Повторные записи, в том числе IDN
алиасы, отклоняются. Source data не содержит argv, пути исполнения или grant.

Ручной список и последний принятый RU-снимок независимы. Пропущенный manual
сохраняется, явный `[]` очищает только manual. Отсутствующий RU-снимок сохраняет
предыдущий. Пустой/некорректный/повторный/с чужим digest обновлённый снимок
отклоняется атомарно, включая одновременно переданный manual patch.
Digest снимка вычисляется `RussianSnapshotDigest` из канонического содержимого.
Автоматическая смена CatalogID пока отклоняется; отдельного source fetcher
или утверждения о проверенном сетевом RU-источнике в этом пакете нет.

`Russian.Enabled=false` сохраняет принятый снимок и ранее явно сохранённые
legacy-отрицания, но выключает их участие и разрешение автообновления.
Manual продолжает участвовать. Существующие frozen `Russian.ServiceIDs` /
`BroadTLDs` и `Rules` с `Action=direct` остаются отрицаниями; новые TLD/ASN/CDN
из факта русскоязычного сервиса не выводятся. Legacy device-scoped direct
сохраняет условие DeviceIDs. Положительный Mandatory не отменяет отрицание.

## Readonly API для владельцев

- `ValidateListNetworkPolicy(p)`: текущая семантика только selected_services;
  исторический all_except строго декодируется, но новый intent запрещён.
- `EffectiveResourceExclusions(p) (EffectiveExclusionSet,error)`:
  detached canonical `PolicyRevision`, `Revision`, `Clients`, `RussianEnabled`,
  `Manual`, `Russian`, `RussianSnapshot`, `LegacyRussian`, `LegacyRules`,
  `BroadTLDs`, `Digest`. Digest включает все действующие отрицания и client
  conditions/источник. Nil policy или nil exclusions не придумывает revision:
  exclusion revision=0; policy revision фактическая или0; match arrays пустые.
- `ResourceTarget{ServiceID,Domain,DeviceID string; Address netip.Addr}`;
  `ResourceExcluded(p,target)` / `EffectiveExclusionSet.Matches(target)`:
  достаточно одной известной resource identity. Нет положительного grant.
  Пустой/некорректный target — ошибка. При совпадающем legacy resource negative
  со scoped DeviceIDs и неизвестным устройством — ошибка, не молчаливый bypass.
- `Store.WithResourceExclusionObservation(ctx,expectedConfig,use)` закрывает
  наблюдение SAME actual Store: полный Config до/после, revision и точные
  фактические bytes disk image до/после через прежний WithRevisionObservation.
  Callback получает detached set. Он **не должен вызывать этот Store или
  получать App operation gate**, пока удерживается существующий Store RLock.
  Original operation admission получают заранее. Method не выдаёт positive,
  physical scope, control, provider, effect или executable permission.

NET/DEFAULT/VLESS/AUTOPILOT должны привязать реальные positive targets,
client/physical scope и route proofs к этому SAME snapshot; после изменения
exclusions текущая config revision отзывает старый grant/queue/Apply.
Для долгоживущего runtime используется реальный retained owner и новый
ограниченный контекст при каждом использовании, а не истёкший HTTP token.

## Запись и HTTP

`Store.UpdateResourceExclusions(ctx,fullExpectedConfig,manualPointer,accepted)`
делегирует `UpdateResourceExclusionsPatch` с необязательными RussianEnabled /
RussianAutoUpdateAllowed. Все три config/policy/exclusion revisions увеличатся
один раз, полный preimage и прежний disk CAS обязательны. Сохраняется только
намерение; AppliedServices/AppliedNetworkPolicy/SafeMode не включаются.

GET/POST `/api/v1/networkpolicy/exclusions`: actual auth, CSRF, исходный
exclusive operation context; GET только читает. POST без дополнительного
confirm для обычного явного редактирования исключений:

```text
expected_revision, expected_policy_revision, expected_exclusion_revision,
manual?, accepted_russian_snapshot?, russian_enabled?,
russian_auto_update_allowed?
```

Явный JSON null для любого patch field отклоняется, неизвестные поля тоже.
Для отсутствующей NetworkPolicy GET разрешён, POST возвращает503
`NETWORK_POLICY_SCOPE_REQUIRED`: первая порция не создаёт Home/allLAN scope.
**Сохранение неактивных исключений на новой установке без configured scope —
отдельный обязательный product follow-up.** Scope validator для Apply не ослаблен.

Ответ GET/POST: `ok`, `revision`, `policy_revision`, `exclusion_revision`,
`resource_exclusions`, `russian_enabled`, `russian_auto_update_allowed`,
`effective`, `applied_revision`, `applied_effective`, `desired_matches_applied`,
`live_applied:false`. Совпадение desired/applied — только сравнение записанного
policy intent, не runtime/client health. Domain/IP negative не означает
whole-service live exclusion. UI получает отдельные retained/active source данные.

Ошибки:400 `NETWORK_POLICY_EXCLUSIONS_INVALID` / `NETWORK_POLICY_LIST_REQUIRED`;
409 `NETWORK_POLICY_EXCLUSIONS_CHANGED`;503 `NETWORK_POLICY_EXCLUSIONS_UNAVAILABLE`
или `NETWORK_POLICY_SCOPE_REQUIRED`, плюс прежние auth/CSRF/gate ошибки.

Новый DefaultRouteConsent имеет Schema2 и selected_services. Прежний Schema1
all_except строго сохраняется/читается как исторический, но никогда Current.
Path/source consent не является resource/client routing grant. Обычный
`/networkpolicy/review` не меняет retained resource negative state:409
`NETWORK_POLICY_EXCLUSIONS_SEPARATE`; all_except:400 LIST_REQUIRED. Обычная
config edit не обновляет approval. Изменение исключений отзывает старую approval
через полный ConfigRevision. Только прежний точный sanctioned commit допускает
неизменённый approval postimage, без расширения области или срока.

## Проверки и границы приёмки

Windows actual portable models PASS: config3.625s, defaultconsent1.308s,
nodestore5.044s, operationgate1.210s. API/default/exclusive focused App3.703s;
main0.085s (по этому фильтру tests отсутствуют, package compile PASS).
После финального readonly seam: config targeted0.443s, defaultconsent1.089s,
App0.259s PASS. Windows vet touched config/defaultconsent/App/main PASS.

Linux amd64/arm64 vet и config/defaultconsent/App/main test cross-build PASS.
Это **не** выполнение Linux/race/native/router тестов. Бинарники для Root:
`.review-local/core-list-{config,defaultconsent,app,main}-linux-{amd64,arm64}.test`.
Root может выполнить реальные config/consent/HTTP regressions и race из source.

Тесты проверяют повторное чтение конфигурации, clone isolation, атомарный отказ
плохого feed, disable/re-enable без удаления, manual clear отдельно, точную
domain/IDN/subdomain/IP/IPv6 границу, mandatory precedence, legacy/device scope,
эффективный digest, stale/same-revision/disk CAS, closing cancellation/file
replacement, реальный HTTP auth/CSRF/no-write GET/no invented fresh scope и
запрет старого full grant/ordinary-negative overwrite.

Root/DEFAULT/NET/UI/OPS получили контракт до реализации и согласовали ownership.
VLESS node-specific admission отдельно; autonomy_worker принадлежит AUTOPILOT.
Candidate diagnostic требует actual active primary service и разрешённый путь,
а вспомогательный CF/ipify endpoint должен пройти current negative проверку до
probe/redirect/pinned IP; исключённый endpoint даёт отказ/inconclusive, не bad node.

Открытые обязательные потребители: actual positive classifier/route proof DEFAULT;
DNS request/answer/CNAME/A/AAAA/Publish NET; candidate/Record/queue/failover hooks;
fresh post-Apply owner; preservation/current-negative route compatibility OPS
при restore/recovery; actual COMMON/NFQ/Linux client acceptance. Прежний third-
config-image recovery fence не ослаблен. DTO/hash/старый runtime snapshot не
заменяют актуальный owner, и этот пакет не объявляет такие проверки пройденными.

Следующая законченная порция: `defaultconsent.Review.CheckProbeTarget(ctx,
hostname, pins []netip.Addr)` проверяет hostname и весь набор literal pins через
реальный retained source/control/config owner до диагностического leaf. Это
отрицания domain/IP; actual primary/aux service-kind catalog classification,
client intent и positive path остаются обязательными в original App review.
Нет DNS/dial/callback effect под Store RLock. Zero/copied/released/stale handle
отклоняется. Excluded даёт `ErrProbeTargetExcluded`, неопределённый target —
`ErrProbeTargetUnknown`; producer не должен классифицировать это как bad node.
Windows defaultconsent1.256s и vet PASS, Linux amd64/arm64 vet/test cross-build
PASS; реального Linux/native probe CORE не выполнял. Бинарники Root:
`.review-local/core-probe-target-linux-{amd64,arm64}.test`.
