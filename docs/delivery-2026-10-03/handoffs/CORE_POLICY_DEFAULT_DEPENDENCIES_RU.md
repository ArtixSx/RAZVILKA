# CORE → NET/VLESS/DEFAULT: negative RPDB dependencies with frozen LAN

04.10.2026. Это read-only helper, не deletion/activation/adoption authority и не отдельный ledger. Existing receipt owner вызывает проверку до durable default-remove intent и снова после него, непосредственно перед delete. Для проверки свободной transport table она также не заменяет bounded full-route table inventory и actual ownership.

```go
AssertPolicyDefaultUnreferenced(ctx, runner, ip, state, family) error
AssertPolicyDefaultUnreferencedWithLAN(ctx, runner, ip, state, family, frozen *LANPolicyRuntimePlan) error
```

Вторая функция клонирует и validates exact frozen LAN payload; его Generation должен совпадать с nonempty canonical state.NetworkPolicyGeneration. Ожидаемые negative RPDB lines выводятся тем же `lanPolicyRules` compiler и `lanPolicyRuleKey`, без второго parser и без hardcoded whitelist goto/nop. Для наблюдаемой семьи допустимо полное отсутствие gate либо ровно один полный набор anchor + всех reviewed physical-ingress skip rules. Partial, duplicate, changed/foreign ingress, mark/mask, priority/anchor, extra/unknown selector и иной goto/nop сохраняют отказ. Absent/full structural result не доказывает active classifier, membership, ScopeCheck или cleanup authority; эти обязательства остаются у common Manager participant и mixed receipt. Обе семьи проверяются владельцем отдельно; error/cancellation/read limits остаются fail closed. Старый helper без frozen payload LAN goto/nop не принимает.

Existing NET `WGEndpointState.matchesRule` и published ownership coordinates также распознают exact public-host transport lookup50/51/52 в legacy/dedicated WG table. Только известный lookup в **другую** таблицу может быть исключён из зависимостей проверяемого default. Same-table selector без exact immutable current pin сохраняет отказ. Для своего immutable pin по-прежнему нужны fresh full NET rule/host-route readback; совпавшие mark/table/argv не дают adoption/deletion ownership. Никакого процесса, WAN identity или host-route grant из этого распознавания не следует.

Зависимости: accepted shared numeric helper899/7745, EndpointTable32 + numeric textb6 + NET JSON883, LAN compiler416; normal merge accepted Root integration c49d0cb выполнен. Файлы manager.go/plan.go и LAN/NET lifecycle не редактировались CORE. Consumer owners передают только payload из того же frozen reviewed Plan.LAN/common receipt и сохраняют fresh checks до/после intent; nil/legacy payload не используется как fallback.

Windows Go1.26.5: адресные новые/старые default-dependency tests RC0 .164s; связанная матрица `PolicyDefault|WGPolicyReceipt|PolicyAdditionReceipt|LANPolicyRuntime|ManagedPolicy` RC0 13.547s, dataplane vet/diff RC0. Покрыты обе семьи, два physical ingress, absent/full/partial/duplicate/changed gate, invalid и другой valid generation, remaining same-table selector, legacy/dedicated WG coordinates, foreign mask/negation/extra selectors и read-only commands. Native kernel execution и full D07 reapply не заявлены этим checkpoint.
