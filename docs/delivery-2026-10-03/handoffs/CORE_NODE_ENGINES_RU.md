# CORE D02: точный app dispatcher, первая порция

04.10.2026 reader3 follow-up: accepted NodeStore checkpoints `516f014`,
`b0d27a9`, `30b432f` normal-merged into CORE. Actual capability CLI already
uses the typed supported reader constant, now 3; its subprocess regression
requires the exact canonical version line. Existing RAW Xray retained state
remains readable by both reader2 and reader3, and reader1 still refuses it.
Targeted cmd NodeHistory/ConfiguredNodeCheckers tests passed 0.243s; diff RC0.
This finished fixture correction does not enable unchecked XHTTP ingress.
OPS owns the separate scanner/admission reader3 follow-up; CORE and XHTTP are
coordinating typed pre-write admission for manual import, feeds and restore.

RAW write compatibility follow-up: the app's Xray check/route admission now
requests the frozen minimum reader2 rather than the supported reader3. OPS
still checks the maximum across every current/retained private image and
controller; this does not admit XHTTP against a reader2 controller. Manual
import previews use the same canonical parser as NodeStore persistence. The
partial-import regression now uses an actually unsupported XHTTP mode instead
of a transport that NodeStore supports. App NodeEngine/XrayNode/NodeExact/
NodeImport/NodeHistory targets passed 1.996s with Windows journal tests enabled;
vet/diff RC0. The first-write XHTTP ingress callback remains a separate owned
API dependency, not a completed capability in this checkpoint.

04.10.2026 retained admission dependency завершена отдельной OPS порцией `5ca485f750c9113b4f7c8e9c5bcd257792cb6795`, branch `sol/ops-20261003`, parent только `eba8abe`. CORE normal merge `18edfcf`; provider WIP не включён. Main подключает `updatecheck.NewNodeHistoryAdmission(nodestore.RequiredPrivateHistoryReadVersion, nodestore.ExactHistoryReadVersion).CheckWrite` к `App.NodeHistoryWriteGuard`. Callback проверяется до probe и перед RecordCheck; отказ OPS API возвращает503 `NODE_HISTORY_ADMISSION_REQUIRED`, без history/probe/fallback. До первой write2 проверяются future maximum2 и sealed retained old/new/legacy backup controllers, exact installed kernel executable identity, bounded reader flag; pending/orphan/unknown/reader1 блокируют. Config/state roots production fixed `/opt/etc/razvilka` и `/opt/var/lib/razvilka`, независимо от ordinary config override. Temporary noninstalled controller не обходит identity. Generic Xray node Apply по-прежнему требует actual scoped materializer + independent NodeTUNProbe; этот gate их не подменяет.

Проверки finished dependency в CORE: updatecheck NodeHistory/Retained/Admission .800s RC0, selfupdatejournal BinaryImages .344s RC0, cmdtypedCLI .246s RC0, shell actual before/afterStop gate PASS в Git Bash (old target/version-only/error refuse; exact marker success). Consumer NodeEngineHTTP/NodeHistory/XrayNodeRoute app1.305s/cmd.253s RC0, vet app/cmd/updatecheck/selfupdatejournal RC0. Local fixtures моделируют executable identity/capability, native production image/probe/fsync acceptance остаётся координатору. В следующих исторических разделах «guard nil/OPS WIP» описывает предыдущие checkpoints, заменённые этим finished dependency/wiring.

04.10.2026. В sol-core нормально merged VLESS `0669514` (`6677b5c` merge commit), затем подключён один `ExactNodeDispatcher` в main. Общая квота **2**, не 2+2; фиксированные Sing-box/Xray views используют отдельные private roots и непересекающиеся портовые диапазоны existing adapters. Startup recovery вызывается один раз через общий dispatcher; ошибка сохраняет собственный poison fence concrete engine и не включает другой engine вместо него. Constructor не пишет state и не запускает probe.

`POST /api/v1/nodes/<id>/check` принимает optional exact `engine`: `sing-box` либо `xray`; отсутствие сохраняет Sing-box для прежних клиентов. Engine не задаёт binary/path/argv. Unsupported/runtime/busy/WAN ошибки не записывают историю, не дают source penalty и не меняют working routes. Нет автоматического fallback. Existing auth/Origin/CSRF/strict JSON остаются. Перед RecordCheck совпадают node/service/fresh WAN/route prefix; positive service evidence также связывает engine и expected/observed path. Positive diagnostic evidence в unavailable result не может быть от другого engine. Result path не переписывается app. Cancellation после Check имеет отдельный interrupted result, а не ложный WAN change/PASS. Existing generation/current-node CAS и повторный свежий WAN сохраняются.

Для production Xray history write введён trusted `App.NodeHistoryWriteGuard(ctx, requiredVersion)`: перед Check и снова под record lock перед записью. **В main callback пока nil**, поэтому Xray HTTP возвращает 503 `NODE_HISTORY_ADMISSION_REQUIRED` до DNS/probe/record. OPS должен поставить фактический downgrade/retained-state admission, прежде чем включить записи; permissive default отсутствует. Это порт сопряжения, а не уже пройденный gate. Read-only capability CLI `-node-history-read-version` печатает VLESS `nodestore.ExactHistoryReadVersion` **2** до любых startup writes. Node envelope schema4 и typed history read capability2 — разные версии.

## Boundary OPS для следующей порции

OPS WIP `RequiredRetainedNodeHistoryReadVersion(ctx, configRoot, stateRoot, read NodeHistoryReader)` прочитан readonly, не merged и не заменён CORE scanner. CORE передаст именно VLESS `nodestore.RequiredPrivateHistoryReadVersion`, включая его hash validation. OPS сканирует current/retained restore/backup images и проверяет capabilities candidate/old/rollback binary; unknown/corrupt record запрещает admission. Одна CLI способность текущего binary читать2 не подтверждает совместимость rollback binary. Нужен concrete readonly write guard, также не позволяющий создать несовместимый образ между precheck и final RecordCheck. Синхронизацию с self-update/private restore даёт existing operation admission; callback не должен брать Store lock с обратным порядком.

Согласованный durable Stop должен иметь один CORE authority и linearized spawn/effect admission. Уточнение и small OPS boundary опубликованы в `CORE_SELF_UPDATE_STOP_CONTRACT_RU.md`; readonly StopCheck сам по себе не закрывает TOCTOU. CORE не копирует uncommitted OPS provider и не повышает `-self-update-schema` выше0. Новая порция лежит поверх `7b8db16`; удерживаемая координатором self-update foundation присутствует в ancestry, поэтому merge всей ветки требует её отдельного acceptance.

## Проверено здесь

- Windows Go1.26.5, GOMAXPROCS2/GOFLAGS-p2/GOTOOLCHAINlocal: `go test ./internal/app ./cmd/razvilka -run 'Node|Autonomy' -count=1` **RC0**, app75.563s/cmd0.177s; `go vet ./internal/app ./cmd/razvilka` RC0.
- Настоящие httptest HTTP/security/gate/nodestore fixtures: два разных exact histories/read capability2 в current/exported private image; wrong engine/path/node/service/profile/evidence/direct-leak без record/measurement/fallback; unsupported/runtime/busy/WAN/guard revocation; invalid engine/auth/Origin/executor injection; legacy Sing-box default. Native probe evidence **моделируется только в fixture**, не является native/HIL PASS.
- Linux/arm64 main build RC0; Linux/amd64 app test compile RC0; outputs только TEMP, удалены. `git diff --check` RC0.
- Первый broad run RC1: legacy positive fixtures не имели service evidence. Исправлены явные fixture builders, production proof check не ослаблен. Следующий broad run обнаружил masked post-check cancellation; добавлена context check до identity validation, финальный broad run выше RC0.

Native/race здесь не выполнялись; опубликованные координатором Xray/Sing-box fixture PASS относятся к VLESS `0669514`, не к app HTTP этой порции. Общая quota/recovery library не изменялась CORE.

## Осталось

D02/D03 ещё открыты: engine-specific job intents/bulk/recovery/autonomy, route syntax/options/ResolveRouteForEngine, scoped Xray app materialization с настоящим LAN proof provider, apply/rollback/restart и downgrade guard. Scoped Xray adapter уже в merged ancestry, но main пока не включает его как selectable LAN executor. Generic Xray не подменяет scoped node routes. D07 common LAN/default executor и DNS semantics не реализованы этой порцией; `NETWORK_POLICY_EXECUTOR_REQUIRED` сохраняется. Durable Stop consumer и pre-files Stop/private-state order также ещё не готовы. Router/VM/shared ports/opkg не трогались.

## Следующая законченная порция: engine-bound manual route consumer

04.10.2026. Shared `routekind.ParseNodeRoute` строго сохраняет engine и canonical node/group ID. App planning/options/general ApplyReview/retained proof теперь вызывают VLESS `ResolveRouteForEngine`; прежний committed node участвует в group hold-down только в том же engine. Xray node/group требует свежий network epoch и в общем Plan, и в candidate RoutePlan; legacy journal без epoch читается, но authority не получает. Node editor drafts обоих engines не потребляются service/node Apply.

Optional exact engine проходит preview→одноразовый owner-bound review→синхронный или durable NodeApply→exact config route/scope commit. Review/Plan digest, current node generation, свежий WAN и typed service proof сверяются при каждом transaction guard. Durable Xray intent сохраняет engine; default Sing-box сохраняет legacy canonical empty field/request hash. Health failure/WAN change вызывает существующий rollback, engine fallback отсутствует. Config commit принимает exact Xray node syntax, reload/CAS/guarded undo и manual policy pin сохраняются. Node/group delete и общий protected cleanup учитывают Xray references.

Production selector отличает generic Xray adapter от scoped factory: `Manager.XrayNodeRouteCapable()` требует concrete scoped backend, materializer, fresh-profile и nonnil independent NodeTUNProbe. Missing verifier/history gate не публикует Xray node option. Main пока имеет generic backend: production Xray node Apply по-прежнему недоступен; native verifier/actual scoped materialization/startup recovery остаются работой сквозной D03, а не PASS от этой проверки наличия callback. HTTP fixture явно моделирует adapter effects и только проверяет CORE consumer.

Проверки: broad `go test ./internal/app ./internal/config ./internal/routekind ./internal/dataplane -run 'Node|Autonomy|ApplyReview|Xray' -count=1` RC0 (83.392s/0.526s/0.190s/8.231s); vet этих packages RC0. Real httptest/security HTTP доказывает Xray review/apply scope, отсутствие заимствования Sing-box proof, wrong engine/revoked admission до effects, health/WAN failure→rollback, exact committed prefix/network, spent review и durable retry без replay. Дополнительно generic/scoped-without-LAN-probe selector refusal, config reload/policy pin/undo, Xray candidate/legacy network fence. Race/native здесь не запускались. OPS dependency согласовывается напрямую по явному разрешению пользователя; finished retained scanner `eba8abe` доступен в общем Git, ещё не merged в этой route порции.

## Сопряжённый CORE CLI для OPS retained scanner

Normal merge `eba8abe9e524cb450b49c4fc76a73aab9e139789` → `58c1f39`; ancestry также содержит уже accepted coordinator OPS supervision fixes до3daf179. Ни один uncommitted sol-ops provider/Stop/private-state файл не переносился. `-check-node-history-state` теперь выполняет scanner с actual VLESS `RequiredPrivateHistoryReadVersion`, сравнивает максимум required с actual reader2 и при успехе печатает ровно `{"ok":true}`. Любой corrupt/unknown/error/cancelled/unsupported reader даёт nonzero и generic stderr без private данных. Flag выполняется до config normalization/Store/bootstrap/worker. Production defaults config root `/opt/etc/razvilka`, state root `/opt/var/lib/razvilka`; явно заданные absolute `-node-history-config-root`/`-node-history-state-root` служат изолированным trusted CLI стендам и не следуют обычному `-config`. HTTP root/path/version не задаёт.

CORE actual subprocess/typed-reader fixtures: Xray current image reader2 PASS, reader1 refusal, legacy reader1 PASS, corrupt retained backup refusal без private stderr, byte-identical live nodes, empty/missing roots без создания, canceled empty scan и relative-root refusal. `go test ./cmd/razvilka ./internal/updatecheck -run 'NodeHistory|RetainedNode' -count=1` RC0 (0.243s/0.557s), vetRC0. После route portion и OPS merge Linux/arm64 main build и Linux/amd64 app test compile RC0 (TEMP only, удалены), diffcheckRC0. Native/fsync/race не заявлены. CLI закрывает target-reader/retained-image часть, **не** заменяет first-Xray-write admission: OPS отдельно выделяет digest/capability gate для retained old/new/rollback executables и actual shell pre/post-Stop consumers. Production Xray guard пока закрыт до этого коммита.
