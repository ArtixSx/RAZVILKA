# CORE D02: точный app dispatcher, первая порция

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
