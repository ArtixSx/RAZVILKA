# Один зарегистрированный Xray owner: generic и exact-node

## Граница порции

`NewXrayRuntimeAdapter` и существующая app-фабрика `NewXrayNodeRuntime` создают одного зарегистрированного owner для legacy `Resolved="xray"` и canonical `Resolved="xray:node-ID"`. API фабрики, private NodeStore materializer и FreshProfile owner сохранены. Main-файлы и held CORE main checkpoint не входят в эту порцию.

Startup flags зарегистрированного adapter не меняются. Каждая операция получает отдельную value-copy view: generic использует прежний managed SOCKS/TUN путь, node требует существующие exact scope, process/manifest, NodeTransit receipt и actual TUN HTTPS proof. Generic fallback после ошибки scoped пути отсутствует.

## Выбор до побочных действий

Полный исходный frozen Plan классифицируется до RoutePlanFor, callback, materializer или runtime effects. Mixed generic/node, malformed node ID и скрытая selected Xray intent отказывают. Canary отдельно проверяет точный Adapter и исключительно Xray routes. Empty candidate отказывает; full retirement Plan может только захватить/восстановить прежний runtime.

Snapshot сохраняет candidate и previous mode в private transaction JSON до Stage/Activate. Previous mode выводится из целого captured engine/sidecar/manifest/interface набора; marker не даёт самостоятельной runtime authority. Legacy captured generic header допускается только при корректном полном старом наборе. Каждая операция удерживает canonical hash исходного snapshot, включая форму отсутствующего legacy marker, и identity исходного каталога. Они проверяются после admission callbacks и перед первой записью/изменением policy; старый режим сохраняет этот seal при rollback publication. Смена marker, других captured данных или подмена каталога даже с идентичным snapshot отказывает.

Committed runtime mode читается bounded и descriptor-anchored, без WAN, DNS, process/runner или materializer callbacks. Частичный/повреждённый scoped набор не может стать generic. Live node требует interface lease; cold classification дополнительно требует отсутствия PID и transport markers. Deactivate использует тот же строгий current-mode reader.

## Переход и возврат

При A→B старые process specs, sidecar RouteProof, policy и node interface проверяются через view режима A. Перед удалением A сохраняется существующий durable unknown policy receipt. Старый owned TUN должен исчезнуть; captured node markers потребляются только при точном совпадении, чужие/неизвестные markers сохраняются с отказом. Затем запускается B без изменения startup owner.

Rollback сначала очищает candidate B своим режимом, затем восстанавливает A его режимом. Старый scoped interface lease не копируется как новая authority: при восстановлении создаётся текущий lease. Fresh-owner retry использует durable receipt phases и captured A, включая точные ProcessSpecs/RouteProof; read-only VerifyRollback также проверяет A.

## Bounded snapshot reader

Private snapshot reader ограничен 64 MiB до allocation/decode, повторно проверяет root/file identity и неизменность bytes. Duplicate keys, включая case aliases Go decoder, unknown keys, trailing/null JSON и unsafe file shape отвергаются. Snapshot может содержать несколько bounded config images и быть больше 4 MiB; отдельный scoped Xray/XHTTP JSON admission сохраняет прежний лимит 4 MiB. Captured interface image ограничен 4 KiB до копирования и разбирается строго.

## Проверки и ограничения

Portable public fixtures проверяют generic/node полный lifecycle, обе стороны A→B→rollback, Stage failure с сохранением A, retirement Snapshot, fresh-owner rollback retry, legacy generic header, plan/marker drift, wrong Canary Adapter/foreign routes и отказ malformed/mixed intent до effects. Bounded reader fixtures покрывают корректный snapshot больше 8 MiB и повреждённые/oversize варианты. Конкретные результаты isolated tracked archive передаются с checkpoint SHA.

Эта worktree выполняет portable tests и compile-only Linux проверки. Actual main/Manager execution, Linux/native TUN, router/VM и account/live probes принадлежат ROOT; portable PASS не подтверждает их. ROOT-owned native QA files не изменяются. Отдельный принятый USQUE consumer `1af0877` не смешан с этим checkpoint.
