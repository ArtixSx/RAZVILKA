# DEFAULT: typed NFQ Spec в existing execution resources

Отдельный finished DEFAULT follow-up на принятой ROOT базе `0aed234`, ветка `sol/default-nfq-identity-20261007`. NFQ owner `ff935600` уже принят ROOT как `01c4d95`; Spec.Clone, typed owner compiler/readers и отдельный queue QA принадлежат NFQ. Этот slice не меняет NFQ implementation или запускает real/native helper.

## Привязка и копирование

`cloneExecutionResources` использует owner `NFQWSScopedSpec.Clone()` вместо копирования только Candidate.Traffic. В частности, `Spec.NetworkIdentity` и отдельный `ExecutionNFQWSDefinition.NetworkIdentity` detached от исходного resource и друг от друга. Original Plan cloning сохраняется.

Typed existing Manager scope требует typed Spec с **точно той же полной identity**: Version, Kind, BootID, Inode, PlatformReviewSHA256. Дополнительно применяется исходный NFQ validator: proc identity должна совпасть с canonical legacy `net:[inode]` и BootID; reviewed-single-init-net должна иметь пустой legacy NetNamespace, нулевой inode и исходный exact compiled stock review. Старую namespace строку нельзя преобразовать в typed singleton или иной live provider.

Registrar отказывает до создания resource childroot/journal reservation, если typed Spec передан untyped Manager либо typed Manager получил legacy-only Spec. Для cold metadata validation typed Spec и typed definition должны присутствовать вместе и совпадать; missing/mixed/foreign поля и unknown identities сохраняют recovery refusal. In-call matching также проверяет эту полную привязку. Legacy untyped Spec + untyped existing scope сохраняются для прежней временной фазы; mixed прежние typed definition + legacy-only Spec **не мигрируются и не принимаются**.

`executionHasNetworkIdentity` учитывает typed value в обоих locations, сохраняя strict compact canonical JSON в SAME latest-execution и transaction/execution journals. Codec netidentity не ослабляется. Saved identities/Spec/compiled hashes остаются intent и никогда не создают provider, actual owner, Start permit или cleanup grant.

## Проверки и ограничения

Модели проверяют compact serialize/read/recovery обоих реальных temporary journals для proc и reviewed singleton, независимые pointers Spec/definition, отсутствие alias при изменении clone, каждый из пяти foreign fields, missing Spec/definition identity, mismatched BootID/legacy namespace и typed/untyped registrar refusal без reservation/owner callbacks/kernel effects. Existing typed issuer opening/closing drift regression обновлён на actual typed Spec; legacy-only fixture не считается typed intent.

Адресные Windows temporary journal модели `TestNetworkPolicyManager.*(NFQWS|Identity)|TestExecutionJournal|TestNFQWSScopedTyped` PASS6.701s. Combined `TestNetworkPolicyManager|TestExecutionJournal|TestNFQWSScoped|TestNFQWSManaged|TestLANPolicy|TestBackendInventory` PASS34.904s. Windows/Linux amd64/arm64 dataplane/app vet RC0; Linux amd64/arm64 dataplane test cross-compile RC0. Temporary binaries удалены. Native/platform/ordinary Enable PASS этим slice не заявляется.

Active lifecycle A–E остаётся отдельной следующей фазой: current resources по-прежнему prepared/planned/process-pending/capture-ready/closed/removed, а unsettled prepared intent не может стать terminal publication. Actual NFQ owner transfer ACK/final confirmation и concrete fresh CORE committed/cleanup guards здесь не выдаются. All-row consumer bridge `8418a31` + ROOT review hardening `73049c2` находится на другой законченной DEFAULT ветке и принимается отдельно.
