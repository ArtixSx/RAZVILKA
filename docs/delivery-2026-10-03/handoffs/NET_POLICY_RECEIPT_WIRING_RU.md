# NET: WG/WARP/AWG lifecycle через общий policy addition receipt

04.10.2026. Ветка `sol/net-20261003`, отдельный checkout `worktrees/sol-net`. Общий модуль VLESS `0d49f3e` принят обычным merge `acfc4f656d9d84b038feffd7abea3373abc951c1`; его реализация, CORE policy/kernel/manager/app и NFQWS D09 не изменены. Этот checkpoint добавляет только NET wiring, NET fixtures и этот отчёт.

## Результат

`WARPWireGuardAdapter` для WireGuard, WARP и AWG больше не вызывает legacy `applyPolicy`, `removePolicy`, `replacePolicy` в Activate/Commit/Rollback/Reconcile/RefreshPolicy/Deactivate. Default routes и selectors удаляет только общий receipt, связанный с полным immutable PolicyState, boot и root. `policy.staged.json`, `policy.json`, файл runtime и `wg-interface-created` не дают cleanup authority для policy.

Production использует ту же реализацию `applyPolicyAddition`, `removePolicyAddition`, `promotePolicyAddition`, что публичные wrappers из [общего контракта](VLESS_POLICY_ADDITION_RU.md), с нулевыми options. Непубличный package-test seam подставляет boot/fault только в unit fixtures. Отдельного parser, argv из JSON или matching-readback adoption нет.

## Поколения и durable reference

На transaction создаётся новый private `wg-policy-generation/` с общим `policy-additions-v1.json`. Sidecar `wg-policy-generation-v1.json` публикуется до первого policy command; он хранит schema/checksum, boot, полный исходный PolicyState и optional random ID. Пустой ID означает transaction source. Непустой ID строго ограничен 32 lowercase hex и адресует только `StateRoot/policy-generations/<ID>/`; произвольного пути в sidecar нет.

Commit переводит единственное cleanup право в новый retained root. Transaction reference получает ID **до** transfer; поэтому Rollback после Commit находит recipient. После подтверждённого transfer публикуются retained reference в StateRoot и final `policy.json`, с private atomic write, file sync и Linux anchored directory sync. Источник остаётся promoted; recipient Removed/Unknown не принимается при повторном Commit. Transaction directory после Commit можно удалить: Stop использует retained receipt. Retained generations автоматически не уничтожаются.

PolicyState внутри sidecar заморожен. WARP Health может изменить endpoint/final runtime digest, а WG revalidation — DNS lease metadata. Эти изменения не перепривязывают full-state hash уже выданного общего receipt. Kernel shape сверяется отдельно через существующий `samePolicy`; cleanup/transfer всегда используют замороженный full state. Runtime ownership продолжает проверять финальный digest и WG public identity/mark существующими NET методами.

Snapshot сохраняет prior generation reference. Перед Stage/Activate/Rollback проверяются checksum, ограниченный ID, adapter coordinates и соответствие kernel shape snapshot. Повреждённый prior reference отвергается до cleanup candidate. Activate дополнительно сверяет текущее committed поколение с snapshot до первого live изменения; отложенный Activate с пустым или устаревшим snapshot не заменяет более поздний runtime.

## Failed activation, Rollback и recovery

Fresh AWG runtime admission происходит до durable `wg-activation-started`. Ошибка Validate/Canary/fresh gate поэтому не превращает staged policy в право удалить concurrent defaults при Manager rollback. Для предыдущего live поколения сначала расходуется общий receipt и проверяется отсутствие policy tuples, затем удаляются его endpoint и interface. Marker interface публикуется после подтверждённого start и не применяется к default/rule cleanup.

Late EEXIST, lost acknowledgement и неизвестный selector передаются общему receipt. Unknown не усваивается по совпадению kernel tuple; unknown selector удерживает defaults и interface. Rollback может очищать acknowledged subset согласно общему контракту, но не продолжает остановку interface/восстановление старого поколения после unresolved cleanup.

Rollback candidate после Commit использует recipient. Предыдущий receipt не оживляется: восстановление старого runtime получает **третье, свежее** поколение. Durable `wg-policy-rollback-v1.json` в transaction позволяет повторному Rollback подтвердить то же восстановленное поколение и закончить восстановление profile/draft без нового apply. Старый transaction не вправе retire более позднее поколение Reconcile/Refresh: ID mismatch возвращает unknown до kernel mutation.

Reconcile в том же boot расходует прежнее известное поколение, проверяет отсутствие всех его policy tuples и создаёт новое. Healthy restart не меняет ID. В новом boot старый receipt не даёт ни cleanup, ни успех apply. Новое поколение допустимо только при независимом отсутствии interface, всех policy tuples обеих семей и WG endpoint route/rule; matching foreign default также блокирует восстановление. DNS/WAN admission по-прежнему проходит до live mutation.

RefreshPolicy также использует новое поколение. Health/authority failure удаляет новый known receipt и восстанавливает прежнюю policy через свежий root. Незавершённый локальный recovery/refresh/restoration хранится в фиксированном `StateRoot/wg-policy-operation/`; наличие этого каталога блокирует последующие Snapshot/Activate/Reconcile/Refresh. Stop пытается расходовать только его собственный receipt с immutable policy, которая может отличаться от committed policy. Unknown сохраняется; broad fallback отсутствует. Settled source удаляется anchored `ownedfs.RemoveAll` только по фиксированному имени operation directory.

## Проверки здесь

Windows, Go 1.26.5, `GOMAXPROCS=2`, `GOFLAGS=-p=2`:

- Финальный полный `go test ./internal/dataplane ./internal/awgprofile ./internal/wireguardprofile ./internal/dnscontrol ./internal/netresolve -count=1`: PASS; dataplane 58.171 s, остальные четыре пакета PASS.
- Финальная отдельная группа `go test ./internal/dataplane -run '^TestWGPolicyReceipt' -count=1`: PASS 5.585 s, включая refresh и stale Activate cases.
- Windows vet тех же пяти пакетов: PASS.
- Linux amd64 dataplane test binary cross-compile и Linux vet тех же пакетов: PASS, включая обновлённый native fixture.
- `git diff --check`: PASS.

Новые unit regressions проходят через реальные adapter methods и, где указано, полный Manager.Apply: late identical EEXIST IPv4/IPv6; unknown последний selector; AWG inventory меняется после mock Canary acceptance и fresh Activate отвергается без cleanup; recipient после удаления transaction; Commit retry с Removed recipient; разные peer profiles и свежая restoration generation; повторный Rollback без apply; stale Rollback после kernel recovery; stale Activate с пустым/существующим snapshot; corrupt snapshot/reference/missing common receipt; boot change с foreign defaults обеих семей; refresh success/failed health/unknown с сохранением defaults и без replay. Unit runner и boot здесь mock; это не Linux service evidence.

## Независимый Linux прогон координатора

Обновлён существующий `TestWGNativeEndpointLifecycle`: initial Commit/recipient; новый процесс без replay; deliberate activation другого неверного peer с настоящим failed handshake; Rollback восстанавливает старый peer и независимый HTTP service через WG, выдаёт свежий receipt, retire обоих прежних grants; повторный Rollback и новый процесс; kernel-loss recovery со свежим ID; stale original Rollback fenced с живым сервисом; точный Stop и cold retry при сохранении foreign route. Endpoint transport IPv4/IPv6 остаётся в двух независимых топологиях.

Неверный peer в этой failure-boundary fixture намеренно проходит прямо к Activate после Validate, минуя Canary; обычный Manager требует Canary. Сам fixture отдельно сохраняет прежние реальные wrong-key Canary и WAN control проверки. Deliberate kernel-loss injection применяет legacy exact `removePolicy` **только в test**, чтобы снять kernel state без receipt acknowledgement; production это не вызывает.

Координатору в эксклюзивной Linux VM после интеграции собрать test binary и запустить:

```sh
RAZVILKA_WG_NATIVE=1 ./dataplane.test -test.run='^TestWGNativeEndpointLifecycle$' -test.count=1 -test.v
```

Здесь новый WG native fixture **NOT_RUN**, Linux race **NOT_RUN**. Переданные координатором результаты `native-policy-receipt-01` (race и 12 real crash boundaries) и `native-awg-02` относятся к прежним checkpoints; это не PASS нового wiring. NET не изменял VM/router/netns/shared ports и не устанавливал module/tools.

## Границы результата

Старый committed state без generation reference/общего receipt автоматически не мигрирует и не получает legacy cleanup waiver; требуется отдельная проверяемая миграция/ручная сверка. Interrupted transfer, unavailable/corrupt receipt, unknown acknowledgement, boot mismatch для cleanup и незавершённая операция остаются fenced. Это сознательно может сохранить runtime и defaults для разбирательства.

WG sidecar publication и rollback-reference acknowledgement не проверены real power-cut/kill во всех промежуточных точках. Последующая отдельная [правка resumable restoration](NET_ROLLBACK_RESUME_RU.md) связывает transaction с restoration до publication и закрывает definite final marker write/source-directory cleanup failure после successful publication через прежний Complete recipient, без blind replay. Interrupted common transfer и partial publication остаются fenced. Общие 12 process crash boundaries не закрывают все NET publication boundaries.

Receipt подтверждает mutation ownership, не service health. Adapter не объявляет `VerifyRollback`; `Manager.RollbackVerified` для WG не становится true только из-за успешного Rollback. Обновлённый native сервисный сценарий, app restart/reboot, Netcraze HIL, whole-LAN/default route health и Bootstrap DAG требуют отдельных доказательств. D08 strict domain authority и D09 NFQWS остаются вне этого checkpoint. VERSION, go.mod/go.sum и capability gates не изменены.
