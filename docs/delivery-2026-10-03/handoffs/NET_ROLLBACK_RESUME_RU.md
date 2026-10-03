# NET: resumable WG restoration после publication

04.10.2026. Отдельная правка поверх `334a62add64b3d43d7025ffa98105b8ad023eab6`, ветка `sol/net-20261003`. Подтверждены оба замечания review: restored generation уже опубликовано, но final rollback marker ещё отсутствует из-за definite write failure либо ошибки `removeSettledWGPolicyOperation`. В прежнем коде retry принимал только prior/candidate ID и отвергал собственное restored поколение.

## Исправление

Restoration получает `RollbackOwner`: SHA256 canonical transaction-root hash, полного immutable snapshot, candidate reference и факта выдачи candidate receipt. Этот digest хранится в private checksummed reference с первой записи source, до policy commands. Он не содержит arbitrary path, команды или private-key bytes. Snapshot и candidate по-прежнему читаются из конкретного transaction, не находятся по совпадению live state.

После settled common promotion в transaction **до publication** записывается новый фиксированный `wg-policy-restoration-v1.json`: точный ID, boot, immutable full policy, owner digest и checksum. Только затем публикуются restored StateRoot reference и policy.json. Ошибка последующего source-directory cleanup или final `wg-policy-rollback-v1.json` больше не уничтожает связь transaction → restoration.

Retry использует отдельный узкий resume path. Он требует правильный owner digest, совпадение current ID/checksum с durable transaction restoration reference, полного current PolicyState hash с immutable receipt state, Complete recipient текущего boot, точных prior runtime bytes, живого interface/public identity/mark, policy evidence и WG endpoint evidence. Если operation directory ещё есть, дополнительно требуются его matching reference и independently readable source со статусом Promoted, тем же ID и без Unknown. Затем retry дописывает final marker, удаляет только settled фиксированный operation directory и заканчивает восстановление profile/draft. Kernel apply/delete, restart interface, replay старого receipt и новый generation ID не выполняются.

Уже существующий final marker проходит те же проверки. Corrupt/different final marker не перезаписывается поверх неизвестного состояния. Missing/wrong transaction binding, Removed/Unknown/missing recipient, смена boot, missing source в существующем operation directory и более позднее поколение остаются fenced.

Дополнительно Rollback с pending operation, которая ещё не получила durable transaction restoration reference, не возвращается к старым candidate markers. Interrupted common promotion после destination copy поэтому не позволяет остановить уже восстанавливаемый interface и косвенно удалить его defaults. Resume такого Unknown transfer не добавлен.

## Fault regressions

`TestWGPolicyReceiptRollbackPublicationCutsResumeWithoutReplay` использует два разных peer profiles и fresh adapter retry:

- Реальный definite `ownedfs.WriteAtomic` failure: в final marker path создаётся directory, который atomic rename не может заменить файлом. После устранения препятствия retry завершает marker по прежнему restored receipt.
- Injected definite filesystem `PathError(ErrPermission)` перед operation deletion, уже после successful publication. Source/recipient transfer settled, final marker отсутствует; retry завершает оба шага.

Оба сценария подтверждают retirement prior и candidate grants, сохранение old runtime, неизменные restored ID/checksum и interface start count, отсутствие policy/interface mutation при двух retry, durable final marker и отсутствие operation directory после settlement.

Negative matrix: missing binding; правильный checksum с неверным owner; corrupt final marker; missing/Removed/Unknown recipient; missing source; новый boot; later generation. Все отвергаются без kernel mutation, runtime replacement или interface stop. Отдельный `promotion-copy` cut подтверждает, что Unknown restoration сохраняет interface/defaults при retry и не расходуется по candidate markers.

## Проверки

Windows Go 1.26.5, `GOMAXPROCS=2`, `GOFLAGS=-p=2`:

- Финальная группа `go test ./internal/dataplane -run '^TestWGPolicyReceipt' -count=1`: PASS 12.285 s.
- Финальный полный `go test ./internal/dataplane ./internal/awgprofile ./internal/wireguardprofile ./internal/dnscontrol ./internal/netresolve -count=1`: PASS; dataplane 67.283 s, остальные четыре пакета PASS.
- Windows vet тех же пяти пакетов: PASS.
- Linux amd64 dataplane test binary cross-compile, включая финальные negative cases, и Linux vet тех же пяти пакетов: PASS.
- `git diff --check`: PASS.

Обновлён имеющийся `TestWGNativeEndpointLifecycle`: после deliberate different-peer activation и настоящего failed handshake первый Rollback восстанавливает старый сервис, но получает operation cleanup error; fresh adapter затем получает реальный marker write error; следующий fresh adapter завершает Rollback. Fixture требует прежние ifindex и generation checksum, настоящий old service до/после retry, settled source cleanup, повторный retry и recovery в отдельном процессе. Оба endpoint families остаются в отдельных топологиях.

Координатору в эксклюзивной Linux VM после интеграции:

```sh
RAZVILKA_WG_NATIVE=1 ./dataplane.test -test.run='^TestWGNativeEndpointLifecycle$' -test.count=1 -test.v
```

Новый native fixture и Linux race здесь **NOT_RUN**. NET не менял VM/router/netns/shared ports. CORE fixtures, общий receipt implementation, manager/app, VERSION и go.mod/go.sum не изменены.

## Границы

Resume разрешён только для уже полностью опубликованной restoration с Complete recipient и сохранённой causality binding. Частичная StateRoot publication, interrupted common transfer, unavailable/corrupt journal и частичное удаление operation directory без читаемой settlement authority остаются fenced; blind replay не добавлен. Real kill/power-cut между всеми NET metadata writes этим Windows fault прогоном не доказан. `Manager.RollbackVerified`, HIL, reboot/app restart и whole-LAN health по-прежнему не объявляются закрытыми.
