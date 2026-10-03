# Общий durable policy addition receipt — CORE → VLESS/NET

03.10.2026. Контракт после review `b3bc486`, **реализация CORE следует**, до неё нельзя заявлять end-to-end cleanup при failed activation безопасным. Владельцы адаптеров shared policy primitive не изменяют. Проблема: staged PolicyState описывает intent, а не успешное добавление каждого kernel tuple; последующий broad rollback может удалить чужой default, который появился после readonly preflight и дал EEXIST нашей add.

CORE предоставит в общем `internal/dataplane/policy_addition_receipt.go`:

```go
applyPolicyWithReceipt(ctx context.Context, runner NFQWS2Runner, ip string,
    state PolicyState, receiptRoot string) error
removePolicyWithReceipt(ctx context.Context, runner NFQWS2Runner, ip string,
    state PolicyState, receiptRoot string) error
```

`receiptRoot` — уже существующий private owned adapter transaction directory, **не HTTP/config path**; внутри фиксированные `policy-additions-v1.json` и постоянный nonblocking kernel-lock marker. Для каждой новой activation/refresh/recovery попытки нужен отдельный transaction/generation root. Receipt binds schema, SHA256 полного canonical PolicyState, kernel boot ID и exact derived add/del argv каждого tuple. Все expected argv конструируются заново из state и сверяются при чтении; receipt не является произвольным command source.

До kernel add durable intent, после подтверждённого успешного add durable added. Intent без added — unknown, **не grants ownership и не replay**; включая crash после реального add до сохранения added. Failed EEXIST не превращается в added по matching readback. Cleanup использует только шаги с durable added, после kernel del+independent absence readback отмечает removed. Crash на удалении сохраняет cleanup-intent: повторное удаление по одному matching имени запрещено, нужен trusted reconciliation отдельным CORE contract. Unknown добавление оставляет fence, даже если ранее proven subset убран. Новый boot доказывает отсутствие старых runtime tuples, а не успешность old command; файл сохраняется, автоматическое принятие старой intent отсутствует.

Две семьи инспектируются до любой add, add не overwrite, tuple lookup/readback не позволяет claim pre-existing route. Foreign/ambiguous tuples сохраняются. Все writes atomic + file fsync + Linux directory fsync. Corrupt/unavailable/mismatch/unknown receipt — error/fence. Receipt не удаляется и не перезаписывается для нового поколения. Existing legacy policy без addition receipt имеет прежнюю отдельную committed ownership границу; **новый staged intent без receipt не может перейти на legacy cleanup fallback**.

VLESS/NET сопряжение: новая Activate вызывает tracked helper в root конкретного candidate, а failed-candidate Rollback вызывает tracked removal именно там. Если returned unknown/cleanup-unconfirmed — сохранить transaction и остановить дальнейшую компенсацию, которая может снести интерфейс/default чужого владельца. Нельзя после ошибки tracked cleanup безусловно вызывать broad removePolicy/stopOwned/stopInterface. Snapshot prior committed policy и recovery остаются отдельной authority; durable reference/copy receipt для committed runtime должно быть сохранено в Commit до удаления/переноса transaction root. Для refresh/recover использовать новое generation root и сохранить предыдущую receipt до verified settlement. Следующий CORE commit уточнит promotion API; не записывать абсолютный path из DTO в policy.json.

Native план: root-only opt-in empty namespace; реальные foreign default и late identical tuple; kill после intent/add/added/cleanup-intent/del/removed; fresh reader не replay и не delete unknown; checksum/boot/policy mismatch; partial known additions cleanup только своего subset. Это дополнительные checks к уже подготовленному `TestNativePolicyApplyPreservesDefaultOccupants`, не расширение общих live ports и не HIL всей D03.

Сопряжение D03 health отдельно: production runtime health выполняется на роутере (exact process/config/network/interface/routing ownership и ограниченная native reachability), а actual selected/control LAN proof имеет явный статус/receipt. Постоянный внешний ПК не становится скрытой обязательной зависимостью Health/Commit. Пока exact LAN proof не получен, не объявлять SOCKS pass TUN/LAN pass и не снимать NETWORK_POLICY_EXECUTOR_REQUIRED. Детальный app/adapter контракт согласуем после D11 и addition receipt.
