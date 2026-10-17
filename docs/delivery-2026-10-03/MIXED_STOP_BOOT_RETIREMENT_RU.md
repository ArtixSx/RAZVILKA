# Explicit offline retirement legacy mixed Stop

Операция `-retire-rollback-after-boot-plan` + `-retire-rollback-after-boot-digest`
получила отдельный узкий путь для legacy Stop: adapters ровно
`nfqws2,sing-box`, без LAN/DNS/domain/synthetic/WG и execution resources.
Исходный forward prefix: два успешных snapshot, успешный NFQ deactivate,
отказ sing-box deactivate. Обычные retry/close не получают этот допуск.

Boot снимка не является boot поколения. Проверяются active binding и точный
committed receipt, их generation/receipt ID, policy, checksum и старый boot
самого bound addition document. Текущий boot должен отличаться. Старые
snapshot, ACK и root hashes никогда не переписываются.

Неиспользуемые исторические копии поколений сохраняются как unknown evidence.
Их closed schema/checksum/old boot обязательны; старый RootHash сохраняется
даже при несовпадении с нынешним местом копии. Каждая историческая Add/Delete
пара должна попадать строго в `rz-sing`, table203 и полные owned/shared RPDB
priority ranges. Иначе отказ: negative inventory не покрывал бы эти эффекты.
Эти argv никогда не исполняются и не становятся cleanup grant.

Свежий proxy observer проверяет процессы/socket/interface, IPv4/IPv6 RPDB,
table203, собственные forwarding chains/references. Все поколения ограничены
его координатами. Дополнительно оригинальный concrete NFQ inactivity source
проверяет file/process identity, полный frozen backend inventory обеих families,
зарегистрированные tables, owned/shared queue graphs, queues и netlink sockets,
с повторными чтениями и identity bookends. Успешный Stop сам по себе не даёт
этой независимой проверки. Живой stock NFQ тоже блокирует операцию.

Original Evidence и Files включены точными bytes в immutable manifest и fsync
до witness и любых journal publications. Источники повторно читаются до/после
архивирования и перед каждой записью журнала. Сбой оставляет fence и resumable
publication; нельзя трактовать частичное архивирование как завершение.
Target journal image закрепляется inode+bytes до долгой absence проверки;
closing CAS повторяется после неё и после staging fsync прямо перед rename.
CAS отказ блокирует дальнейшие записи этого live writer. Immutable provenance
исключает только три exact mutable publication paths текущего плана;
execution предыдущего committed плана всегда проверяется как evidence.

Итог использует существующий совместимый state `rolled-back`, но всегда
`RollbackVerified=false` и отдельный marker `retired-after-boot` в error/note.
Это metadata retirement после runtime absence, а не подтверждённый rollback,
успешный Stop, восстановление stock configuration или service access.

## Вызов владельцем

Только после завершения всех собственных тестов/owners, остановки panel через
S99 и подтверждения отсутствия controller. Сохранить post-Stop backup. Проверить
точный plan/digest, текущий настоящий boot и неизменные настройки. На роутере
автор patch ничего не применял.

```sh
/opt/bin/razvilka \
  -config /opt/etc/razvilka/config.json \
  -stage /opt/razvilka/state/staging \
  -backups /opt/razvilka/state/backups \
  -custom-services /opt/etc/razvilka/custom-services.json \
  -devices /opt/etc/razvilka/devices.json \
  -cloudflare-state /opt/etc/razvilka/cloudflare-private \
  -node-state /opt/etc/razvilka/nodes-private \
  -warp-state /opt/razvilka/state/warp \
  -dataplane-state /opt/razvilka/state/dataplane \
  -retire-rollback-after-boot-plan dp-651ffa77322fa13e \
  -retire-rollback-after-boot-digest 651ffa77322fa13e9c96f3a3be81fa20deb0b3d71af1c3a1254b77d845b9773d
```

Операция сохраняет lifetime leases private recovery до выхода и не запускает
HTTP/workers. NFQ observer собирается только на fixed production roots с
настоящим admitted tool lease. При живом stock NFQ ожидается RC!=0 и
`offline post-reboot retirement requires intact reviewed history and absent runtime`.
Это нормальный отказ, не повод удалять journals/leases или менять boot.

## Проверки

`TestMixedStopBootRetirement*`: intact Stop, unchanged original archive,
fresh complete modeled NFQ source, missing/late source refusal, same boot,
binding root tampering, orphan boot/checksum/foreign-interface refusal,
ownership inventory mutation, durable archive before publication,
publication write failure and resume; ordinary retry/close remain rejected.
Старые `TestBootRetirement*`, `TestCloseFailedRollback*`,
`TestRetryFailedRollback*` сохранены.

Дополнительный Linux-only `TestMixedStopBootRetirementRetainedArchive`
читает gzip tar по `RAZVILKA_TEST_STOP_RETIREMENT_ARCHIVE`. Это read-only pure
metadata eligibility replay без extraction, kernel observation или live action.
Приватный архив не входит в Git. Нужны отдельные Linux race/CLI проверки и
независимое review перед применением на router.
