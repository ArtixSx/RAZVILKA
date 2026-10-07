# NFQWS: fresh classic facts после закрывающих callbacks

Отдельный follow-up к `2c9af560c1c9e50db9c912657a1e5abe73c70479`. CLOUD обнаружил конкретный unsafe Apply boundary: closing `AdditionalReadback` в последнем `readRules` мог убрать ACKed opposite-family body после сбора classic rows. Prefix проверял старый image и выпускал attachment RPC; следующий readback возвращал Unknown уже после записи.

## Исправленная граница

`readClassicRules` содержит прежний bounded all-ten-table collector без external predicate callbacks. Обычный `readRules` сохраняет opening/closing `AdditionalReadback`, syntax/size/context checks и свой прежний контракт.

Новый private `readFinalRules` выполняет обычный full `readRules`, отбрасывает его classic image после closing callback, затем повторно собирает все десять таблиц через `readClassicRules`. Counts/foreign/body/Needs/prefix проверяются только в последнем локальном image; после него нет Guard, LAN, Process или AdditionalReadback predicate callback перед actual base RPC. Два other-backend/physical-namespace checks сохранены, callback errors не превращаются в permission. Original base Runner по-прежнему consume CORE admission на actual Cmd.Start.

Apply prefix использует эту границу после closing process/LAN callbacks. Итоговый COMPLETE также получает свежий `readFinalRules` после закрывающих process/LAN callbacks: их nominal success не может валидировать ранее прочитанные classic rows. Старые images могут лишь раньше отказать, но не выдать финальный grant.

Common receipt, original admission, both full ExactPresence, process/queue proofs, producer/caps и Remove/settlement в этом follow-up не меняются. Remove WIP не включён в commit и исключён из verification через локальный Go overlay.

## Проверка и стоимость

Неизменённый CLOUD `TestCloudReviewNFQWSPrefixCannotSurviveClosingBackendReadback` прочитан из его review tree и подключён только локальным overlay. До fix: RED 0.162s, семь writes вместо шести до cut, attachment=1 при peer=0. После fix: PASS вместе с Apply tests 1.912s; attachment не записывается. Собственные cuts проверяют missing peer body, future tuple, foreign queue, backend error/cancel на closing backend callback перед attachment и четыре аналогичных cuts на последнем backend callback финального COMPLETE.

Финальный successful Apply source count с N effects: classic whole images `5N+4`, other-backend brackets `4N+3`, post-target reads N, full process/LAN owner checks `N+2`. При N6: 34 classic images, 54 AdditionalReadback callbacks и шесть post-target reads. Если каждый AdditionalReadback делает две legacy version + один nft CLI, direct read CLI = 508 против старых 544. LAN.Verify остаётся 16 против 44; неизменённые live nested consumers дают общий source estimate около 1020 read CLI против 1912. Предыдущие 26 images/934 CLI относятся к rejected `2c9af56` и не являются оценкой этого fix. Это расчёт, не measured speedup и не гарантия command deadline.

Native/packet/race acceptance и отдельный cleanup time gate выполняет только ROOT после independent review.

Изолированный fix-only overlay исключал весь Remove WIP: Windows NFQ scoped + common PolicyEffectsReceipt + unchanged CLOUD regression PASS 17.488s; Windows/Linux amd64 vet, Linux amd64/arm64 test cross-compile и diff check PASS. Реальные Linux binaries здесь не запускались.
