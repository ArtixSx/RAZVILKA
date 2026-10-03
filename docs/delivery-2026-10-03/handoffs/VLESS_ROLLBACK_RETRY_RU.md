# Безопасный retry proxy Rollback

04.10.2026. Порция поверх `ddb7edb` исправляет отказ повторного Rollback после публикации `phase=restoring`. Общие CORE policy mutation/kernel/forwarding, app/manager, D10 worker и production dependencies/version не изменены.

## Durable progress и ownership

Transaction aggregate получает private `restoration_generation` — validated random ID, из которого адаптер сам строит путь под StateRoot. Он записывается и синхронизируется до global pending binding A, forwarding и попыток RPDB add. Digest недостаточен: A и B могут иметь одинаковую PolicyState. Новый ID не оживляет removed receipt прежнего A.

Retry `restoring` сначала проверяет только чтением same boot и exact shared B receipt (source либо recorded promoted receiver). Требуется Removed без Unknown. Повторная очистка B не вызывается. Дальше возможны три исхода:

1. Новое A ещё не началось: нет restoration ID, global binding отсутствует для legacy cold history либо указывает точно на consumed prior A/receiver B с Removed ledger. Допустим повтор ранних stop/files/start и новое поколение A. Ошибки forwarding/stop/interface/file/start немедленно прекращают последовательность; ошибка stop больше не приводит к переписыванию файлов работающего процесса.
2. Exact restoration ID имеет Complete shared ledger и matching pending/active global binding. До записи состояния проверяются snapshot runtime files, running pair/SOCKS, полный policy/forwarding readback, candidate-only selectors/chains; для scoped Xray также ifindex lease и full process/config identity. После проверки завершаются binding/journal/draft/marker этого же поколения. Нет RPDB add/delete, forwarding mutation, interface removal, Start/Stop managed pair. Уже работающий package runtime повторно не запускается.
3. Unknown/partial/missing/corrupt/mismatched ledger, foreign binding либо сменившийся boot: ErrProxyPolicyUnknown до firewall, process или file mutations. Pending reference не заменяется historical binding. Cut после restoration ID, но до доступного exact binding/ledger, также остаётся fenced; отсутствие ACK не выводится из kernel readback.

Старый `restoring` aggregate без restoration ID не даёт права затереть неожиданное новое pending/active A. Такой interrupted state требует отдельного trusted reconciliation.

Rollback после Snapshot, если Stage не успел записать candidate policy, отдельно проверяет exact unchanged committed A: same boot, snapshot binding == current active binding, Complete receipt, policy journal, runtime files и runtime readback. Этот A остаётся работающим без нового generation/teardown. Для tracked/bound history без такого доказательства — fence. Untracked cold history сохраняет отдельную прежнюю границу, но появившийся после Snapshot global binding, tracked/malformed current journal или orphan aggregate тоже запрещает изменения. Та же проверка текущего tracked marker действует для legacy cold retry из restoring; missing binding не открывает legacy fallback.

## Проверки

Windows regression tests покрывают transient Stop failure → fresh adapter retry и verified A; lost restoration add ACK → неизменные RPDB/firewall/process/files и pending reference; foreign exact default/selector между попытками → сохранение чужого tuple и отказ; отказ policy journal после всех durable ACK → завершение того же A без runtime replay, включая cut до active binding. Есть no-mutation checks для boot change, missing/corrupt receipt, foreign generation binding; Snapshot-only exact A и отказ при изменённых binding/files/boot/active proof; cold Snapshot без policy не перезаписывает появившийся active/pending binding.

Адресная группа receipt/proxy generation/scoped lifecycle/rollback была выполнена трижды: PASS (35.631s). Финальные дополнительные cold journal regressions и вся `TestProxyRollbackRetry*` группа: PASS (6.323s). Windows vet и Linux amd64 compile/vet после финальных edits: PASS. Native Linux process-crash/proxy lifecycle, race/full Linux и router restart/HIL остаются gates координатора; compile не заменяет native evidence.

Два ранее переданных CORE fixture updates (`TestProxyForwardingCommitRecoveryRefreshAndDeactivateShareOwnership`, `TestCanceledNodePolicyRefreshRestoresWithIndependentContext`) здесь не изменялись. Весь остальной Windows dataplane с исключением ровно этих двух tests PASS (64.797s); full gate PASS этой порцией не объявляется.
