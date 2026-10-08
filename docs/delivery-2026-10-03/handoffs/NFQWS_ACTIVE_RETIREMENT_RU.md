# NFQWS active owner: явное завершение участия

Дата: 2026-10-08. Parent: `a1aabb5` (ограниченный audit списков).
Это ранее согласованный ROOT/DEFAULT process retirement seam. Он не меняет
compiler/config, list-mode, COMMON journals, регистрацию адаптеров или main.

## Частный API для DEFAULT

```go
(*NFQWS2Adapter).retirePreparedNFQWSProcess(
    freshBoundedContext, originalPreparedHandle,
    verifyCommon func(context.Context, NFQWSExecutionBinding, NFQWSScopedProcessProof) error,
) error
(*NFQWS2Adapter).retireActiveNFQWSProcess(
    freshBoundedContext, originalActiveHandle, verifyCommon,
) error
```

Не экспортируется, не создаёт handle и не принимает detached DTO вместо
исходного владельца. Callback должен быть закрыт на фактический retained
DEFAULT execution: exact issued root/typed Binding.VerifyInactive, известное
receipt-owned removal/absence, полная инвентаризация всех таблиц, LAN-last и
настоящий CORE cleanup review. Он не удаляет process ownership.json.
Callback произвольного публичного caller не является production issuer.

## Порядок и отказ

1. Fresh context имеет deadline и не отменён. Проверяются исходный adapter,
   original handle pointer, SAME8/Spec/command, stopRequested, завершённый
   фактический Start, sole Wait и завершённый Commit/его compensation.
   Незавершённый Commit не допускает retirement даже при уже reaped helper.
2. Одноразовая попытка сравнивает закрытый private Wait/parent ACK результат с
   текущей точной lease3. File/receipt metadata без private done недостаточно.
3. Linux producer держит writer существующего ownership.json, проверяет его
   protected path и exact terminal image; actual typed provider доказывает
   пустую очередь. COMMON callback получает исходный fresh context, SAME8 и
   реальный terminal proof; owner.mu не держится через callback.
4. Terminal proof, file image и пустая очередь проверяются повторно. Только
   затем CAS удаляет тот же ownership.json; проверяются отсутствие и снова
   пустая очередь. Close writer тоже должен завершиться успешно.
5. Закрывается request watcher, проверяется исходная association и лишь затем
   очищается adapter.activeProcess. Отзываются оба handle и старые callbacks.
   Теперь новый retained participant может занять этот исходный adapter.

Stop сам по себе association не очищает. Ошибка COMMON, несовпавшая запись,
неподтверждённый Wait, изменение namespace/queue, потерянный результат после
unlink, deadline/cancellation или Close error сохраняют fence. После начала
попытка одноразовая; нет повторного удаления по отсутствующему файлу, cold
adoption или очистки только по PID. Некорректный вход до admission не потребляет
COMMON callback. Ошибки наружу имеют статический stage; cause доступен через
Unwrap без печати private payload.

## Проверки и границы

Windows: `TestNFQWSActive|TestNFQWSManaged` PASS 0.451 s; package vet завершился
с кодом 0. Linux amd64/arm64: package vet и полная cross-compilation dataplane
test binary завершились с кодом 0. Linux здесь не исполнялся.

Новые meaningful модели: Stop без COMMON; copied/new adapter и copied handles;
bounded/cancelled/nil input; SAME8/Spec drift; terminal metadata без sole Wait;
разный actual Wait/readback; COMMON failure; пропущенный/повторный callback;
потерянное подтверждение после removal; отмена во время COMMON; остановка
посреди final guard с отказом retirement до завершения compensation;
отзыв старых handle и возможность следующей association после успеха.
Эти модели не являются actual second Apply или COMMON journal/native PASS.
Linux file/queue retirement routine пока проверена vet/cross-compilation;
production consumer и actual COMMON cleanup интегрирует DEFAULT.

Отдельно ROOT сообщил actual Linux NFQ149 на accepted `5e54926`: race моделей
active PASS 1.523 s; genuine child request-end/activation-expiry 16.17 s,
prepared cancel 1.40 s, panel stop 1.93 s, общий native 19.50 s, RC0.
Closing queue empty, sole Wait/ECHILD и parent ACK подтверждены, rules не
изменялись; private helper удалён. Это предыдущая process QA, не проверка
нового retirement seam, COMMON/CAS/main или list/exclusion enforcement.
