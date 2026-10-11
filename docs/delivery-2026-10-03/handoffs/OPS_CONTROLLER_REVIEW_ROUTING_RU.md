# OPS: выбор verifier по запечатанному review

11.10.2026. CORE для обычного live quiesce нужен выбор обычного verifier до сканирования peer. Добавлен только read-only API:

```go
func (a *SelfUpdateFileAdapter) OrdinaryInstallerControllerReview(ctx context.Context, id string) (bool, error)
```

Проверяет finite действующий ctx, fixed production adapter с root-owned путями, Stop `read/observe`, действительный immutable header/hash/binding и повторное неизменное чтение header. `true,nil` выбирает ordinary verifier только для schema2/Bootstrap nil, старой версии не ниже 0.20.0, строго большей новой версии и полноценного reader4 proof. `false,nil` возможен только для явно валидного bound bootstrap review. Любое повреждение, неизвестная схема, неверная версия, reader, binding, смена header или отмена возвращают error; error не разрешает bootstrap fallback.

Этот API не доказывает роль, inactivity или effect. CORE после выбора отдельно вызывает полный соответствующий verifier. В post-wait callback сначала используется `OriginalOrdinaryInstallerControllerAdapter(ctx,id)`: present-valid даёт тот же producer adapter и обычный binder; present-invalid прекращает наблюдение; `nil,nil` требует выбора по новому API локального adapter. Main/DP и existing bootstrap role API не изменены. Это не расширение acceptance старой миграции.

Windows focused routing/ordinary/accessor tests PASS. Linux AMD64/ARM64 vet и compile-only проверяются перед передачей pin; Linux/VM/router execution OPS не выполняет. Native routing вместе с Main/DP остаётся проверкой Root после CORE wiring.
