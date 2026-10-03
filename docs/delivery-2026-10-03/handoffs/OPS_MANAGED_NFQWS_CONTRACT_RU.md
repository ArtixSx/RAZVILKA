# OPS managed NFQWS producer contract — 04.10.2026

Producer реализуется в existing components package; components→strategylab import отсутствует. CORE преобразует descriptor в CompatibilityApproval из NFQWS `9cdcbff`. Stock spec/adapter не переключается автоматически; file installation заканчивается ready-idle, не запускает binary, hooks, opkg, network или service. Runtime activation/adaptive session принадлежат NFQWS/CORE/NET.

Закреплён первый flavor keenetic-payload-1.3.1 ARM64, официальный неизменённый parent IPK. Read-only проверен ранее скачанный research Temp artifact: 381072 bytes, SHA2569167d72053a83a78f48f6439af38432fb2d1d411fb22c0980240a949ace614df. Exact выбранные binary/Lua/blobs input/raw sizes установлены локальным bounded чтением; ничего не скачано/исполнено заново.

## Signature для NFQWS/CORE

```go
type NFQWSRuntimeAsset struct { Path, SHA256 string }
type NFQWSRuntimeBlob struct { Alias, Path, SHA256 string }
type NFQWSRuntimeDescriptor struct {
    ReceiptID, ManifestSHA256, Flavor, GenerationPath string
    Executable NFQWSRuntimeAsset
    Lua []NFQWSRuntimeAsset // lib → antidpi → auto, exactly three
    Blobs []NFQWSRuntimeBlob // quic_initial → tls_clienthello, exactly two
    LuaCompat int // 6
    AllowedFeatures []string
}
func (m *Manager) AcquireManagedNFQWSRuntime(ctx context.Context, receiptID string) (*ManagedNFQWSRuntimeLease, error)
func (l *ManagedNFQWSRuntimeLease) Descriptor() NFQWSRuntimeDescriptor
func (l *ManagedNFQWSRuntimeLease) Check(ctx context.Context) error
func (l *ManagedNFQWSRuntimeLease) Close() error
```

Acquire использует тот же permanent writer inode/kernel lease existing component journal и держит его весь validate/probe session. Installer/Update/rollback используют этот же lease. Проверяет exact accepted ready-idle receipt, manifest и все bytes/modes/tree; descriptor содержит canonical absolute generation paths. Close повторно проверяет immutable generation и освобождает lease; ошибка Check/Close аннулирует session acceptance. Генерации never rewritten/pruned; новые публикуются отдельно, old/LKG сохраняются. Нет второго ownership ledger/lock или runtime owner.

CORE держит lease до завершённой durable NFQWS session/ACK, повторяет Check перед launch и после probe, включает все Lua/blob paths+SHA в frozen CompatibilityApproval. Executable identity/root-euid exclusion, actual child Start/Stop admission и отсутствие чужого NFQUEUE owner остаются обязательными проверками session owner; hashes/readonly modes не защищают от произвольного root-euid writer. Не выдавать Native/activation capability по descriptor alone. `--daemon`, PATH lookup, upstream init/shell eval не нужны.

Journal extension schema3 будет ограничен этому provider; текущая production CLI capability2 не поднимается до Root acceptance и wiring. Каждый schema3 write требует explicit trusted reader/retained-controller admission3 до эффекта. Generic package recovery откажет payload transaction; matching file-only recovery использует тот же existing journal. Исторические opkg schema1/2 не меняются. Эта signature согласует границу; готовый implementation SHA и tests будут добавлены после завершения.
