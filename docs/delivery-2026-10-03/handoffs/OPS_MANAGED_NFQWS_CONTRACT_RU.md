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

Journal extension schema3 ограничен этому provider; текущая production CLI capability2 не поднимается до Root acceptance и wiring. Каждый schema3 write требует explicit trusted reader/retained-controller admission3 до эффекта. Generic package recovery отказывает payload transaction; matching file-only recovery использует тот же existing journal. Исторические opkg schema1/2 не меняются.

## Завершённый file-only implementation

```go
func ReviewedManagedNFQWSManifest(architecture string) (ManagedNFQWSManifest, error)
func (m *Manager) InstallManagedBundle(ctx context.Context, manifest ManagedNFQWSManifest, expectedRevision uint64, authority ManagedNFQWSBundleAuthority) (ManagedNFQWSBundleReceipt, error)
func (m *Manager) UpdateManagedBundle(ctx context.Context, manifest ManagedNFQWSManifest, expectedRevision uint64, authority ManagedNFQWSBundleAuthority) (ManagedNFQWSBundleReceipt, error)
func (m *Manager) RecoverManagedBundle(ctx context.Context, transactionID, action string, authority ManagedNFQWSBundleAuthority) (ManagedNFQWSBundleReceipt, error)

type ManagedNFQWSBundleAuthority struct {
    InstallationID string
    Sequence uint64
    ReaderVersion int // exactly3, trusted reviewed consumer set, never JSON
    Check func(context.Context, string /* installationID */, uint64 /* frozen sequence */, uint64 /* frozen revision */, int /* required reader */) error
    Admit func(context.Context, string /* transactionID */, string /* installationID */, uint64 /* frozen sequence */, uint64 /* frozen revision */, string /* effect */, func() error) error
    Inactive func(context.Context) error // fresh OWN managed-runtime inactivity
}
```

Nil wiring, reader2, wrong frozen installation/epoch/revision, active own runtime and unknown manifest fail closed. Default production catalog принимает только exact compiled ARM64 Keenetic1.3.1 manifest, не HTTP recipe/latest/version-only. MIPS/MIPSel не подставляются. Downloader использует existing bounded HTTPS client, exact parent size/SHA и identity encoding; библиотека не скачивала новый upstream artifact в этом чате. Parent/control/data/Lua streams проверяются целиком с CRC, limits, duplicate/path/type/trailing-data gates до stage. Hook members читаются/отбрасываются как данные, не материализуются. Binary не исполняется. Notice metadata отдельно сохраняет wrapper/patch/source links и GPL/LGPL/LuaJIT/compiler/zlib unresolved-build-input; composite executable не объявлен MIT-only/reproducible или native ABI verified.

Owned canonical root `/opt/lib/razvilka/nfqws2/releases`, разрешён только reviewed `/opt` mount symlink, descendants не могут перенаправить файлы в stock. Stage — exclusive random directory700; полный verified tree и all new ancestors fsynced, затем stage root chmod555 + actual Linux RENAME_NOREPLACE inside short CORE admission. На rename failure stage mode700 возвращается в том же bounded callback; fsync остаётся вне admission. Binary0555, assets/manifest/notices0444, generation dirs0555, no setuid/setgid/sticky/extra files. Все canonical ancestors должны иметь other-execute для UID-drop2147483647; /root/private700 ancestor блокирует producer/descriptor без chmod чужого каталога. Controls/receipts700/600, staging root остаётся700 до publication. Это mode/traversal evidence; actual ACL/default UID access и genuine Lua init проверяет native owner. Windows использует только private model publication override; production publication там недоступна. Ни mutable lists/config/logs, ни network/accounting, ни stock init/binary/package DB provider не изменяет.

Transaction phases existing component current.json: prepared → upgrade-started (generation publication intent) → upgrade-finished → awaiting-live-acceptance (inventory publication intent) → accepted-installed-idle. Для этого provider названия означают только verified file readiness, не opkg или runtime acceptance. К existing journal добавлен strict canonical schema3 union, permanent writer marker не пересоздаётся при retained current. Immutable per-transaction evidence хранится в существующем `<transactionID>/managed-accepted-installed-idle.json`. Inventory — отдельный owned `components/receipts/nfqws2-managed.json`, stock `nfqws2.json` и Specs.Provider=opkg не подменяются. Это existing component receipt inventory, не второй transaction/ownership ledger.

`resume` только читает complete stage/published bytes и повторяет локальный CAS при known old/new image; downloader/hook/process не replay. `rollback` проверяет original accepted generation/receipt, admitted exact inventory rename/unlink восстанавливает old receipt или prior absence; этап rollback-started → rolled-back. Обе generation и terminal evidence сохраняются. Third image, changed generation, missing marker или archive не перезаписываются. Final guard повторяется после durable terminal publication; late Stop/cancel возвращает ошибку API, already complete files остаются evidence. Ready-idle metadata не разрешает actual runtime Start/acceptance.

Acquire должен предшествовать StrategyLab CAS lease: component generation lease → StrategyLab lease → short common actual-effect admission. Callback begin содержит только bounded stage chmod+rename, receipt rename/unlink либо actual Start syscall, не fsync, Wait или Store lock. CORE держит оба необходимых leases до durable NFQWS session ACK и обрабатывает Check/Close errors. Actual runtime activation при active/reappeared stock owner остаётся blocked-foreign; producer не останавливает/усыновляет stock.

## Проверки и handoff

Local Windows file models: install, exact ordered descriptor, held session excludes installer, immutable LKG A→B→A, 13 install publication boundaries +6 rollback boundaries с новым Manager/recovery без download/command replay, strict schema3/duplicate closure, missing permanent inode, Stop/reader/nil/active-runtime guards, forged nil-effect admission, malformed paths/types/duplicates/gzip CRC/trailing/bomb/missing/wrong hashes, third image and generation tamper. Official research IPK381072 data-only install также PASS, все шесть exact selected/raw hashes и immutable descriptor; Runner отказывает любому command. Stock DB/config/init/binary/ndm fixture bytes до/после совпадают. Это file/model verification, не запуск настоящего NFQWS.

Windows components/updatecheck/selfupdatejournal full tests и vet RC0; Linux amd64/ARM64 test compilation и Linux vet RC0. `scripts/test-nfqws-bundle-native.sh` — coordinator Linux/race launcher, только TempDir/file fixtures. Опциональный `RAZVILKA_MANAGED_NFQWS_IPK` указывает уже локальный official archive и не вызывает download. Linux-specific test uses actual common CORE Stop lock непосредственно до real generation/receipt rename, проверяет retained pending/no ready receipt/revoked epoch/no Stop reset; cross-compiled здесь, execution требуется Root. Physical power-cut, disk-full/fsync hardware behavior и runtime/Lua/UID/NFQUEUE/packet visibility не заявлены.

До включения production consumer: Root принимает checkpoint/native tests; CORE связывает actual callbacks, highest component reader3 и retained old/candidate/backup write admission3, согласует legacy downgrade/self-update reader gates для schema3, преобразует lease descriptor в approved NFQWS session и удерживает его по указанному порядку. Этот коммит намеренно не поднимает existing CLI capability2/main/HTTP/StrategyLab native flag, не переносит NFQWS9cdcbff/f7a46bf WIP/held ancestry и не редактирует их owner files. Full application acceptance и runtime activate остаются отдельной CORE/NFQWS/NET порцией.
