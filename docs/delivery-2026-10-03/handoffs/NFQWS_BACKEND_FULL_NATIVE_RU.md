# ROOT full backend inventory fixture — 07.10.2026

QA-only follow-up поверх finished collector `0d847deffbfe4b99c6249bbecdbe89a66d7525e6` и bounded CLI fixture compatibility `9c0d83037ddc08bbd3746545c521fb48362f9d0c`. Новый `network_backend_inventory_native_linux_test.go` и этот handoff; production collector/provider/issuer/receipts не меняются. ROOT запускает VM/router последовательно, owner только model checks/vet/cross-compile. Platform PASS пока не заявлен.

`TestBackendInventoryFullNativeObservation` по умолчанию SKIP. Explicit QA selector `RAZVILKA_BACKEND_INVENTORY_NATIVE=linux70` или `stock-nc1812`; другие values отказывают. Требуется euid0. Это **test-only deployment selector**, не production profile/environment fallback.

- linux70: actual `netidentity.NewProcProvider`, `/usr/sbin/iptables-legacy` и `/usr/sbin/ip6tables-legacy` → Root fresh-reviewed `xtables-legacy-multi`, version1.8.11(legacy), SHA256 `da62b7b5a7371424906138fa1eba11ec922b256969e5fa3dfa716949abafe8ac`.
- stock-nc1812: actual accepted `NewReviewedStockNC1812Provider` и explicit stock collector constructor; `/opt/sbin/iptables` и `/opt/sbin/ip6tables` → version1.4.21 `xtables-multi`, SHA256 `966a3efa461f9f42a9f48dfb8c0bc8b5ef858aac1130adf5f84e3724b3ec2acf`. Дополнительно exact Root pins libip4tc.so.0.1.0 `70b9df4548483520cfcdcb89cddbe7ff2faa7cae89ed53e22ad60544fdca1c2a`, libip6tc.so.0.1.0 `48a62bbcb302d06abdc438720de6275f63435cd77e87a9379ba5f7aa463788de`.

ROOT явно принял эти **fixed-tool deployment fixture assumptions** для actual QA. Они не являются новым general production tool/admission issuer. На stock ROOT подтвердил root0:0/0755 для `/opt`, `/opt/sbin`, `/opt/lib`; uid1001 относится к `/opt/etc` и `/opt/var`. Никакого chown или изменения deployment этим test нет.

Fixture удерживает реальные open file descriptors, root-owned protected alias/ancestor nodes и symlink targets; проверяет pinned multicall/TC hashes, ELF64 target machine/little-endian, bounded file-backed extents (NOBITS memory-only), PT_INTERP + recursive DT_NEEDED через fixed protected library roots, допустимые fixed RPATH/RUNPATH, всю существующую xtables extension directory и её stable name set. Остальные ELF/dependency hashes берутся с actual Root-reviewed deployment и повторно сверяются, а не объявляются independently attested trust. Caps:384 images/64MiB total/16MiB each, до32 dependencies наimage, до256 extension entries/directory, bounded dynstr/interpreter/versions. Unknown lookup/shape/path/alias/hash/version отказывает.

Mandatory real CheckTools повторяет retained path/inode/mode/owner/hash/alias/dependency/extension checks и обе actual `--version` commands до initial и final classic image. Проверяется отсутствие loader preload files; реальные команды используют fixed environment PATH=/usr/sbin:/usr/bin:/sbin:/bin и LANG/LC_ALL=C, без inherited loader/xtables overrides. Основные `-t registered-name -S` команды выполняет **именно production nfqws2ExecRunner.RunBounded**, не fake wrapper и не CLI template выдачи rows. Native ELF/file review helper существует только в `_test.go` и не используется public factory как trust issuer.

Provider construction/initial expected binding/tool fixture preparation имеют отдельный bounded2s setup context. Actual `collector.Read` получает новый original caller2s context, и его внутренние provider/tool/socket/classic/closing checks делят **этот же 2s capture budget**; Read deadline не расширен и не заменён новым operation после failure. Provider handles scope/locked-thread/closing; test не вызывает setns. Captures: real registered classic both families → full double images/name closures и real native NFT normal/sole-negative contract, Schema1 consistency. Present NFT допустим как complete inventory observation, но RequireComplete/absence gate обязан отказать.

Вывод: только static mode/stage/outcome/state, row/table/check counts, elapsed milliseconds, deadline-expired boolean, complete coverage/closing booleans и всегда capability=ungranted. Ни PID/TID/boot/netns/port/seq/generation, ни table/rule/dependency paths/names/hash payload/raw error/env/argv/private data не печатаются. FAIL не даёт partial snapshot или capability. ELF hashes выше — заранее переданные ROOT fixed deployment review pins, не live output.

## ROOT setup/build/run

VM должен иметь указанные exact legacy aliases/version/hash и их protected loader/libs/extensions (обычно `/usr/lib/x86_64-linux-gnu/xtables`, либо соответствующий aarch64 path). Registered `ip_tables_names` и `ip6_tables_names` должны уже существовать в actual thread proc net directory; missing files дают Unknown, test не запускает module commands и не создаёт таблицы. Root решает setup до opt-in; никакого nft/iptables mutation или package install внутри fixture нет. Stock использует уже проверенные aliases/provider; ROOT свежим read подтвердил обе names lists доступны через real `/proc/PID/task/TID/net`, по3 registered entries.

Обычный package binary: `go test -c -ldflags='-s -w' -o backend-full.test ./internal/dataplane`. ROOT actual launch:

```sh
RAZVILKA_BACKEND_INVENTORY_NATIVE=linux70 ./backend-full.test -test.run='^TestBackendInventoryFullNativeObservation$' -test.v
# Отдельное router окно:
RAZVILKA_BACKEND_INVENTORY_NATIVE=stock-nc1812 ./backend-full.test -test.run='^TestBackendInventoryFullNativeObservation$' -test.v
```

Для минимального binary Go overlay исключает только остальные tracked dataplane `_test.go`, оставляя `network_backend_inventory_native_linux_test.go`. Все production files/netidentity API остаются исходными. ROOT генерирует список из accepted integrated pin, не переносит owner overlay. Новый fixture не зависит от portable wire fixtures/других tests. Старый `RAZVILKA_BACKEND_NFT_OBSERVE_NATIVE`/closed49 observation сохраняется отдельным diagnostic test и не является full collector.

Fixed production environment не передаёт old test CLI role markers. Поэтому checkpoint9c0d830 выделяет единственный bounded IO/Wait body: production RunBounded задаёт fixed environment, старый nine-mode CLI fixture задаёт dedicated QA env этому же body. Actual full fixture вызывает production method. Существующий CLI fixture ROOT при желании повторяет отдельно; его native assertions owner не исполнял.

Final owner checks PASS: Windows amd64 все `TestBackend*`0.086s и package vet; Linux amd64/arm64 package vet, full test binary cross-compile и stripped minimal full-observation-only overlay cross-compile. Source/gofmt/diff checks PASS. Ни Linux/native/race, ни VM/router/live не исполнялись здесь; GET autoload и userspace deadline limitations прежние. Весь DTO/RequireComplete остаётся observation, не mutation/admission capability.

## Static tool diagnostics follow-up

ROOT native107 на accepted5899399: VM full collector PASS0.38s, actual capture168ms, rows0/NFTtables0/COMPLETE_EMPTY и2 actual tool checks. Router остановился до capture, stageTOOLS; actual unmet fixture assumption пока не установлено.

QA-only follow-up добавляет `tool-step` — до16 compiled labels, например `ALIAS_V4/ELF_DEPENDENCY/PATH_UID`, и `setup-deadline-expired` boolean. Различаются canonical path/UID/write mode, held file bounds/read/hash pin, ELF target/extents/interpreter/search/dependency, extension set, actual version и closing retained-image checks. Вложенный failure сохраняет исходную error identity через Unwrap; underlying Error/paths/names/output не печатаются. Все thresholds, root ownership, exact pins, lookup/search semantics, versions, fixed environment и2s deadlines прежние. Production files не меняются. Это диагностика отказа, не новый trust issuer, не relaxed deployment profile и не router PASS.
