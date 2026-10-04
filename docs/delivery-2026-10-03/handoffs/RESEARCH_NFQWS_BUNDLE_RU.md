# NFQWS2 без stock hooks: управляемый payload — 04.10.2026

Продолжение принятого `48b3ab0`, та же ветка `sol/research-20261004`. Задача этой порции — реализуемая установка/обновление, а не очередной отказ stock hooks. Production, go.mod/VERSION, package DB, VM, роутер и GitHub не изменены. Бинарники **не запускались**, сборки/установки не выполнялись. Исходники, release metadata и отдельные archive members читались как данные в Temp; opkg и лицензии netfilter дополнительно проверены read-only subagent `opkg_scripts_check`.

## Рекомендация для первой реализации

Ввести один provider `managed-nfqws-payload` для существующего engine NFQWS2: собственный каталог RAZVILKA, один закреплённый исходный архив, allowlist binary/Lua/blobs, immutable generation и receipt. Installer только скачивает/проверяет/раскладывает данные и заканчивает `ready-idle`. Он **не вызывает opkg или какой-либо upstream init/hook**. Активацию выполняет существующий runtime owner после отдельного admission. Stock NFQWS2 остаётся отдельно наблюдаемым чужим package; установка managed payload не является его upgrade/adoption.

Для Netcraze/Keenetic первым поддержать **payload официального nfqws2-keenetic 1.3.1 ARM64 IPK**, извлекаемый без установки. Причина выбора: он сохраняет явный Keenetic fastpath patch, который отсутствует в unmodified bol-van release. Это не изменённый IPK и не заявление «upstream package установлен»: оригинальный архив остаётся неизменным input, новый artifact имеет имя/provenance RAZVILKA. Второй flavor — неизменённый `bol-van/zapret2 v1.0.5.2` для платформ с подтверждённой packet visibility. Не смешивать binary одного flavor с Lua/assets другого без manifest evidence.

Ограниченный первый результат OPS: `InstallManagedBundle` и `UpdateManagedBundle` с exact extraction/receipt/rollback **без запуска сетевого runtime**, плюс descriptor для NFQWS/NET owner. Такую установку можно реализовать без ожидания upstream suppression feature. Дальнейшая активация требует одного runtime adapter, а не нового сетевого manager или полного updater framework.

## 1. Проверенные официальные поставки и контрольные суммы

### Unmodified bol-van release

[Release v1.0.5.2](https://github.com/bol-van/zapret2/releases/tag/v1.0.5.2), опубликован 15.09.2026; Git commit `6b6c63e3385fa73f8af3be4a69171e947f5a319d`. [Полный tar.gz](https://github.com/bol-van/zapret2/releases/download/v1.0.5.2/zapret2-v1.0.5.2.tar.gz), 9 539 156 bytes, SHA256 `fb3bcf69e7d86b9fa2d60bd53c956ac06d9dcc3adf9392afd84865f1d94b1158`. Digest GitHub asset и локально прочитанного архива совпали. [sha256sum.txt](https://github.com/bol-van/zapret2/releases/download/v1.0.5.2/sha256sum.txt) имеет SHA256 `12557a74d31b1a3a3a951d5bb896a4accd2c423ef32fde413cd0661b5c34bc72`; перечисленные ниже binary hashes совпали с ним и с извлечёнными bytes.

Пути внутри архива начинаются с `zapret2-v1.0.5.2/`:

| Платформа | Member | SHA256 | Проверенные ELF headers |
|---|---|---|---|
| ARM64 | `binaries/linux-arm64/nfqws2` | `8788877cd4b3140357dd10524832ca508d47055efae072bc426b887bfea253a7` | ELF64 little-endian, machine183, 317852 bytes |
| MIPS | `binaries/linux-mips/nfqws2` | `5196ed96586539ee5884607f40b68c995ea0edffd9b9c4bdfdd96057194ccee6` | ELF32 big-endian, machine8, flags0x1007, 347684 bytes |
| MIPSel | `binaries/linux-mipsel/nfqws2` | `96868e12466cbc2475220651c4f7794b71ce28691f501cb24634f320ea7f4a2f` | ELF32 little-endian, machine8, flags0x1007, 350560 bytes |

У всех трёх проверенных packed ELF нет PT_INTERP/PT_DYNAMIC; [build.yml:150–187](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/.github/workflows/build.yml#L150) собирает static libraries и final `-static`. Это evidence отсутствия обычного внешнего loader/library requirement, **не native ABI PASS**. UPX присутствует в release recipe; CPU/kernel/stack/executable-memory совместимость проверяет координатор. MIPS и MIPSel выбираются по ELF class/endianness/ABI, не только строке uname; `linux-mips64` не подставляется вместо MIPS32.

Полный tar.gz содержит raw Lua, `files/fake` и `docs/LICENSE.txt`. OpenWrt embedded variant из того же release сжимает Lua и удаляет docs/source — для первого собственного layout проще полный tar.gz. Само наличие install scripts в архиве не требует их исполнения; они не входят в extraction allowlist.

### Keenetic flavor, payload из неизменённого IPK

[Wrapper release v1.3.1](https://github.com/nfqws/nfqws2-keenetic/releases/tag/v1.3.1), 23.09.2026. Annotated tag `d5b34d66111205afd27f2164dd3b985c65f0b81c` указывает на source commit `077f9af6068cd3380527085ca351b503a2dcf926`.

| Оригинальный asset | SHA256 | Проверка этой порции |
|---|---|---|
| [aarch64-3.10.ipk](https://github.com/nfqws/nfqws2-keenetic/releases/download/v1.3.1/nfqws2-keenetic_1.3.1_aarch64-3.10.ipk) | `9167d72053a83a78f48f6439af38432fb2d1d411fb22c0980240a949ace614df` | Download digest, control и selected payload members |
| [mips-3.4.ipk](https://github.com/nfqws/nfqws2-keenetic/releases/download/v1.3.1/nfqws2-keenetic_1.3.1_mips-3.4.ipk) | `6896bf8c8e6b59be945ee8eb1e6cff7247e300bd2f049f68caab4c53d39d7f58` | Download digest; payload/ABI отдельно не проверены |
| [mipsel-3.4.ipk](https://github.com/nfqws/nfqws2-keenetic/releases/download/v1.3.1/nfqws2-keenetic_1.3.1_mipsel-3.4.ipk) | `c31d324fd444f658b598a7f9e817733c175153cdc804759d35fe1551e7e2c34f` | Только GitHub asset digest: OS antivirus заблокировал локальный read |

ARM64 IPK — outer gzip tar с `control.tar.gz`, `data.tar.gz`, `debian-binary`; это также видно в [packages.mk:89–123](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/packages.mk#L89). Allowlist относится только к regular data members: `./opt/usr/bin/nfqws2`, три `./opt/etc/nfqws2/lua/zapret-{lib,antidpi,auto}.lua.gz`, два `./opt/etc/nfqws2/blobs/{quic_initial,tls_clienthello}.bin`. **Не извлекать** init, ndm/netfilter hooks, shell config, lists, control scripts в live `/opt`. Control можно читать как metadata, без исполнения и записи stock status.

ARM64 binary имеет SHA256 `0c97153a2cc72392776fc550bf7be1cec77bc5db2505ab5b9dbc6d071e739c09`, ELF64 LE machine183, 318336 bytes; он отличается от bol-van binary выше. [build-nfqws2.yml](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/.github/workflows/build-nfqws2.yml) применяет patches и использует latest upstream release при сборке. [fastpath patch](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/patches/001-tls-reasm-fastpath.patch#L125) вводит process-wide retransmission detection и обработку incomplete TLS reassembly. Это source evidence алгоритма; пользу на Netcraze здесь не испытывали.

Manifest обязан назвать flavor `keenetic-payload-1.3.1`, wrapper source/tag, parent IPK digest и patches. Нельзя подписывать binary как unmodified bol-van только по одинаковому printed version: wrapper сохраняет upstream version macros. Для exact parent build provenance потребуются resolved upstream commit/toolchain из конкретной сборки; в этой порции runtime version не запускалась и полный build attestation не установлен. Exact input/payload digests установлены независимо от этого ограничения.

### Общий минимальный Lua/blob набор

Ниже raw/decompressed SHA256. Для bol-van проверены raw members архива и raw source по commit; для Keenetic ARM64 проверено совпадение после чтения gzip stream. Исходные gzip bytes имеют отдельные digests и тоже должны войти в input manifest, если распространяются compressed.

| Роль | Raw/decompressed SHA256 | Wrapper ARM64 gzip SHA256 |
|---|---|---|
| `zapret-lib.lua` | `b67a470f23b00a8d6e732c4e5135a39b224511e0b71809d5f4616adf62674980` | `7c586c11c8cfa14031c348cb7715890434df779d2bb0cc7ddf0f81f599c70024` |
| `zapret-antidpi.lua` | `31c9dd75b0bd55e98e5306293f2be81e9d2ecadcbbf9157394ff37dcff7dc85a` | `9017b2684a0b7aba96221fde0f9548254764f946b8d73f7abbb2ea8286e6f0b6` |
| `zapret-auto.lua` | `c2028f544134b0dec33f054ac54fe4f2315d969ba034601456f72017fd5f8528` | `f643392e43f5b87cd75e71fb38883dece57df30d563cd86aca987654c75df422` |
| QUIC fake: upstream `files/fake/quic_initial_www_google_com.bin`, wrapper `quic_initial.bin` | `f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a` | — |
| TLS fake: upstream `files/fake/tls_clienthello_www_google_com.bin`, wrapper `tls_clienthello.bin` | `936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c` | — |

[zapret-lib.lua:1–5](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/lua/zapret-lib.lua#L1) требует `NFQWS2_COMPAT_VER_REQUIRED=6` и отказывает при несовпадении. Загрузить lib→antidpi→auto в этом порядке, с абсолютными immutable paths; aliases `quic_initial`/`tls_clienthello` задать самим compiler. В первой порции не нужны mdig/ip2net, blockcheck, obfs/pcap/tests Lua или upstream installers. Пользовательские стратегии, которым нужны дополнительные trusted assets, получают отдельную manifest capability; ничего молча не удалять.

## 2. Dependency/license manifest: не маркировать весь executable MIT-only

Main zapret2/Lua/assets имеют [MIT notice](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/docs/LICENSE.txt), wrapper — [MIT](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/LICENSE). Однако Linux binary statically links другие проекты; [nfq2/Makefile:20](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/Makefile#L20) и [workflow:84–185](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/.github/workflows/build.yml#L84) дают dependency recipe:

| Dependency | Recipe/version | Primary license evidence |
|---|---|---|
| libnfnetlink | 1.0.2 | [Official source](https://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-1.0.2.tar.bz2), `src/libnfnetlink.c:10–12` GPLv2 без later; отдельные iftable/rtnl GPLv2+ |
| libnetfilter_queue | 1.0.5 | [Official source](https://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.5.tar.bz2), `src/libnetfilter_queue.c:6–8` GPL-2.0-or-later |
| libmnl | 1.0.5 | [Official source](https://www.netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2), `src/socket.c:4–7` LGPL-2.1-or-later |
| LuaJIT | OpenResty 2.1-20250826 для ARM64/MIPS/MIPSel; FFI disabled | [Tagged COPYRIGHT](https://github.com/openresty/luajit2/blob/v2.1-20250826/COPYRIGHT), MIT с additional notices |
| musl / libm / libgcc | musl-cross toolchain через floating `latest`; `-static-libgcc` | [musl COPYRIGHT](https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT); exact toolchain/version не установлен, compiler runtime notices включить из выбранной сборки |
| zlib | workflow запрашивает `releases/latest`, exact версия этой сборки не установлена | [Upstream LICENSE](https://github.com/madler/zlib/blob/master/LICENSE), zlib license; latest license read не заменяет source pin |
| embedded SHA/HMAC/HKDF и AES/GCM | в самом source tree | [sha.h](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/crypto/sha.h): IETF Trust notice; [aes.c](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/crypto/aes.c) и [gcm.c](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/crypto/gcm.c): public-domain/no-copyright declarations |

Recipe подтверждает версии первых четырёх dependencies, но не является полностью закрытым SBOM всех build inputs: toolchain и zlib floating. Digest подтверждает exact binary, не reproducible build. Нельзя выдумать missing versions по дате релиза или ELF stub. В bundle manifest эти поля явно `unresolved-build-input`, platform acceptance отдельно от provenance.

**Практический первый выпуск:** RAZVILKA поставляет reviewed manifest/layout и downloader; оригинальный binary загружается непосредственно из закреплённого upstream asset и локально собирается в owned каталог. Не включать новый composite executable archive в MIT RAZVILKA distribution под ложной MIT-only маркировкой. Сохранить notices/source URLs в installed metadata. Если координатор выбирает собственный распространяемый binary bundle, сначала фиксируется complete corresponding source/recipe/dependency notices для GPL/LGPL частей; bounded fallback — собственная pinned сборка этих семи групп dependencies с точными toolchain/zlib hashes и честным новым flavor/build ID. Ни такой сборки, ни заявления о полной compliance готового composite archive здесь нет.

## 3. opkg: существующая suppression семантика и почему она здесь не нужна

Проверены upstream `80503d94e356476250adaf1f669ee955ec26de76` и все семь Entware patches `969c703e6fd8b2ad84d82affaeb14b48d1fcb105`:

- В [CLI options:61–116](https://github.com/openwrt/opkg-lede/blob/80503d94e356476250adaf1f669ee955ec26de76/src/opkg-cl.c#L61) и [config options:45–77](https://github.com/openwrt/opkg-lede/blob/80503d94e356476250adaf1f669ee955ec26de76/libopkg/opkg_conf.c#L45) нет отдельного live/package-specific `no-scripts`. `noaction` — dry run, `download-only` не устанавливает. Entware patches такого switch не добавляют.
- [pkg_run_script:1355–1371](https://github.com/openwrt/opkg-lede/blob/80503d94e356476250adaf1f669ee955ec26de76/libopkg/pkg.c#L1355) действительно пропускает **все** maintainer scripts при offline_root без force_postinstall. Force снимает эту общую защиту; далее /bin/sh выполняет hook без chroot. Это не suppression только daemon start.
- [opkg_cmd.c:421–428](https://github.com/openwrt/opkg-lede/blob/80503d94e356476250adaf1f669ee955ec26de76/libopkg/opkg_cmd.c#L421) считает return0 успехом configure и ставит installed. При успешном configure pass offline установка заканчивается installed, хотя scripts были пропущены. Partial/flag-unpacked/следующий upgrade вновь могут вызвать сохранённые stock scripts; live install вызывает configure(NULL) также для других unpacked packages.

**Важная оговорка к абсолютному «невозможно»:** по [opkg_conf.c:92–101](https://github.com/openwrt/opkg-lede/blob/80503d94e356476250adaf1f669ee955ec26de76/libopkg/opkg_conf.c#L92) offline prefix `/` + dest `/` образуют `//`, то есть на Linux тот же root. С explicit config можно получить live file writes при offline skip. Это вывод из кода, не испытание. Такой обход глобально пропускает обязательные hooks, пишет stock DB/files/init, сохраняет latent scripts и нарушает требование сохранить чужого owner. Для RAZVILKA он отвергнут. Честный вывод: **нет подходящего live/package-specific switch**, но есть offline skip, который не решает нашу задачу.

Managed extraction не использует даже offline opkg: Go archive reader читает regular members как данные. Нет command receipt opkg, принятого `installed` статуса stock package, скрытой postinst migration или повторения unknown package command. Лицензия opkg headers — GPL-2.0-or-later, COPYING — GPLv2; его код не переносится в MIT приложение.

## 4. Минимальный layout и API для OPS/NFQWS/CORE

Один новый data root под существующей установкой, например `/opt/lib/razvilka/nfqws2/releases/<manifest_digest>/`. Это **файловое пространство имён**, не Linux namespace. В нём `bin/rzv-nfqws2`, `lua/`, `blobs/`, `manifest.json`, `licenses/`. Переименование файла не меняет upstream bytes; actual executable identity хранит digest+dev/inode, а не basename. Mutable config/lists/log/autohostlist и runtime receipts — отдельно в `/opt/var/lib/razvilka/nfqws2/`, с владельцем/режимами для выбранного UID. Никаких shared writes в `/opt/etc/nfqws2`, `/opt/usr/bin/nfqws2`, stock init, ndm hooks или opkg DB.

`ManagedNFQWSManifest{schema, provider_id, flavor, source_repo, tag, source_commit, parent_asset_url/size/sha256, architecture/abi, members[path,size,sha256,destination], lua_compat:6, dependencies, notices, allowed_features}` закрепляет входы. SHA256 из того же публичного endpoint — integrity, не независимая подпись автора; admission использует уже принятый coordinator trust/review manifest. GET/login/UI не запускают download/install. Не брать latest на router во время применения.

`InstallManagedBundle(ctx, reviewed_manifest, expected_revision) -> BundleReceipt{transaction_id, manifest_digest, generation_path, state:ready-idle}`: fixed trusted TLS hosts; bounded size/count/decompression; reject traversal, absolute names, symlink/hardlink/device и duplicate selected member. Извлекаются только точные allowlisted regular members; остальные entries читаются/пропускаются в пределах лимита, без materialization. Missing member, иной тип/размер/hash выбранного member или destination вне owned staging — отказ. Не распаковывать весь archive в /opt и затем удалять hooks. Проверить hashes до publication, fsync files/directory, atomic generation publication, old LKG не удалять. Install/upgrade не устанавливают network rules и не порождают долгоживущий runtime как child update supervisor.

Receipt и file phases подключить к существующему OPS component journal/recovery, с явным provider ID; второй updater/journal не создавать. Matching repair проверяет staged/published owned bytes и receipt, не исполняет opkg для этого provider. Уже опубликованная complete generation может быть read back после crash; это не право её запустить. CORE сохраняет отдельные auth/CSRF/CAS/Stop admission для файловой операции и runtime activation.

`NFQWSRuntimeDescriptor{receipt_id, flavor, executable_path/hash, ordered_lua_paths/hashes, blob_alias_paths/hashes, lua_compat, allowed_features}` отдаётся NFQWS owner. Existing `internal/components/release.go` поддерживает один binary и другое имя checksum asset; заменить одну строку Provider в Specs недостаточно. Нужен маленький multi-member payload provider, не обход проверки existing manifest. `NFQWS2Adapter` на базе имеет stock ConfigPath/InitPath и restart через S51: managed mode должен идти через отдельный проверенный backend/descriptor, не маскироваться под этот init. StrategyLab/engineconfig получают те же descriptor paths; PATH search не подменяет exact executable evidence.

Первый argv compiler: `--qnum=<owned_queue>`, `--uid=<reviewed_uid>:<reviewed_gid>` (либо `--user=<reviewed_username>`, не числовой UID), три `--lua-init=@<absolute_lua>`, два `--blob=<alias>:@<absolute_blob>`, собственные list/log paths и reviewed strategy argv. [nfqws.c:1828–1829](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/nfqws.c#L1828) различает username и numeric UID/GID. Без `--daemon`, shell eval/source и upstream startup scripts. Foreground process принадлежит runtime supervisor; update installer возвращает idle и не ждёт его через package ECHILD. Unmodified flavor не принимает `--fastpath-workaround=auto`; explicit пользовательская стратегия с этим флагом получает flavor mismatch, её нельзя молча переписать.

**Validation limits:** [nfqws.c:3351–3368](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/nfqws.c#L3351) dry-run заканчивается до nfq_main. Он проверяет argv/list/script files, но не исполняет полноценный Lua init: [lua.c:4662–4676](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/lua.c#L4662) вызывается при runtime startup. Кроме того, до dry-run exit возможны собственные writable-dir/file-access effects. Поэтому dry-run только с staging-owned paths; version/dry-run не live acceptance и не доказательство работы circular/functions. Lua compatibility подтверждается manifest+actual runtime startup, не одним exit0 dry-run.

## 5. Сохранение stock owner и обновление своей active generation

Install/update managed files разрешён при наличии stock package: это не takeover. **Activate** отказывается при active foreign NFQUEUE/rules или неизвестном пересечении scope; очередь с другим номером сама по себе не устраняет двойную DPI обработку. Никаких stock `stop`, `restart`, `disable`, `opkg remove`, killall, изменения stock config/init или global offload/sysctl. В read-model: «managed готов, activation blocked by foreign owner». Пользователь отдельно прекращает/перенастраивает чужой owner своими средствами; после нового readback возможна обычная reviewed активация. Даже stock stopped сейчас не доказывает, что rc.unslung не вернёт его на boot: до автоактивации после boot снова проверять conflict, при его появлении убирать только свои rules/process и сохранять fence.

NFQWS/NET предоставляют `ActivateManagedNFQWS(descriptor, scope, control_epoch)` через существующие authority/addition receipts: свободная queue, owned mark mask/chain names, exact process birth/exe/config identity, scoped additions и cleanup. [nfq_create_queue documentation](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html) обещает отказ при уже существующей queue, сохраняя её. Но [nfqws.c:355–392](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/nfqws.c#L355) также вызывает protocol-wide bind/unbind; source comment считает их NOOP начиная с Linux3.8. На Netcraze4.9 и особенно vendor/MIPS3.4 это надо доказать native readback, а не предположить по отдельному queue ID. До такого proof совместное существование с foreign queues не разрешать. Никакого требуемого PID/net namespace или children interface.

Обновление своей active generation: OPS stages immutable candidate; runtime owner стартует его в собственной свободной queue без LAN redirect, проверяет identity/Lua readiness; NET отдельно переключает только owned scoped path, затем acceptance. Старый LKG и его mutable state сохраняются до принятия; candidate не пишет в старые autohostlists/logs. При failure вернуть verified old generation/owned path, не stock runtime. Stop epoch отменяет startup/switch/acceptance и разрешает только exact cleanup. Если безопасный hot switch пока отсутствует, bounded первая версия — reviewed scoped pause→exact old stop→candidate activate→accept или verified LKG rollback; не заявлять zero downtime. Pending/unknown и crash требуют matching receipt recovery, не второго безусловного launch.

## Приёмка и граница исследования

1. **OPS file-only:** install/update из закреплённого archive, hashes/MIPS endianness, malformed tar/gzip/duplicate/traversal/bomb, disk-full/fsync/rename faults. Stock package DB/config/init/binary до/после byte-identical; ни один hook не исполнен. Перезапуск после каждой publication boundary оставляет old либо complete candidate и pending receipt, LKG не потерян.
2. **NFQWS/NET native:** exact foreground ownership, UID file access, Lua compat6, missing blob/function, queue collision и foreign protocol handler сохранены, packet visibility/fastpath, TCP/UDP v4/v6. Копирование ARM64 ELF не доказывает Netcraze совместимость; MIPS/MIPSel отдельно на hardware.
3. **Lifecycle:** active stock owner оставляет managed ready-idle; его reappearance после boot не вызывает чужой stop. Своя A→B failure→verified A; Stop в любом шаге; PID reuse/foreign same basename; crash supervisor; no global conntrack/offload changes. Packet success не service/media/voice PASS.

Фактически выполнено: primary web/raw source research; download/hash/list полного bol-van release; data-only extraction/hash/ELF headers трёх binaries и общего Lua/blob набора; ARM64 wrapper payload extraction, gzip-to-raw Lua hash comparison; wrapper MIPS archive hash; source-only opkg/license audit. После сообщения пользователя «Разблокировал» повторный bol-van download/read успешно завершился. Новый wrapper MIPSel archive был отдельно заблокирован OS antivirus; его digest взят только из GitHub API, этот read не обходился. Ограничение не мешает contract первой ARM64 реализации, но wrapper MIPSel payload остаётся непроверенным.

Проверка handoff: `Get-FileHash -Algorithm SHA256` и сопоставление digests в документе с 18 ранее прочитанными локальными archive/payload files — RC0; `tar -tvf` полного release — RC0. Это проверки данных, без исполнения binaries/hooks.

Это готовый contract к реализации, не изготовленный/подписанный managed bundle и не runtime/HIL PASS. D07/D08 не исследовались повторно. `NETWORK_POLICY_EXECUTOR_REQUIRED`, auth/CSRF/TLS/CAS/Stop/ownership/recovery/LKG/rollback сохранены.
