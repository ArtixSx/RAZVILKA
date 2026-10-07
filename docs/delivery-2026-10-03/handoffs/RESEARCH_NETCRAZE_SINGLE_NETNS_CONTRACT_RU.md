# Netcraze: принятие single init-net по полному procfs observation — 07.10.2026

**Вывод: capture90 позволяет предложить узкий поддерживаемый single init-net platform contract без окончательного `.config`.** Для приёмки Root должен явно принять соответствие работающей прошивки проверенному proc namespace directory ABI. Это одно конкретное допущение о семантике vendor kernel, а не требование бесконечной attestation всей системы. Сам capture90 это соответствие не удостоверяет. Документ не принимает production profile, не меняет guards и не объявляет backend coverage/PASS.

База research `2d6e073b74befead99df436222141efe9c8c68b5`; shared reader review `3e94a675c5eddbdd049467ed25647d60d165ce9d`. Новое поручение Root: source/documentation по уже выполненным им QA probes. Здесь production, helper source, роутер, VM, firmware, storage и firewall не менялись; новые runtime probes не выполнялись.

## Что установлено теперь

| Evidence | Установленный результат | Граница |
|---|---|---|
| `router-version79.json` | Netcraze Ultra NC-1812, aarch64, stable, release `5.01.C.6.0-1`, title `5.1.6`; уточнённые scoped fields: `ndw4.version=5.1.C.6.0`, `ndm.exact=0-996b1e0` | Идентификация выпуска; не связь машинного procfs кода с source pin |
| `router-metadata81.json` | `/opt` root:root0755; `/opt/etc` и `/opt/var` 1001:1001; три net paths отсутствовали; registered IPv4/IPv6 names `nat/mangle/filter` до/после совпали | Storage/tool trust и backend completeness остаются отдельными проверками; предыдущие ENOENT сами по себе не были namespace proof |
| Root Go1.26.5 QA | По сообщению Root, amd64/arm64 crossbuild PASS; VM procns90 RC0, `netPresent:true`, полное чтение и все checks TRUE | Положительная проверка обычного NET_NS=y пути; VM JSON здесь не читался |
| Прочитанный `router-procns90.json` | RC0, release `4.9-ndm-5`, names ровно `["mnt"]`, `netPresent:false`, `mntPresent:true`, `directoryComplete:true`, `observationValid:true`; все 15 checks TRUE, budget не истёк, stderr пуст, временные файлы удалены | Полное проверенное наблюдение; `observationOnly:true`, `runningAbiAttested:false` сохраняются |

Capture90 закрыл конкретный недостающий факт capture81: теперь есть полная directory enumeration с нулевой позиции до explicit EOF, а не только неуспешные lookup/readlink. Helper не фильтрует DT_UNKNOWN или zero-inode records. Удержанные procfs FDs, numeric PID/task/TID walk без следования symlink, procfs magic/device/fs identity/mount IDs, self links, task start, boot, mountinfo и повторно открытый путь прошли проверки вокруг чтения. В этом capture DT_UNKNOWN не наблюдался.

Прочитанные локальные artifacts и hashes:

- [version79](C:/Projects/RAZVILKA/delivery-review/.review-local/router-version79.json): SHA256 `c8eb7483f3c5404e852e1fe17af0c7669e6425340a41ec9123b0d001c2ac3969`.
- [metadata81](C:/Projects/RAZVILKA/delivery-review/.review-local/router-metadata81.json): SHA256 `321546f4f64de46d5332f112a4f0ad0d8e3a0e5dccde2b6be86dc0991f9482ea`.
- [procns90](C:/Projects/RAZVILKA/delivery-review/.review-local/router-procns90.json): SHA256 `77e95c83d30c2f1ce4b2d9719e208f4cf46c63e3fbf9e9db311c9cc292dbee40`.
- [helper source](C:/Projects/RAZVILKA/worktrees/sol-research/.review-local/procns-audit/main_linux.go): SHA256 `53eceab895ac42d28b4d7cc3198a7946cc4fb0b5a8148e1138f546efa9d1295e`, после Root QA не изменён. ARM64 binary SHA256 из artifact: `045aa23e4d83611bd1d110b05c02d8be2ed90a9c3333a991e18e832e47aa17ba`.

Boot IDs, mount paths с volume identifiers, task IDs и другие приватные raw значения в документ не перенесены. Ограничения userspace watchdog описаны в [helper README](C:/Projects/RAZVILKA/worktrees/sol-research/.review-local/procns-audit/README.md); RC0 не превращает его в гарантию остановки произвольного kernel syscall за 5 секунд.

## Почему отрицательное наблюдение имеет положительный смысл при принятом ABI

Vendor kernel pin: `7b6c9477d429217042117fbfa3d2e9894a087607`, tag `4.9.337-181-2`.

1. В [fs/proc/namespaces.c:14–37](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/fs/proc/namespaces.c#L14) `netns_operations` добавляется первым под `CONFIG_NET_NS`; `mntns_operations` присутствует без этого guard. Имя операции — [ровно `net`](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/core/net_namespace.c#L1062).
2. [proc_ns_dir_readdir](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/fs/proc/namespaces.c#L111) перечисляет этот массив. Он не проверяет доступ к каждому namespace и не вызывает его `.get` для выбора имён. Исчезнувшая задача даёт ENOENT; исчерпание буфера оставляет позицию для следующего чтения. [proc_fill_cache](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/fs/proc/base.c#L1840) выдаёт имя и при ошибке instantiate, используя DT_UNKNOWN. Permissions/hidepid не создают здесь выборочного пропуска `net`.
3. Поэтому при этой семантике успешная полная enumeration без `net` несовместима с включённой поддержкой net namespaces. Это логическое следствие принятого source ABI, не результат чтения фактического `.config`. `["mnt"]` допустим: остальные имена имеют свои compile guards; наличие нескольких других namespaces не требуется.
4. Семантика single initial network scope подтверждается [init_nsproxy.net_ns=&init_net](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/kernel/nsproxy.c#L32), веткой [copy_net_ns без CONFIG_NET_NS](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/include/net/net_namespace.h#L159), сохраняющей прежний scope, и [read_pnet](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/include/net/net_namespace.h#L269), возвращающей init_net. Это стандартная семантика проверенного kernel, при существующем доверии его реализации.

Здесь отсутствует неоднозначность errno от pernet callbacks, разобранная для unshare. Однако совпадение `uname` и успешных helper checks само по себе не связывает работающую реализацию с этим source: kernel с сохранённым release и изменённым `ns_entries[]`, убравшим `net` при работающем NET_NS, мог бы дать такой же JSON. Это конкретный контрпример **без** принятого directory ABI contract.

## Что именно остаётся допущением

Официальный SDK ref `5.01.C.6.0-1` закреплён на `1d58c10c46e270d6876836e5455fa4e9b786ad1e`. Его [kernel-defaults.mk](https://github.com/keenetic/keenetic-sdk/blob/1d58c10c46e270d6876836e5455fa4e9b786ad1e/include/kernel-defaults.mk#L8) выбирает kernel tag выше, а [localversion](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/localversion-ndm) задаёт `-ndm-5`. [SDK README:23–47](https://github.com/keenetic/keenetic-sdk/blob/1d58c10c46e270d6876836e5455fa4e9b786ad1e/README.md#L23) связывает выбор ref с собственной версией firmware. Эти facts дают конкретного кандидата ABI для observed release.

**Не доказана ровно связь:** установленный stock Netcraze NC-1812 release/build использует перечисленную семантику proc namespace directory, включая отсутствие selective hiding `net`. SDK описывает KeeneticOS; profile `KN-1812` и соответствующий hardware дают corroboration, но сами не удостоверяют NC-1812 image mapping и running proc implementation. Final config всех компонентов, полный module inventory и хэш каждого kernel byte для данного namespace вопроса не нужны.

Для эксплуатационного platform profile возможны два честных уровня:

- **Maintainer-accepted vendor ABI:** Root явно принимает эту узкую связь для указанного stock выпуска на этом устройстве, записывает источник, pin и допущение. Capture90 становится достаточным observation evidence для single init-net scope. В записи приёмки должно быть «accepted vendor ABI contract», а не «running ABI independently attested» или «CONFIG_NET_NS прочитан».
- **Source-bound corroboration вместо допущения:** одно положительное vendor release/source manifest или подтверждение, связывающее NC-1812 exact build с этим proc ABI, закрывает оставшуюся связь. Проверенный firmware/kernel provenance, уже имеющийся у Root, также годится. Достаточно подтвердить используемую семантику; требовать побайтовую идентичность всего firmware исходникам необязательно. В этих artifacts такого binding нет.

Доверие stock kernel и собственному reviewed reader, отсутствие намеренного syscall/buffer interposition остаются общими assumptions любого native inventory. Helper не проводит их независимую attestation. Это не новая специальная цепочка требований для single-netns: Root может использовать существующую доверенную среду QA/deployment. Для custom/patched kernel или недоверенного reader этот profile неприменим.

**Рекомендация:** Root может завершить namespace design acceptance через явно записанный первый уровень. Новой router enumeration, unshare probe или извлечения `.config` ради этого условия не требуется. Если политика Root требует внешнего source binding, нужен только указанный release→ABI input; до него результат остаётся observation-only, а не поводом для broad search.

## Минимальный контракт реализации для existing owner

1. Поддержка отдельного profile для **NC-1812/aarch64, exact release/build выше и kernel `4.9-ndm-5`**; `uname` не выбирает его автоматически. Profile связан с проверенным deployment и принятой source ABI семантикой. Изменение firmware/build/kernel, отсутствие подтверждённого profile или custom kernel требует нового review; broad `4.9-*` fallback не допускается.
2. Existing namespace/inventory owner получает свежую bounded observation в собственном locked thread/process context: trusted anchored procfs, нулевая позиция, все raw names до EOF, `mnt` присутствует, `net` отсутствует, identity/mount/boot brackets успешны. Старый JSON helper90 служит acceptance evidence, но не reusable authority будущего inventory. Лимиты/ошибки/неподходящий mount/смена task или boot дают Unknown.
3. Identity имеет явный вид **vendor single initial network scope**, отличный от proc namespace inode identity. В неё входят accepted profile identity и настоящий непрозрачный boot epoch вместе с успешными scope checks. Boot различает загрузки и **не доказывает singleton**. Не синтезировать `net:[0]`, fake inode или namespace token из одного boot ID. Источник profile acceptance и raw `runningAbiAttested:false` хранятся раздельно.
4. Reader связывает classic/proc/native observations с одной такой scope identity и проверяет действительность контекста на existing review/effect boundaries. При отсутствии принятого profile обычный netns inode путь сохраняется; ENOENT не запускает универсальный fallback. NET_NS=y VM с `netPresent:true` успешно проходит helper, но не принимается singleton profile.
5. Грант относится только к network scope binding. Current `RegisteredTablesComplete=false`, fixed-five coverage, storage/tool review, mutation admission и nft guards не снимаются этим документом. Adapter принадлежит existing owner, без второго decoder, daemon или параллельного inventory authority.

## Минимальная приёмка и meaningful tests

Сборка двух architectures и positive NET_NS=y VM уже выполнены Root. Router90 уже подтверждает negative observation. Повторять их без изменения source/platform или неуспешного результата не требуется. Ниже тесты для будущего typed adapter и guard, а не поручение нового router probe.

| Сценарий | Ожидаемая приёмка |
|---|---|
| Accepted exact profile + полная стабильная `["mnt"]` observation | Typed single initial scope принят; это не backend Complete/Empty/PASS |
| VM с `net`, либо неизвестный model/build/source profile | Обычный supported netns путь или Unknown; singleton не выдаётся по одному release/ENOENT |
| Начальная позиция 3, буфер содержит только другие names и EOF | Отказ: конкретный false-negative сценарий пропуска первого `net` не принимается как полная enumeration |
| `net` в DT_UNKNOWN или zero-inode record | Имя сохраняется; отсутствие `net` не объявляется |
| Частичный read без EOF, ошибка, malformed/duplicate record, превышение cap, отсутствие `mnt` | Unknown; partial names и syscall success не становятся singleton authority |
| Symlink/submount shadow, изменённый FD identity, PID/TID/start/boot/mount bracket | Отказ до допуска inventory/effect; прежний accepted scope не переиспользуется |
| Firmware/build/profile или boot сменился после review | Старое scope evidence инвалидируется; новый review обязателен |
| Accepted singleton + nft EINVAL/EOPNOTSUPP или неполный registered-table read | Backend остаётся Unknown/incomplete; namespace capability не маскирует ошибки collector |

Граница test proof: injected faults проверяют поведение consumer при известных нарушениях; native Root captures проверяют реальные syscalls. Они не удостоверяют отсутствие произвольного adversarial kernel modification или writer ABA. Существующие trust/writer assumptions сохраняются явно.

## Отдельно о NFT и итоговом статусе

Single init-net profile позволяет именовать effective network scope. Он **не** доказывает NF_TABLES=n, отсутствие compiled/unloaded providers, отсутствие nft tables/rules или полноту classic tables. Для NFT сохраняется reviewed complete all-family GET evidence либо отдельно accepted exact backend absence profile; raw errno не означает отсутствие. Registered `nat/mangle/filter` из metadata81 не заменяют complete collector и rules readback.

Finished research result: source implication и необходимые acceptance boundaries определены, helper90 observation проверен. Namespace prerequisite может быть закрыт Root после явного vendor ABI acceptance и reviewed typed implementation. Production code/guards, текущий backend HOLD и storage ancestors не изменены. Проверка документа: source/artifact/hash review и `git diff --check`; runtime QA принадлежит Root, а не этому documentation turn.

Уточнение ROOT по фактическому ответу команды (`router-version100`, 07.10.2026): ранний helper79 уплощал вложенный текст регулярным выражением и оставлял последнее поле `version`. Это значение принадлежит **ndw4.version**, не является отдельным полем версии firmware; `ndm` является группой с `exact`. Сам release `5.01.C.6.0-1` и kernel `4.9-ndm-5` подтверждены без изменения. Production producer должен разбирать уникальные поля в соответствующих группах, отвергать неоднозначность и не использовать этот ранний flattened JSON как authority. Наблюдавшиеся два внешних `ESC[K` относятся к оформлению CLI; они не разрешают произвольные управляющие последовательности внутри полей.