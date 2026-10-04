# NFQWS: Entware xtables и прямое чтение nft — findings / proposed ABI

Дата: 2026-10-04. Основание: ROOT запросил сначала bounded ABI и findings
для штатного Netcraze / Entware, без второго network owner и сетевых мутаций.
Этот handoff не меняет `CheckNFQWSScopedOtherBackends`, common Execution,
capability или lifecycle. Production admission остаётся закрытым.

## Установленные факты

ROOT выполнил readonly проверку роутера: aarch64, kernel `4.9-ndm-5`,
iptables и ip6tables выводят `v1.4.21`; plain aliases ведут на
`/opt/sbin/xtables-multi`, отдельных `-legacy` aliases нет. Queue proc есть,
загружены nfnetlink_queue / nfnetlink_log. Утилиты nft, sysmodule nf_tables,
файлов nf_tables/nft под matching modules tree и доступного kernel config
не найдено. Эти отрицательные filesystem факты не доказывают отсутствие
встроенной или иначе загружаемой nft-подсистемы.

Проверены pinned Entware sources `969c703e6fd8b2ad84d82affaeb14b48d1fcb105`
и актуальные official Packages.gz обоих ARM64 feeds. Пакетов nftables в
обоих списках **0**. Recipe содержит nftables 1.1.6, варианты json/nojson,
но оба `BuildPackage` отключены. JSON-вариант добавляет jansson; libnftnl
не является executable nft reader. Следовательно, нельзя включать в
product preflight предложение установить готовый nft-пакет из этих feeds.
[Pinned nftables recipe](https://github.com/Entware/Entware/blob/969c703e6fd8b2ad84d82affaeb14b48d1fcb105/package/network/utils/nftables/Makefile),
[main feed](https://bin.entware.net/aarch64-k3.10/Packages.gz),
[Keenetic feed](https://bin.entware.net/aarch64-k3.10/keenetic/Packages.gz).

Official iptables 1.4.21 source archive проверен по Entware PKG_HASH.
`xtables-multi` содержит iptables / ip6tables dispatch в libiptc backend;
libiptc читает таблицы через getsockopt SO_GET_INFO / SO_GET_ENTRIES.
Вывод `-V` имеет форму `iptables v1.4.21`, без `(legacy)`. Pinned main и
Keenetic patches не добавляют nft dispatcher. `NO_LEGACY` исключает старые
ревизии отдельных xt matches, а не переключает backend на nftables.
[Official archive](https://www.netfilter.org/projects/iptables/files/iptables-1.4.21.tar.bz2),
[recipe](https://github.com/Entware/Entware/blob/969c703e6fd8b2ad84d82affaeb14b48d1fcb105/package/network/utils/iptables/Makefile),
[revision patch](https://github.com/Entware/Entware/blob/969c703e6fd8b2ad84d82affaeb14b48d1fcb105/package/network/utils/iptables/patches_kn/700-disable-legacy-revisions.patch).

Downloaded official ipk bytes совпали с SHA256 в feeds. Из архивов только
прочитаны control и извлечены выбранные executable/library bytes как data;
они не запускались и не устанавливались. Main 1.4.21-5 и Keenetic 1.4.21-6
содержат одинаковые xtables-multi и libip4tc/libip6tc. Keenetic расширяет
extensions; это не основание объявить весь пакет побайтно одинаковым.
Полные pins записаны в соседнем `NFQWS_ENTWARE_REVIEW_INPUTS.json`.

## Предлагаемый контракт trusted xtables review

Вместо проверки суффикса нужен private immutable review descriptor,
создаваемый существующим trusted runtime/component review. Простой DTO,
version string, наличие symlink или package name не дают разрешения.

Descriptor связывает оба fixed alias paths, их real targets и protected
file identity/hash с одним reviewed artifact. Для опубликованных двух
пакетов xtables-multi SHA256:
`966a3efa461f9f42a9f48dfb8c0bc8b5ef858aac1130adf5f84e3724b3ec2acf`.
Дополнительно связываются реально загружаемые backend/xtables/extension
libraries и loader search policy. Их список и hashes уже извлечены.
Caller обязан исключить подмену через LD_PRELOAD, LD_LIBRARY_PATH,
XTABLES_LIBDIR и непроверенный tool path; сохранить нужный argv[0]
iptables/ip6tables для старого multi dispatch. Проверки owner/mode,
resolution и hashes свежие до/после чтения; writer поколения удерживается
в течение использования, как в существующем OPS contract.

Bounded `-V` обоих aliases должен завершиться RC0 с точным ожидаемым
выводом. Для этого artifact ожидаются plain v1.4.21; modern legacy artifact
может иметь свой отдельный reviewed descriptor. Ни произвольная версия
меньше некоторого числа, ни подстрока `(legacy)` не являются review.
Descriptor подтверждает реализацию backend, но не пустоту kernel ruleset.

Existing whole xtables inventory сохраняется: все capture/references,
both families, scoped LAN/process/queue/Execution checks. Recipe перечисляет
четыре таблицы, current owner также требует security. Наличие/отсутствие
security на firmware ROOT ещё не проверял; описание пакета не позволяет
игнорировать таблицу. Это отдельная runtime compatibility проверка.

## Что именно читать через NETLINK_NETFILTER

Предлагается private Linux reader, вызываемый existing
`AdditionalReadback` внутри того же scoped owner. Он не создаёт journal,
не выбирает queue, не выдаёт operation admission и не устанавливает nft.
Работает только в уже проверенном текущем network namespace; не setns.

Один socket AF_NETLINK / SOCK_RAW / protocol 12, unicast kernel peer,
groups=0, bind port=0, actual assigned port из getsockname. Каждый запрос
имеет новый ненулевой sequence и фиксированные bytes, без caller raw JSON,
NLA, family filters или произвольного message type:

| Запрос | type | flags | nfgenmsg / attrs |
| --- | --- | --- | --- |
| generation | 0x0a10 GETGEN | REQUEST + ACK | UNSPEC, version=0, res_id=0; no attrs |
| all tables | 0x0a01 GETTABLE | REQUEST + DUMP + ACK | UNSPEC, version=0, res_id=0; no attrs |

Порядок: GETGEN A -> GETTABLE complete -> GETGEN B. Generation A=B;
оба replies NEWGEN имеют ровно один корректный big-endian NFTA_GEN_ID,
version=0 / UNSPEC и согласованный low16 res_id. Между endpoints current
boot/netns проверяются повторно. Успешный dump UNSPEC перечисляет таблицы
всех зарегистрированных nft families, включая bridge/netdev/inet, без
неполного IPv4/IPv6 projection. В первом bounded варианте **любая таблица
означает отказ**: для пустого состояния не нужен expression parser;
разрешение даже пустых nft таблиц потребует отдельного полного contract.
[NFT UAPI](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/include/uapi/linux/netfilter/nf_tables.h),
[GETTABLE / GETGEN implementation](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/net/netfilter/nf_tables_api.c#L452).

Предлагаемые пределы одной проверки: deadline min(ctx, now+2s), не более
3 запросов, 256KiB суммарного receive, 64 datagrams и 1024 frames; один
datagram <=64KiB. Нет automatic retry/replay после partial/error. При
изменении generation новая проверка возможна только отдельным caller
решением с новым полным budget; предыдущая не объявляется успешной.

Framing: checked 16-byte header, nlmsg_len/alignment/remaining bounds,
exact seq и assigned destination nlmsg_pid, recvmsg sockaddr AF_NETLINK
с kernel sender pid=0/groups=0. Header nlmsg_pid в Linux4.9 replies равен
destination port, **его нельзя ошибочно требовать равным нулю**. Reject
MSG_TRUNC, NLMSG_OVERRUN, NLM_F_DUMP_INTR/FILTERED, unexpected message,
duplicate DONE/ACK, unexpected attrs/padding, malformed lengths, invalid
endianness и данные после terminal. Нельзя читать только первый datagram.

Dump proof требует ровно одно NLMSG_DONE с корректным нулевым status;
zero-error ACK не заменяет DONE. На v4.9 успешный dump подавляет ACK
внутренним return -EINTR; ждать отдельного ACK для dump нельзя. Для errno требуется NLMSG_ERROR с
negative code и точной копией original request header+payload; CAP_ACK
не включать. Generation reply тоже должен получить соответствующий
успешный ACK. Ограниченный decoder допускает только исследованные формы;
неизвестное расширение остаётся diagnostic refusal до review.
[Netlink reply / ACK producer](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/net/netlink/af_netlink.c#L2139),
[UAPI framing](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/include/uapi/linux/netlink.h).

## ABI результата и genuine unsupported

Предлагаемые private reader результаты разделены:

| Состояние | Основание | Допуск existing owner |
| --- | --- | --- |
| complete-empty | exact whole dump + DONE0 + equal generations + fresh endpoints | nft inventory пройдено, остальные guards обязательны |
| present | хотя бы один well-formed table reply | отказ, не удалять чужие tables |
| unsupported-candidate | exact validated kernel error для sealed valid request | сам по себе отказ; хранить diagnostic evidence |
| unknown | permission/malformed/interrupted/truncated/deadline/changed endpoint | отказ |

Reader возвращает detached evidence: boot/netns, assigned port, request
digests/sequences, bounded terminal/error classification, generation и
count/digest. Он не возвращает reusable boolean capability/token. Отдельный
trusted platform classifier может превратить unsupported-candidate в
`kernel-unsupported` **только** на положительном проверенном firmware
contract, связывающем running build и отсутствие исполняемого nft backend.
`uname 4.9-ndm-5` без build/config provenance таким contract не является.

На upstream v4.9 `nfnetlink_rcv_msg` выдаёт EINVAL при missing subsystem,
missing callback, invalid attribute parsing или отсутствии callable handler.
Правильно сформированный GETTABLE+DUMP без attrs проходит dump handler,
но errno alone не сообщает, какая dispatcher ветка выполнена. Два EINVAL
для exact GETTABLE и GETGEN усиливают diagnostic, но не устраняют vendor
ABI/config неизвестность. EPERM означает CAP_NET_ADMIN refusal; ENOBUFS,
ENOMEM, EINTR, EIO, EOPNOTSUPP/EINVAL вне reviewed platform contract,
socket protocol errors и любые transport ошибки не означают empty.
[v4.9 nfnetlink dispatcher](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/net/netfilter/nfnetlink.c#L151).

Положительное unsupported evidence может быть matching trusted vendor
build/config с disabled NF_TABLES и удостоверенным runtime build identity;
либо отдельно исследованный kernel interface с однозначным отказом.
В исследованном single-message nfnetlink API универсального однозначного
unsupported discriminator не найдено. До дополнительного evidence
предложенный reader честно возвращает unsupported-candidate, без skip.
NFQUEUE availability этого evidence не заменяет: NF_TABLES — отдельный
tristate с собственной конфигурацией.
[Kernel configuration](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/net/netfilter/Kconfig).

## Почему не batch probe и не absolute no-side-effects claim

Batch dispatcher даёт EOPNOTSUPP для отсутствующего subsystem, но successful
empty nft batch вызывает commit: меняются base_seq и generation cursor.
Поэтому BATCH_BEGIN/END, NEW/DELETE/FLUSH/RESET и любые тестовые правила в
readback исключены. Чтение не должно менять состояние ради диагностики.
[Generation-changing commit](https://github.com/torvalds/linux/blob/69973b830859bc6529a7a0468ba0d80ee5117826/net/netfilter/nf_tables_api.c#L4047).

Даже обычный GET на upstream4.9 может вызвать kernel request_module при
missing subsystem. Reader сам modprobe/insmod не вызывает, но обещать
полное отсутствие kernel module autoload нельзя. Нельзя глобально менять
module policy ради теста. ROOT отдельно определяет допустимость фактического
probe на review VM/router; socket/GET — только чтение ruleset, не второй
network owner. Multicast membership тоже не даёт отсутствия subsystem.

## Handoff / следующие проверяемые шаги

1. ROOT readonly сверяет actual router hashes executable+backend libraries
   с evidence pins и trusted loader environment, проверяет security inventory.
2. RESEARCH независимо проверяет unsupported classification. При отсутствии
   positive evidence нужен vendor build/config provenance, а не errno skip.
3. После согласования ABI реализуется private reader + decoder regressions;
   current predicate до этого не ослабляется. ROOT native proof: supported
   empty, present foreign table, permission error, interrupted/malformed
   decoder fixtures, exact vendor unsupported evidence если доступно.
4. Finished reader используется в existing AdditionalReadback по обе стороны
   whole xtables inventory. Common Execution lifecycle/child Start ABI и
   shared settlement остаются отдельными незавершёнными prerequisites.

Локальная проверка этой поставки: только source/feed/archive data inspection,
JSON validation и diff whitespace. Native/kernel/router/race тестов локально
не было; Go product code не менялся. Ignored inspection bytes сохраняются в
`.hil/nfqws/entware-nft-packaging/`; authoritative pins включены в tracked JSON.
