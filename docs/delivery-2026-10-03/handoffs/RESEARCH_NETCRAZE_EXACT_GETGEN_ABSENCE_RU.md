# Netcraze: exact GETGEN и отсутствие зарегистрированного NFT backend — 07.10.2026

**Finished source verdict:** для отдельно принятого NFNETLINK/NFT GETGEN ABI vendor pin `7b6c9477d429217042117fbfa3d2e9894a087607` корректный exact GETGEN без attributes и подтверждённый kernel error ACK `-EINVAL` позволяют установить отсутствие зарегистрированного NFNL_SUBSYS_NFTABLES на момент lookup после попытки autoload. Это предложение узкого observer contract, не изменение current generic error classifier и не production/backend PASS.

База research `d60933a05d21045bc685f3a5f658f899a4f59bed`. Документ сохраняет уже законченный source report по поручению Root; дополнительного исследования здесь нет. Production, helper, зависимости и другие worktrees не менялись; router/kernel/module actions и probes не выполнялись.

## Отдельное принятие ABI

Ранее принятый Root [namespace contract](C:/Projects/RAZVILKA/worktrees/sol-research/docs/delivery-2026-10-03/handoffs/RESEARCH_NETCRAZE_SINGLE_NETNS_CONTRACT_RU.md) касается proc namespace directory и single init-net. **Он автоматически не принимает NFNETLINK dispatcher, NFT callback table, netlink reply path или специальный errno predicate.**

Для нового пути Root должен явно принять stock NC-1812 exact-release profile с семантикой перечисленных ниже частей того же vendor kernel pin: стандартный NF_TABLES provider для subsystem ID10; GETGEN callback присутствует при регистрации provider; valid-wire dispatch и unicast ведут себя как в source. Это maintainer-level vendor ABI assumption для конкретного deployment, не независимая attestation running kernel. Известная release tuple: NC-1812/aarch64, `5.01.C.6.0-1`, title `5.1.6`, ndm `exact: 0-996b1e0`, kernel `4.9-ndm-5`. Одного uname для выбора profile недостаточно.

## Закрытая цепочка errno в pin

| Участок | Source evidence | Вывод для точного запроса |
|---|---|---|
| Тип и размер | [NFNL_SUBSYS_NFTABLES=10](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/include/uapi/linux/netfilter/nfnetlink.h#L60), [GETGEN enum](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/include/uapi/linux/netfilter/nf_tables.h#L89), [dispatcher](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/nfnetlink.c#L151) | Один nlmsghdr16 + nfgenmsg4, type NFTABLES/GETGEN: valid subsystem и callback ID, attrlen0 |
| Capability gate | [nfnetlink_rcv:450](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/nfnetlink.c#L450) | Недостаточный CAP_NET_ADMIN даёт EPERM, а не EINVAL. UID0 сам по себе не является capability proof |
| Registry/client | [lookup/autoload:151–215](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/nfnetlink.c#L151), [GETGEN callback:4015](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/nf_tables_api.c#L4015), [subsystem descriptor:4295](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/nf_tables_api.c#L4295) | При стандартном зарегистрированном provider callback найден и `.call` не NULL. Иначе generic dispatcher мог бы дать такой же EINVAL |
| Attributes | [nla_parse:182](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/lib/nlattr.c#L182) | Пустой attribute region не вызывает parser error |
| GETGEN callback | [fill_gen_info:3858](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/nf_tables_api.c#L3858), [getgen:3917](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/nf_tables_api.c#L3917) | Выделение skb: ENOMEM; заполнение: EMSGSIZE; далее unicast. Здесь нет EINVAL |
| Reply unicast | [nlmsg_unicast:589](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/include/net/netlink.h#L589), [destination lookup:1131](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netlink/af_netlink.c#L1131), [attach/send/unicast:1202–1343](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netlink/af_netlink.c#L1202) | В этом пути нет EINVAL; missing/mismatched destination даёт ECONNREFUSED, congested nonblocking delivery — EAGAIN; successful delivery/filter drop возвращают неотрицательный результат |
| Error ACK | [netlink_rcv_skb:2374](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netlink/af_netlink.c#L2374) | Callback errno передаётся в kernel NLMSG_ERROR. Collector проверяет именно этот ответ, а не syscall errno |

При всех этих preconditions оставшаяся ветка `-EINVAL` — NULL subsystem после повторного lookup в dispatcher. Registration race может дать replay; вывод относится к lookup, фактически завершившему запрос. Исходники не говорят, что subsystem никогда не появится позже.

## Минимальный collector contract для review

1. Только явно accepted NFNETLINK/NFT profile. Свежий socket NETLINK_NETFILTER в принятом network scope; собственный проверенный port ID; без multicast subscriptions, socket filters и CAP_ACK сокращения error echo. Boot/scope identity и existing trust/ownership guards сохраняются.
2. Единственное 20-byte сообщение: `nlmsg_len=20`, type `(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_GETGEN`, flags ровно REQUEST|ACK, свежий sequence, свой port ID; nfgen family AF_UNSPEC, version0, res_id0. Нет attributes, DUMP, batch или других messages в datagram. Не использовать GETTABLE без DUMP как substitute: у него другие lookup errors.
3. Bounded complete receive/decoder: sender sockaddr port0/groups0, совпадающий sequence, корректные framing/length/alignment и error body; для negative branch — полный byte-exact echo исходного 20-byte запроса. Не путать header pid с authenticated sender port. Truncation, overrun, ambiguous/mixed replies, неверный echo, timeout и транспортные ошибки дают Unknown. Точный предел datagrams/bytes/deadline назначает reviewed existing observer; userspace watchdog не объявляется hard kernel cancellation proof.
4. **Negative branch:** только authentic matching NLMSG_ERROR `-EINVAL`, без противоречащего normal GEN response, → typed `NoRegisteredNFTSubsystemAtCapture`. **Normal branch:** valid NEWGEN с полным NFTA_GEN_ID32 и нормальным завершением REQUEST|ACK → backend доступен; далее existing all-family GETTABLE dump/generation contract. ACK0 без GEN, другие errno или syscall EINVAL не означают отсутствие.
5. Snapshot сообщает current registration observation, а не CONFIG_NF_TABLES=n, permanently Unsupported или future absence. Fresh checks на existing boundaries и принятые writer/provider assumptions обязательны; две отрицательные пробы не удостоверяют отсутствие registration ABA между ними. Backend completeness consumer и source owner отдельно рассматривают этот typed result. Generic raw-EINVAL→Unknown вне exact profile сохраняется.

## Autoload и граница разрешённого испытания

[Dispatcher:169](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/nfnetlink.c#L169) вызывает `request_module` при отсутствующем subsystem; socket/protocol availability также нельзя обещать как отсутствие autoload. GET-only означает отсутствие NFT mutation requests, **не zero-write/no-effects claim**: loader/module init могут иметь эффекты. Deadline/cancellation observer сами не доказывают прекращение или settlement autoload.

Root отдельно рассматривает допустимость limited probe в ранее авторизованном router-test окне. Этот документ ничего не запускает и не выдаёт такое разрешение. Повторный human permission flow исследователем не предлагается. Если будущая проверка обязана исключить autoload, данный GETGEN путь неприменим; нужен отдельно accepted build/symbol-coverage absence input, а не замена запроса dummy batch.

## Почему kallsyms не выбран самостоятельным grant

В [scripts/kallsyms:241](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/scripts/kallsyms.c#L241) обычный режим сохраняет text/inittext; KALLSYMS_ALL для function names не требуется. [link-vmlinux:207](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/scripts/link-vmlinux.sh#L207) передаёт nm output генератору; [kallsyms s_show](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/kernel/kallsyms.c#L600) выводит names независимо от маскирования addresses. Адреса для такой диагностики не нужны.

Но полное EOF чтение удостоверяет только перечисленные symbol records. Отсутствие `nf_tables_getgen` требует принятой связи build/retained function names с обязательным live code; точное совпадение bare name не покрывает compiler suffixes/CFI или stripped module-local symbols. [Module symtab retention](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/kernel/module.c#L2580) и [module enumeration](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/kernel/module.c#L4026) не превращают missing symbol name в registry read. [Полный proc/modules](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/kernel/module.c#L4161) и [standard nf_tables module composition](https://github.com/keenetic/kernel-49/blob/7b6c9477d429217042117fbfa3d2e9894a087607/net/netfilter/Makefile#L82) полезны для loaded-provider coverage, но не исключают builtin backend без text-name coverage contract. Presence функции тоже не доказывает успешную registration. Сам subsystem registry pointer через этот интерфейс не читается; KALLSYMS_ALL не предполагается доступным.

## Минимальные counterexamples / тестовые границы

- Registered provider с другой/старой callback table, где GETGEN отсутствует: тот же EINVAL, но backend присутствует. Без нового exact NF ABI profile → Unknown.
- Syscall EINVAL, malformed/multi-message request, другой type/seq/echo или чужой peer: не kernel absence evidence.
- Callback success/ACK0 при dropped/missing GEN: не отсутствие; failed/incomplete normal branch остаётся Unknown.
- Module/backend зарегистрировался после отрицательного ACK либо появился и исчез между checks: snapshot не становится future/atomic absence proof.
- Missing bare symbol, пустой/частичный kallsyms corpus или отсутствие nft CLI: не заменяют этот contract и не доказывают CONFIG_NF_TABLES=n.

Finished recommendation: один exact GETGEN observer после отдельного NF ABI и autoload review. Иные live paths не предлагаются. Документ проверен `git diff --check`; runtime/native assertions этого пути ещё не испытаны. Registered classic coverage, NFT normal dump completeness, storage и production admission остаются прежними отдельными условиями.
