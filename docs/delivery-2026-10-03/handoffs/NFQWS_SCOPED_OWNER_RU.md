# NFQWS scoped kernel owner / common receipt

## Назначение и границы

Эта порция реализует compiler, actual readback и receipt binding в назначенных
NFQWS новых `nfqws_scoped_owner.go`, `nfqws_scoped_readback.go` и собственных tests.
Процессная зависимость — принятый ROOT `ec275f69401adac1665a9864579c4a5586912e2d`:
существующий managed session в `runtime/nfqws2/ownership.json`, exact helper/child
birth/exe/argv, terminal ECHILD + parent ACK. ROOT подтвердил source52 native RC0
для семи механизмов и pinned genuine процесса. Это не прежний stock init путь.

Kernel effects используют **существующий** schema2 mixed `PolicyEffectPlan` и
`policy-additions-v1.json` в childroot общего Execution. Нового журнала, queue
picker, scheduler, daemon takeover, чтения argv из receipt как authority нет.
Manager/Execution registrar и durable typed record принадлежат DEFAULT;
app/operationgate/main wiring — CORE. Эти shared файлы здесь не изменены.
Production capability остаётся закрыта до готового общего wiring и ROOT native
проверки. Legacy `NFQWS2Adapter.VerifyRuntimeInactive` пока не получает право
считать весь adapter inactive по этой библиотеке автоматически.

## Согласованный typed compiler ABI

`CompileNFQWSScopedPlan(expected Plan, spec NFQWSScopedSpec) (*NFQWSScopedPlan,error)`.

Spec: фиксированные `Queue uint16`, `BootID`, `NetNamespace` (`net:[decimal]`),
`SessionID` (32 lowercase hex), `CommandSHA256`, `Candidate`.
Candidate: `ID`, `Incarnation` (32 lowercase hex), `ArgumentsSHA256` реального
executable argv0 + args, `Traffic []NFQWSScopedTraffic{Protocol,First,Last}`.
Traffic — bounded непересекающиеся TCP/UDP destination-port intervals.
Spec не содержит root, executable path, arbitrary argv, cleanup boolean.

Opaque plan предоставляет detached `Spec()`, `Resources()`, `Effects()` и
`Digest()`. Resources: PlanID/PlanDigest/Revision/NetworkProfileID,
Generation/LANDigest, BootID/NetNamespace/Queue, SessionID/CommandSHA256,
CandidateID/Incarnation/ArgumentsHash, exact compiled Chains. Для recovery общий
typed record сохраняет exact expected Plan + detached Spec, повторяет compiler
и сверяет generation/effects digest/header. Persisted effects — сравнение,
никогда execution source. Caller mutations через getter не меняют owner.

Compiler требует frozen validated LAN, exact route ingress из LAN,
source-prefix containment и то же NetworkPolicyGeneration. Каждая capture rule
имеет physical `-i`, source, public destination CIDR, `LANPolicyMatch()` и
reviewed TCP/UDP interval. Нет `raw`, `OUTPUT`, queue-bypass, динамического выбора
очереди или захвата private/local destinations. Домены без executable flow
binding отказывают; DNS-observed IP не превращается в domain authority.
Bounds проверяются до копирования nested input/JSON, также действуют общие
limits mixed receipt. Цепочки обеих необходимых family готовятся до jumps;
attachments в **mangle FORWARD**, после общего mangle PREROUTING LAN gate.
Reverse Needs удаляет attachments раньше body и chain.

## Binding и общий owner lifetime

`NFQWSScopedBinding` получает trusted Runner/Tools, ApplyGuard/CleanupGuard,
VerifyLAN, ProcessRunning/ProcessInactive, QueueCheck, AdditionalReadback.
Runner обязан потреблять **actual common scoped admission в Cmd.Start**.
Callback/typed DTO сам по себе это право не выдаёт. CleanupGuard отдельный,
точный receipt-owned, доступен после Stop/revocation; ApplyGuard при этом закрыт.

DEFAULT register сохраняет spec/generation/digest BEFORE первого effect в том
же Execution и удерживает queue/chains/LAN dependency до independent closure.
Root передаётся только из registrar; compiler не принимает receipt path в Spec.
Settlement выполняется исключительно после removed closure, не по RC cleanup.

- `CheckBeforeProcessStart`: current guard, LAN, пустой queue namespace и zero
  capture до child Start; Start отдельно потребляет common authority.
- `VerifyPrepared(ctx,plan,root)`: exact running session + own actual queue,
  current LAN + guard, zero capture/foreign references в обоих family, absent
  receipt **и lock** в fresh protected root; read-only, не требует Complete.
- `Apply`: common mixed receipt, process/queue/LAN/current guard перед каждым
  effect, exact complete kernel после. Любой lost actual add ACK сохраняет
  unknown generation и запрещает replay/retirement.
- `Remove`: known terminal ECHILD + ACK и fresh absence до мутации, отдельный
  cleanup guard, только durable mixed receipt grants; unknown сохраняет guards.
- `VerifyInactive`: exact Removed/non-Unknown/non-Promoted receipt + independent
  terminal session + fresh helper/child absence, zero queue namespace и zero
  own/foreign queue attachments/references в обоих family; повторный receipt и
  cleanup guard. Observer открывает **только существующий** common lock marker:
  missing lock/file не создаются и не заменяются.

`ReadNFQWSScopedManagedProcess(ctx,adapter,plan,inactive)` связывает настоящую
existing session с spec, boot, exact command/argv hashes и единственным
`--qnum=<reserved>`. Возвращаемый `NFQWSScopedProcessProof` — metadata:
SessionID/CommandSHA256, Receipt, Child, Acknowledged. Ни PID file, ни init status,
ни отсутствие /proc само по себе не дают proof.

Для LAN.ConsumerCheck при удерживаемом NFQWS receipt writer есть
`CheckKnownReferences`: retained exact typed registrar ApplyGuard + свежий
process/queue + exact allowed partial bodies/references; без рекурсивного
LAN.Verify и повторного acquisition собственного receipt lock. Это не adoption
matching kernel и не Complete receipt. Full prepared/removed closures отдельны.

## Actual readback

Оба family и raw/mangle/nat/filter/security читаются bounded `iptables -S`.
Missing table/capability, unknown syntax, duplicate effect, wrong mask/iif,
partial required family, чужая RZQ chain/reference или любой foreign QUEUE /
NFQUEUE (в том числе другой qnum, queue range) отказывают. Canonical -S order,
numeric marks и host /32 /128 нормализуются только в compiler vocabulary.

`CheckNFQWSScopedQueue` читает Linux `/proc/net/netfilter/nfnetlink_queue` и
`/proc/net/netlink`: **peer_portid не PID**. Он связывает NETLINK_NETFILTER
port с socket inode и exact recorded child open fd, требует COPY_PACKET, свежие
netns/birth/exe/argv и повторное чтение port/queue/process. Nil child требует
пустой entire namespace; missing/permission errors никогда не означают empty.
При missing `/proc/net/netfilter/nfnetlink_queue` возвращается отдельный
`ErrNFQWSScopedQueueInventory`: caller показывает необходимость установить или
загрузить `nfnetlink_queue` для данного ядра и повторить preflight. Owner сам
модуль не загружает; classification не ослабляет отказ и не создаёт authority.
[Kernel queue proc producer](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nfnetlink_queue.c#L1619)
и [netlink proc producer](https://github.com/torvalds/linux/blob/v6.12/net/netlink/af_netlink.c#L2525).

Concrete `CheckNFQWSScopedOtherBackends` подтверждает legacy tools и bounded
strict whole `nft -j list ruleset` всех families (включая bridge). Nft projection
через iptables не принимается за whole readback. Для этой legacy binding **любой
active nft rule или flowtable** отказывает: executable nft expression owner не
реализован, поиск только известных queue/mark spellings не даёт whole proof.
Отсутствующий nft reader тоже explicit refusal.
Эта консервативная baseline требует подтверждённых tools; неизвестную firmware
или offload совместимость нельзя вывести из успешного parser/model test.

## Проверки и ROOT launcher

Локально ordinary Windows dataplane full suite и vet RC0. Новые compiler,
receipt lifecycle, lost add/delete ACK, revoked Apply vs cleanup, readonly
prepared/missing-marker, foreign IPv6/security range, portID/inode, two-sided
child change, canonical -S и immutable recovery spec regressions RC0. Linux
amd64/arm64 native test compilation и Linux vet; shell syntax check выполнены
без native/race/queue/network execution на локальном Windows.

ROOT-only запуск в exclusive Linux VM:

```sh
RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW=/protected/root-owned/review.json \
  sh scripts/test-nfqws-scoped-kernel-native.sh
```

Тот же explicit pinned review ABI, что process native harness: BinaryPath,
BinarySHA256, Assets[{Path,SHA256}], ordered BaseArguments (только lua-init/blob).
Launcher ничего не загружает; требует ip, iptables-legacy, ip6tables-legacy,
nft, unshare, nsenter и root. Private artifacts сохраняются. Test отказывает в
неизолированном или непустом netns. Создаёт только private veth peer netns и
dummy egress, включает forwarding только внутри disposable netns. Настоящий
reviewed NFQWS запускается foreground через existing exact helper на 15s bound.

Oracle: actual socket ownership; wrong birth refusal; Complete mixed kernel
receipt; selected IPv4/IPv6 packet counters increase; excluded MAC с новыми
IPv4/IPv6 адресами не увеличивает NFQUEUE counters; cancellation joins exact
ECHILD/ACK; own receipt removal; foreign IPv6 same queue refusal без изменения
receipt; fresh removed closure; LAN gate удаляется последним. Private foreign
rule снимается только test fixture, который её создал, не NFQWS owner.
Этот isolated harness **не доказывает** pending sharedExecution admission,
OPS generation lease bridge, service health, router/native firmware/offload,
adaptive selection efficacy или production capability.

Первый ROOT `nfqws-kernel59`, integration `b642b73`, **RC1 до Start**: queue
inventory отсутствовал. ROOT проверяет VM module и повторяет запуск; это не
скрытый PASS и не причина заменить missing inventory пустым списком. На этом
этапе actual queue packet PASS ещё не заявлен.
