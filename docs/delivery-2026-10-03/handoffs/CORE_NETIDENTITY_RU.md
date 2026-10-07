# CORE: общий typed network identity provider

07.10.2026. Законченная первая identity-порция по контрактам LAN
`20ba5fef6eaa1740498d7e4fb719143fa333477d` и RESEARCH
`d60933a05d21045bc685f3a5f658f899a4f59bed`. Изменения ограничены новым
`internal/netidentity/*` и этим handoff. Dataplane, backend inventory, NFQ,
node, receipt, main wiring и другие owner WIP не изменены.

## Интерфейс и граница доверия

`Identity{Version, Kind, BootID, Inode, PlatformReviewSHA256}` — comparable
value, version 1. Два несовместимых варианта:

* `ProcNetInode` / `proc-net-inode`: настоящий положительный nsfs inode,
  текущий boot UUID, пустой profile hash.
* `ReviewedSingleInitNet` / `reviewed-single-init-net`: inode строго 0,
  текущий boot UUID и точный hash единственного compiled review-профиля.

`Validate`, `Encode`, `Decode`, `MarshalJSON`, `UnmarshalJSON` проверяют
вариант. `Decode` ограничен 1024 bytes и требует точный canonical JSON всех
пяти полей: unknown/duplicate/missing поля, будущая версия, старый string,
смешанный вариант, неизвестный профиль, лишние bytes и noncanonical JSON
отвергаются. Для strict границы сохранённого значения применять `Decode` к
его полным bytes; внешняя JSON-обёртка сама отвечает за свой формат.

Значение, его декодирование и успешная фабрика **не дают authority**.
Consumer сравнивает ожидаемое значение с новым наблюдением в своей операции;
boot, kind, inode и profile hash входят в полное `==`. Для старых receipts
нет автоматической миграции или permissive fallback.

`NewProcProvider()` допускает только реальный inode. Явный trusted startup
вызов `NewReviewedStockNC1812Provider(ctx)` выбирает единственный reviewed
stock профиль после свежей полной проверки. У `Provider` нет публичных
runner/path/profile/observation hooks; zero value недействителен. DTO,
environment, cached version JSON и наличие/отсутствие ENOENT не выбирают
профиль. Фабрика не подключена к main в этой порции.

`Observe(ctx)` удерживает calling goroutine на OS thread только на время
наблюдения; внешний `runtime.LockOSThread` сохраняется. Рекомендуемый
`WithCurrent(ctx, func(ctx, Identity) error)` удерживает тот же thread на
время синхронной caller-операции и closing observation. При успехе callback
нужны полное равенство closing identity и действующий context. Ошибка
callback возвращается без выдачи успешного результата. Работу в другой
goroutine/thread этот scope не покрывает. Ошибка closing check не отменяет
уже сделанный effect: prepare/rollback, resource ownership и границы effect
остаются у consumer.

Нужен исходный context с deadline; nil, canceled и unbounded context
отвергаются. Его values/cancellation/deadline сохраняются, внутренний максимум
операции — 2 seconds, меньший caller budget не увеличивается. Proc/ELF loops
проверяют cancellation; NDMC использует `CommandContext`, direct process
join и 50 ms `WaitDelay` для pipe shutdown. Положительный результат после
истечения budget невозможен. Это не hard watchdog для заблокированного
kernel/filesystem syscall или произвольного callback. Фонового collector,
daemon, goroutine reader, autoload, сетевой команды или route effect нет.

## Реальный readonly producer

Linux amd64/arm64 reader выделен из procns90 helper SHA256
`53eceab895ac42d28b4d7cc3198a7946cc4fb0b5a8148e1138f546efa9d1295e`:
verified procfs magic/root inode, numeric PID/task/TID anchored nofollow walk,
полный raw dirent scan с fresh position 0 до EOF. DT_UNKNOWN и zero-inode
names сохраняются. В обоих PID/ns и TID/ns нужны одинаковые полные names
с `mnt`; `net` не теряется из-за d_type или d_ino. Task/process start, boot,
uname, mount layout/mnt_id, self links, held FDs и повторное открытие обоих
namespace directories проходят brackets. Positive ветка дополнительно
удерживает и сверяет реальные nsfs net FDs процесса и текущего thread.
Broken net readlink/open никогда не становится singleton.

Пределы: mountinfo 256 KiB, namespace directory 64 KiB / 64 read calls /
64 names; limits/faults/partial reads отзывают всё наблюдение.

Compiled profile — maintainer-accepted **vendor ABI**, не независимая
attestation running `.config`:

* Netcraze Ltd.; Ultra (NC-1812); device Ultra; release `5.01.C.6.0-1`;
  stable; title `5.1.6`; arch aarch64; ndm `exact: 0-996b1e0`;
  firmware version `5.1.C.6.0`; uname `4.9-ndm-5` / aarch64.
* SDK `1d58c10c46e270d6876836e5455fa4e9b786ad1e`, kernel
  `7b6c9477d429217042117fbfa3d2e9894a087607`.
* Profile SHA256
  `7909df2d50793c6847474b778feb906386f4b66244d6e278d00273892f889c75`:
  SHA256(domain `razvilka-network-platform-review-v1` + NUL + compiled
  profile JSON). Portable test pins this value.

Каждое reviewed observation читает actual proc/uname/boot до и после двух
свежих `ndmc -c "show version"` и требует exact unique runtime tuple.
Фиксированный `/bin/ndmc` открывается из protected root-owned non-writable
system paths, исполняется через retained FD. Interpreter и статический
DT_NEEDED closure проверяются в `/lib` / `/usr/lib`; metadata/paths/FD/hash
сверяются до/после. RPATH/RUNPATH/audit/filter/auxiliary и compressed,
extended/ambiguous/out-of-file ELF metadata отвергаются. До debug/elf чтения
проверяются tables/extents; максимум 128 program headers / 256 sections,
32 images / 128 edges, 16 MiB/image / 64 MiB total. Это защита фиксированного
system producer, не attestation всего firmware или динамических dlopen effects.

Environment задан целиком: system PATH, `LD_LIBRARY_PATH=/lib:/usr/lib`,
LANG/LC_ALL=C; shell, inherited env, Entware library path и caller argv не
используются. `/etc/ld.so.preload` должен отсутствовать и его protected parent
не меняться. stdout 8192 bytes, stderr 1024 bytes; любой stderr, overflow,
дубликат/missing tuple field или drift — отказ без вывода raw NDMC data.

## Проверки и следующий owner шаг

Go 1.26.5 Windows portable tests: PASS (0.219 s); Windows vet: PASS.
Linux amd64 и arm64 vet и native test binary crosscompile: PASS / RC0.
Тесты проверяют closed codec/catalog pin, complete-vs-partial/DT_UNKNOWN/
zero-inode directory data, каждый из 15 bracket faults, process/thread names,
profile/build/boot drift, caller budget/cancel, closing identity drift и
bounded ELF metadata/forbidden tags. CORE Linux/router код не исполнял.

Root выполняет native VM opt-in `RAZVILKA_NETIDENTITY_NATIVE=1` с
`TestNativeNetworkIdentityProcThreadAndClosing` и exact stock router opt-in
`RAZVILKA_NETIDENTITY_STOCK_NATIVE=1` с
`TestNativeReviewedStockNC1812FactoryAndScope`. Оба теста readonly;
stock тест использует actual fixed producer, не model hooks. Если system
layout/ELF/CLI/budget отвергает production build, нужен конкретный результат
Root, а не ослабление профиля или cached/ENOENT substitute.

NFQ и NET могут готовить независимые consumer slices по этому API. Inventory,
generation/receipt/process integration и trusted startup registration —
последующие owner commits **после Root review провайдера**. Эта порция не
снимает backend HOLD, не подтверждает table/queue completeness, inactivity,
process ownership, effect admission или linked self-update e2e.

## QA-only диагностика отказа provider96

Root actual source `4d98100`: VM proc/thread/closing PASS (0.02 s, RC0);
exact stock factory FAIL (0.10 s, RC1, stderr empty). Это не принятое
production provider и не разрешение consumer integration.

Отдельная QA-порция добавляет только `qa_*_test.go` и этот раздел. Root opt-in
`RAZVILKA_NETIDENTITY_DIAGNOSTIC=1`, test
`TestNativeReviewedStockSanitizedStages` сначала повторяет **actual factory**.
При отказе выполняет bounded readonly probes в том же locked thread и исходном
2 s context: proc checks, protected image/ELF/dependencies, fixed system NDMC,
tuple и closing brackets. Все production bytes/guards остаются прежними.

Вывод ограничен фиксированными stage labels, booleans и bounded image index;
actual error strings, argv/environment values, NDMC data, paths, hashes,
version/boot/identity не печатаются. Первый отказ даёт `blocked_stage`.
`nobits_over_file` отдельно проверяет существующий source predicate: текущий
ELF preflight отвергает `SHT_NOBITS.sh_size > file size`, хотя NOBITS bytes в
файле отсутствуют ([ELF ABI](https://gabi.xinuos.com/elf/03-sheader.html)).
Это source-level concern, **не установленная причина native отказа**. Portable
регрессия проверяет bounded probe и сохранение текущего production refusal;
исправления ELF acceptance эта QA-порция не содержит.

Повторный actual factory success может завершить диагностический test PASS;
если factory отказал, однокомандный probe не выдаёт admission даже при полном
успехе всех этапов и завершается FAIL. Независимый первоначальный stock тест
остаётся обязательным. CORE native диагностику не исполняет; Root выполняет
следующее router окно. Windows portable tests/vet PASS (0.212 s); Linux amd64
и arm64 vet/test binary crosscompile PASS / RC0.
