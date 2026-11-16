# Проверки панели и сетевого стенда, 16.11.2026

## Обновлённые отказы полной приёмки

[Проверка завершения процессов b07cebf7](inactive-proc-b07cebf7.json),
run43934484415: actual Linux normal/race PASS. В исходном541764f5 живой
рабочий поток при Z-лидере ошибочно проходил проверку отсутствия процесса;
теперь оба наблюдателя отказывают. Проверены exec рабочего потока, настоящий
Z/1 с последующим Wait/исчезновением и пять подмен mount ID при том же inode.
Это исправление корректности; скорости и готовности router/LAN оно не доказывает.

Strategy-pair8ab43927647142: reader compatibility PASS, но общий10мин timeout
пакета прервал седьмой stopped cut после1м54с; восстановленная панель SKIPPED.
ba5ffd02 разделяет семь запусков, сохранив case5мин/helper4мин/job20мин,
проверку каждого точного PASS и отказ при SKIP. Независимое review и проверка
выбора семи сценариев PASS; actual43934930569 ещё выполняется.

Общий push и PR CI8ab8f100 PASS (43927646979/43927655267).
Обычный Mihomo live43927647165: lifecycle, check-settlement, manual-http,
postcas-failure PASS4/4; это не отдельная race ACK матрица ниже.

[VLESS и очередь8ab](probe-comparison-8ab8f100.json), run43927647138 PASS:
на одной машине baseline363f→8ab, N12 повторов, полная медиана live
311.549→220.1895мс; selected1527.3895→1329.274мс; single699.367→600.2145мс.
Dead-node6.6265→6.8415мс стал медленнее. Все182 строки, ожидаемые verdict и
cleanup проверены; first samples отдельно, фиксированный порядок может влиять
на cache/load. Это частная Linux-сеть, не аппаратный LAN или cold boot.

Matched domain image43927646960 на8ab отказал ДО native samples:
fixture drift относительно исторической344912c. Отказ сравнимости сохранён;
из него нельзя вывести скорость или функциональную ошибку DNS. Новый парный
эксперимент готовится из одной текущей ревизии с явным synthetic fallback.

NFQ diagnostic6818: original scope не включён, fallback-wg-inactivity-cleanup37.
Вd67342c8 захвачен исходный comparison carrier при BindExecution; остальные
cleanup exclusions и полный body сохранены. Native43932269168 подтвердил
16 eligible/entered/body-completed/completed, body-error/error0. Сам manual
Apply всё ещё FAIL42.297с включая rollback, NATIVE_OWNER_REFUSED; rollback
verified и независимый failed-Apply Close PASS. Другой host исключает вывод
об ускорении по сравнению абсолютных времён двух прогонов. Raw:
`C:/RAZVILKA-research-20261116/managed-d673-network/`.

[Mihomo race60bd5153](mihomo-parent-race-60bd5153.json), run43926086704:
parent/private и два ACK cuts PASS; completed.json, terminal-transaction и
terminal-global FAIL120с, retirement absence-source-opening. Это не закрытая
race-приёмка; отдельная диагностика HEV её не заменяет.

На8ab8f100, run43927647142, strict DNS selected достиг HTTPS, но запрос не
уложился в4с; GEN2 original cancellation witness не достигнут за12с.
Диагностика с30с отдельно: baseline FAIL68.56с, candidate PASS62.74с,
capture PASS66.93с, standby PASS63.53с. Raw и SHA manifest:
`C:/RAZVILKA-research-20261116/proc-io-production-8ab8f100/`.

NFQWS2 race8ab manual: consumer-open SOURCE_MISSING, Apply24.223с,
rollback-failed/verified=false. Прежний60bd verified cleanup не относится к
этому результату. Raw: `C:/RAZVILKA-research-20261116/managed-8ab-network/race/`.
Разные CI hosts не позволяют приписать новый отказ изменению FD-read.

Identity8ab, run43927541148: все3 jobs PASS, включая actual normal/race
ProcReadRefusals, FDKeepsCallerOwnership, InvalidEntryDoesNotRead, offline retry
и live TLS. Generic push/PR проверяются отдельно.


Актуальный сводный статус: [единая матрица](../../CURRENT_STATUS_RU.md#current-release-checkpoint).

[Полное чтение proc60bd5153](backend-proc-io-60bd5153.json), run43925928845 PASS:
8 чередующихся пар по64 чтения на вариант, включая opens/closing/closes.
Normal медиана0.217571→0.190196мс (-12.58%), race0.134316→0.110744мс
(-17.55%). Сравнение только внутри режима: normal/race на разных host.
Отдельный strace подтвердил17 fcntl и17 epoll_ctl →0 при прежних22 openat,
29 fstat и29 fstatfs. Production в измеренной ревизии не изменён;
это не ускорение полного DNS/NFQ Apply и не аппаратная приёмка.

[Повтор с production8ab8f100](proc-io-production-8ab8f100.json), run43927533589
PASS: normal0.079705→0.076085мс (-4.54%; две из восьми пар медленнее),
race0.350742→0.284820мс (-18.79%; все восемь пар быстрее). Каждый режим
сравнивается только со своим baseline на том же host. Проценты не являются
постоянным коэффициентом ускорения. Исходный trace содержит устаревшую подпись
«production не изменён»; erratum сохранён в JSON, сами данные не переписаны.

- [Mihomo ABBA42b83032](mihomo-self-image-42b83032.json): одна пара исходников,
  8 запусков на одном host; normal +11.34% времени, race two-SHA проходит
  исходные120с, исходный image — два timeout. Это не полный recovery PASS.
- [Exact parent dc5829fd](mihomo-parent-dc5829fd.json): race PASS, normal
  final absence FAIL, ACK matrix SKIPPED; отдельная HEV диагностика не причина
  отказа parent с исправленным ELF.
- [Managed NFQ66f00639](managed-66f00639.json): fullLAN/manual/race не приняты;
  исходные deadlines и проверенное освобождение после отказа сохранены.
- [DNS Lookup b31ff873](nodestore-profile-b31ff873.json): профиль не подтверждает
  JSON/SHA как основную стоимость Lookup; следующая проверяемая гипотеза —
  лишние операции вокруг чтения уже проверенных системных файлов.

[Повтор HEV2df338cb](hev-source-2df338cb.json): обе Ubuntu,64 samples PASS;
исправлен строгий reader provenance manifest, ELF неизменён.
[Normal parent +5ACK e2fb7b88](mihomo-parent-e2fb7b88.json): PASS,
прежний intermittent dc5829fd не объявляется устранённым.

[HEV374bbd46](hev-replacement-374bbd46.json): exact original HTTP
old→patched, отказ при живых old/desired ELF, отмена, crash и rollback;
Linux normal/race PASS, run43916940407. HTTP fixture1.12/1.97с — не время
полного LAN-маршрута. [Хеши12 исходных файлов доказательств](hev-replacement-374bbd46-files.json).
Default pin не изменён, vendor asset не опубликован.


## Последующая контрольная точка `fc5bcc6c`

[Точные результаты и исходные числовые строки](release-fc5bcc6c.json).
`c92fd75a`, run43899528342: все12 защитных тестов Linux и16 реальных
восстановлений (8 архивов +8 local Git) PASS. Использованы исходные gzip bytes
из отдельного data-only commit `318ac9c7`; main, теги и выпуски не менялись.
Предыдущий run43896413328 честно отказал на gzip, заново сжатом другим zlib;
это не основание менять pins. HTTP-доставка будущего compatibility release ещё
не проверена: assets пока не опубликованы.

`9da19ea6`, run43896414773: identity/historical reader4/normal+race PASS.
В узком self-image замере normal warm pair ~51.4→34.4мс, race ~95.8→237.2мс.
Это разные бинарники:39,715,081 и57,372,937байт соответственно; сравнивать
normal с race как одинаковую нагрузку нельзя. В race release/clear ~0.7–1мс;
основные затраты — opening130мс и closing104–108мс. Ускорения полного маршрута
нет: `94e85625` race ACK completed.json всё ещё FAIL120с. Следующий `a84f3c15`
остановился раньше: HEV exit254/signal0/пустой вывод. Старт HEV исследуется
отдельно, без трассировки acceptance-процесса и изменения его ancestry.

`458b20ef`: standalone baseline.Current теперь использует существующее
наблюдение исходных файлов с полными closing checks до следующего эффекта.
Локальные association/context/fallback тесты PASS; независимое ревью PASS.
Actual strict DNS run43899676997 выполняется; пока не PASS.
Общий CI `94e85625` run43892266549 PASS. Более новые CI оцениваются отдельно.
Router-ready=false, пересоздание GitHub не выполнено.

Воспроизведение: `identity-contract-regression.yml` для стадий self-image;
`tool-observation-image.yml` для реального графа утилит;
`compatibility-sources.yml`, input `assets_ref=318ac9c7902fb1d7f55acc047d2c72dfcdf98f76`;
`hev-startup-diagnostic.yml` — отдельные фиксированные8+8 запусков.

## Контрольная точка `492e813b`

[Машиночитаемые результаты](release-492e813b.json): identity regression,
публичное восстановление истории и modern rollback PASS; strict DNS FAIL.
Generic CI43889164918 завершился PASS. Router-ready=false.
На последующей `c972ab26` локально исполнена настоящая reader4 библиотека
`4cc9f869`: receipt4 принят, реальный bound pending5 отклонён, точный terminal4
снова принят;0.52с. Linux normal0.14с/race0.13с и полный identity run43891102721 PASS. Архивная проверка в этом тесте моделируется явно.

Профиль `4e83e678`, race/completed.json:120.01с elapsed,107.01с sampled CPU;
SHA33.31с flat, syscall26.08с flat. В cold-file hashing22.73с cumulative,
из них19.90с SHA. Это основание для проверяемой оптимизации self-image closing,
но не доказанное ускорение после изменения. Overlapping cumulative не суммируются.

```sh
go tool pprof -top -nodecount=25 sameboot-consumer.test sameboot-consumer.cpu.pprof
go tool pprof -top -cum -nodecount=35 sameboot-consumer.test sameboot-consumer.cpu.pprof
```

Отдельная диагностическая ABBA серия пустого race child,3 блока,6 измерений
на вариант: медианы1067.050342мс original и64.0199825мс exit-sleep-zero.
Она измеряет только завершение процесса без тестов; исходный acceptance GORACE
не меняется. В настоящем NFQWS2 Consumer вариантzero всё ещё FAIL15.8845с
при14с; LateWaitCleanup PASS22.36с. Ускорение service/LAN не заявляется.
Команда воспроизведения — workflow `mihomo-same-boot-validation.yml` с
`mode=race`, `ack_cut=completed.json`, `consumer_profile=true`; отдельный
`native-race-helper-exit.yml` сохраняет оба результата и исходный отказ.


Исходная панель — `71891f5c`, оформление/навигация — `35947259`, исправление
устаревшего теста уведомлений — `e8954294`. Все 49 served assets совпадают с
[browser report](panel-navigation.json). API/backend admission не расширялся.
Скриншоты и сырые логи сохранены вне production tree:
`C:/RAZVILKA-research-20261110/panel-netzapret/` и
`C:/RAZVILKA-research-20261116/`.

## Панель

Изолированный Chromium, synthetic stopped state, 1440×1000 и 390×844:
13 основных пунктов, 21 сохранённая страница, 28 переходов, подменю,
Tab/Escape/возврат фокуса, отсутствие горизонтального overflow. Нет API mutations,
обращений к роутеру или внешней сети; missing APIs отвечают503. Независимый
source review проверил сохранение предупреждений, черновиков и recovery guards.

```powershell
$env:NODE_PATH='<bundled runtime>/dependencies/node/node_modules'
$env:RAZVILKA_UI_CHROME='C:/Program Files/Google/Chrome/Application/chrome.exe'
$env:RAZVILKA_UI_ARTIFACTS='<external artifact folder>'
node scripts/test-panel-navigation-browser.mjs
```

[Node review](ui-node-review.json), точный source `e8954294`: 118 PASS из121
команды `check.sh`, включая6 shell-fixtures в Git Bash/MSYS. Один platform FAIL:
component-update-supervision требует отсутствующий `/opt`; два explicit Linux
rollback-reader запуска не выполнялись. Это не результат полного Linux gate.
CI `147d8885` прошёл Go normal/race, затем FAIL на старом CSS assertion;
исправление входит в `e8954294`; оба Linux CI этой ревизии PASS:
[push](https://github.com/ArtixSx/RAZVILKA/actions/runs/43860680896),
[PR](https://github.com/ArtixSx/RAZVILKA/actions/runs/43860691276).

## Сопоставимые проверки соединений

Run [43856995070](https://github.com/ArtixSx/RAZVILKA/actions/runs/43856995070),
baseline `363f433611620cda4d14db2d0a7ae2475b0278f1`, candidate
`147d8885ac97ea402dc3ca6b25ce829f8329afcb`: PASS182 paired rows, outcome и cleanup
parity. Полные агрегаты, SHA256 raw и provenance: [JSON](probes-147d8885.json).
Это повторная проверка прежнего изменения cleanup, не эффект оформления.

| Сценарий | N повторов на версию | p50 до→после, мс | p95 до→после, мс |
| --- | ---: | ---: | ---: |
| Live node/service |12|311.632→223.534|316.201→251.152|
| Dead service |12|310.886→223.711|311.696→225.721|
| Cancel |12|268.962→183.150|270.678→184.395|
| Dead node |12|7.670→7.842|7.997→8.340|
| Очередь single |12|651.5→565.5|666→580|
| Очередь selected2 |12|1440→1267.5|1462→1289|
| Очередь all VLESS |12|1457→1276|1509→1313|

p50 — median, p95 — nearest rank. Один runner, фиксированный порядок
baseline→candidate, Xray26.3.27 с pinned SHA, модель сервиса40мс и очереди25мс.
Первый sample отделён: live317.877→224.757мс; это не cold page-cache.
Медианы overlapping стадий live: config17→18, start1→1, ready11→10,
protocol64→65, egress64→65, service104.5→104, cleanup100.5→11мс.
Стадии нельзя складывать. Queue измеряет enqueue→server completion,
не browser paint. WAN, фактический LAN route-ready и роутер здесь не измерены.

## DNS: отрицательный эксперимент

Run [43858117782](https://github.com/ArtixSx/RAZVILKA/actions/runs/43858117782),
`655e63d6`: selected и canceled-ready, внутри каждого сценария один runner,
profiler on/off/off/on. Все8 samples FAIL, ускорение и готовность не доказаны.
Два samples на режим недостаточны для устойчивого p95. Разные CPU между
сценариями не сравниваются как причинный эффект.

Capture mean selected on5.5151/off5.5724с; canceled on6.8190/off6.6634с.
Off не создаёт CPU profiles. Initial kernel256–320мс; mapping compare и
publication-open не достигнуты. [Полный разбор](dns-profiler-655e63d6.json).
На `3c5f2d11` исходный deferred join раскрыл forwarding contract refusal.
На `e37fbc67` [43860362402](https://github.com/ArtixSx/RAZVILKA/actions/runs/43860362402)
уточнён отказ programs/BPF при успешных proc/network/qdisc checks.
Отказ не подменён timeout и не снят. Native-only instrumentation сохраняет
исходные чтения, short-circuit, ошибки и бюджеты12/4с.

`61cbf147`, [43861157202](https://github.com/ArtixSx/RAZVILKA/actions/runs/43861157202):
исходный BPF query вернул `attach=18` (INET4_BIND), `program_count=1`,
`attach_flags=0`, `errno=0`. Это реальная эффективная программа cgroup CI-host;
чистый netns не отменяет её наследование. Проверка отсутствия таких программ
сохранена. Для положительной приёмки нужен изолированный Linux runner/VM с
cgroup v2, доказанной общей membership процесса/потока и нулевым effective
program count для всех12 уже проверяемых attach types. Права fixture на
net/mount namespace, veth, legacy iptables и sysctl нужны внутри стенда.
Нельзя снимать чужую BPF policy с действующего хоста ради зелёного теста.
Проверен уже доступный стандартный `ubuntu-24.04`:
`eacafc39`, run43862791267, kernel7.0.0-1017-azure. BPF guard проходит дважды,
ни одной refused метки. Поэтому дополнительная VM не является текущим внешним
блокером и действия владельца для этого теста пока не нужны. Сценарий всё ещё
FAIL: в12с preparation не завершена, публикации нет. Completion таймера mapping
после отмены не означает успешный compare; итоговый fresh-identity/cancel error
нельзя объявлять доказательством самостоятельного drift до отмены.

Отдельно исправлена ошибка памяти `6db973e2`: backing storage `bpf_attr.query`
увеличен с32 до64байт, extension fields нулевые. Kernel записывает revision
в bytes56–63 даже при count-only запросе; размер входных данных не ограничивает
эту запись. Добавлена проверка ABI offsets/size, независимое ревью подтвердило
32-bit layout и неизменность errno/count/flags guards. Это не обход host policy.
Закреплённые первичные источники Linux v7.0 `028ef9c96e96197026887c0f092424679298aae8`:
[UAPI](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/include/uapi/linux/bpf.h#L1724),
[output](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/bpf/cgroup.c#L1254),
[input dispatcher](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/bpf/syscall.c#L6210).
Лицензии GPL-2.0-only и UAPI GPL-2.0 WITH Linux-syscall-note; исходный код Linux
не копировался, воспроизведён ABI layout. Pins/hashes: [source record](linux-bpf-source.json).

```powershell
gh workflow run domain-profiler-comparison.yml --ref <exact-ref> -f plan=abba
gh workflow run domain-profiler-comparison.yml --ref <exact-ref> -f plan=single-selected-off
```

## Другие native сценарии

`147d8885`: Mihomo4/4 PASS
([43856995188](https://github.com/ArtixSx/RAZVILKA/actions/runs/43856995188)).
Strategy pair, legacy public empty/draft/history, pinned iptables1.8.11
normal/race PASS; strict DNS, diagnostic30 и managed NFQWS2 normal/race FAIL
([43856995054](https://github.com/ArtixSx/RAZVILKA/actions/runs/43856995054)).
NFQ physical WAN bridge/route/FDB/ARP ownership drift PASS отдельно от fullLAN
и manual failures. Ни один результат не объявляет готовность router/LAN.

Modern fixture исправлен: настоящий source `-migrate-config` перед запуском,
регрессия исходного fingerprint guard PASS; допустимое отсутствие false
`stopped` принято по существующему JSON omitempty контракту. Production update
guards неизменны. Полный public rollback46855c1a завершился FAIL1234.07с в run
[43857560034](https://github.com/ArtixSx/RAZVILKA/actions/runs/43857560034).
Source migration PASS, preparation/public Apply пройдены, receipt command-started,
candidate live не наблюдался. Это ещё не восстановление работающей панели.
На824b3651 добавлены только bounded diagnostics с закрытыми stage/code labels
и ранний FAIL при уже опубликованном terminal requires-review и исчезнувшем
точном helper. Прежний cleanup сохраняется. Следующий run43861837523 проверяет
причину отказа, без ослабления production guards. Он FAIL40.12с: первые две
команды reaped/exit0/ECHILD, quiesce reaped/exit3. Наffa33828/run43862659350
прочитан существующий закрытый producer category `authority-opening`.
RuntimeQuiesceAuthority отвергал schema3 после её успешной проверки
privateSnapshot. Согласование поддержанных2/3 в565221ca прошло независимое ревью;
[targeted normal/race regression62b](update-admission-62b53867.json) PASS.

## Повторный разбор mountinfo

`8baead92`, [43862363991](https://github.com/ArtixSx/RAZVILKA/actions/runs/43862363991):
netidentity normal/race, ABI normal/race, capacity fixture source parity PASS.
После успешного первого parser и полного равенства двух независимых свежих
буферов второй чистый parser удалён. Никакие чтения, metadata, EOF/size,
process/thread/network identity или closing guards не удалены.

Пять повторов,257 синтетических mount rows, один бинарник и машина, фиксированный
before→after порядок. Median valid_equal:74610→36940ns/op,
127296→63648B/op,518→259allocs/op. Invalid_equal:36808→37220ns/op;
changed_valid:36784→36757ns/op — отрицательные случаи не ускорились существенно.
Это вычисление parser/equality, не весь capture/Apply/LAN.
[Samples и raw hashes](identity-8baead92.json).

## Закрытый modern сценарий

[43864979694](https://github.com/ArtixSx/RAZVILKA/actions/runs/43864979694),
`453559dac1d0f20be01a6dcf5ddc90002023c5f2`: PASS102.73с. Исправлены
source migration fixture, schema2-only quiesce gate для валидной пары3 и
порядок наблюдения завершения helper. File receipt rolled-back предшествует
окончательной публикации helper; чтение StrategyLab теперь идёт после exact
terminal job и reaped PID, в прежнем5с бюджете, без снятия recovery fences.

Доказаны actual candidate live, original post-Live cut, actual rollback receipt,
исходные бинарник/init, точный draft state, доступный reader, настоящий init
restart, joined Stop всех панелей и kernel baseline. Все10 admission regression
cases PASS; unknown format, forged/unbound pair, unjoined prior command и cancel
не принимаются. Две main-сборки из одного source с lab versions, native fixture
tag и synthetic release transport; official release provenance=false, router_ready=false.

Mihomo повтор e895, run43860680897:3/4PASS. Lifecycle candidate HEV sidecar
exit254/signal0, original same-host baseline также sidecar-start FAIL (exitcode
не записан); оба rollback/verify-rollback PASS. Причина выхода HEV ещё неизвестна,
stdout/stderr отбрасываются. Не делать вывод о TTL/сети/TUN только из exit254.

## Интегрированная повторная проверка7b6e576b

Public modern PASS141.86с; Strategy pair и old193 empty/draft/history PASS;
iptables1.8.11 normal/race PASS. Strict DNS и diagnostic30 FAIL на известной
effective BPF policy ubuntu-latest. NFQ fullLAN/manual normal/race FAIL.
Отдельно core probe не достигнут: предварительный эксперимент фиксированного
8MiB image model отверг actual8,918,408байт. Это не успешная проверка core.

Mihomo run43865735517: lifecycle и check-settlement PASS, manual и post-CAS
FAIL до целевой границы при HEV exit254. Для manual same-host baseline тоже
sidecar-start FAIL, без записанного exit code. Не считать2/4 готовностью workflow.

Probe run43865735751 PASS: baseline363f→7b6e, N12 live p50
314.0245→224.7245мс, selected queue1473→1302.5мс, cleanup verified.
Разница с147d на другой машине не доказывает эффект текущих изменений.
Raw/manifest сохранены в `C:/RAZVILKA-research-20261116/integration-7b6e576b/`.

Generic62b53867 PASS. PR generic7b6e FAIL в тесте committed evidence:
он предполагал неизменность двух независимых ambient engine/host inventories.
CreatedAt не участвует в digest; конкретный изменившийся field старый лог
не сохранил. В7561f2ec прежние predicate/copy выделены без изменения семантики;
положительный контракт проверяется на фиксированном actual BuildAt→Record→Committed,
отдельно проверяются state/digest/revision/missing/read-error, реальный engine/host/route
drift и nonaliasing. HTTP negative и запрет stale evidence сохранены.
Независимое ревью PASS; normal/race повторы50 выполняются отдельным workflow.
