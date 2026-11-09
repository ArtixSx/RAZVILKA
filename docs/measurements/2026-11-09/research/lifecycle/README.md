# Продолжение lifecycle после измеренного VLESS улучшения

Первый baseline: `a9f5825dbec953030c4b18d68bc844d2fc95be02`, исполняемый код
совпадает с8c; последующие docs/CI changes не меняли runtime.

| Проверка | Результат на a9f | Вывод |
| --- | --- | --- |
| Binary/StrategyLab pair, race, реальные reader binaries old/5/current | PASS, job128980231202 | Совместимые пары/unknown/partial проверены отдельно от generic CI |
| Восстановленная панель | Реальный native child PASS0.12с, без SKIP | Не power-loss испытание роутера |
| DNS selected, default12s/4s | FAIL14.18с, publication не достигнута |137 full executable hashes,4.98GB,250 table children; capture4.98с и standby4.83с — overlapping diagnostic, не сумма wall |
| DNS canceled-ready | FAIL до исполнения | Старый fixture требовал diagnostic30; это ошибка предусловия теста, не повтор сетевого отказа |
| Mihomo post-CAS required TLS rejection | PASS59.42с,503, exact desired restored, rollback_verified=true, original_pending=false | Достигнут реальный целевой отказ и rollback |
| Mihomo full lifecycle | FAIL74.21с, fresh Check journal unavailable после Apply | Stop/reapply не приняты |
| Mihomo failed-Check settlement | Apply87.467с, через0.577с тот же journal отказ | Целевой settlement cut не достигнут |

Runs: [research42561994669](https://github.com/ArtixSx/RAZVILKA/actions/runs/42561994669),
[Mihomo42561994598](https://github.com/ArtixSx/RAZVILKA/actions/runs/42561994598).
Raw logs и [SHA256](manifest.json) сохранены рядом. У research run общий FAILURE
из-за DNS не отменяет отдельный успешно завершённый backup job.

## Исправления следующего кандидата

`c4399c94`: strict fixture12с для обеих DNS generations (30 только явный
диагностический вариант), свидетельство фактического cancel, fixed Mihomo error
labels, точный перенос reviewed098 classic batch: каждый настоящий child
сохраняет полные metadata bookends, исходные внешние full SHA остаются; два
дублирующих обхода вокруг nonempty readonly batch удалены. Новый end-to-end
выигрыш не заявлен. Более новые combined-output guards сохранены.

`94821d71`: исправлена повторная ротация журнала внутри оригинального Mihomo
Check. Первоначальная ротация выполняется в committed; beginHealthCheck переводит
его в active-checking, поэтому повторная ротация из currentLiveObserved ошибочно
требовала committed и возвращала journal sentinel. Отсрочка допускается лишь
для того же открытого health cursor с точным header после старых ownership и
local-record checks. Missing/copied/foreign/closed/failed/stopping/publishing/
unknown/header mismatch/cancel отказывают; reader gate полного cohort сохранён.
Одинаковая regression до исправления FAIL, после PASS; [before](rotation-before.txt)
и [after](rotation-after.txt). Independent targeted run PASS0.409с. Это portable
доказательство ошибки metadata, не свидетельство завершённого native lifecycle.

`a9bd8d75`: добавлен узкий retirement исходной unpublished DNS preparation
до создания kernel owner. Требуются настоящий successor failure cursor,
законченный original child/source и отсутствие выданного alias/flow. Partial ACK
не передаёт custody другому владельцу. Generic GEN1 failure recovery этим
контрактом не реализован. Native приёмка пока ожидается; отрицательные модели
и Linux crosscompile не заменяют успешную очистку.

Paired fixture берёт точный c439 и опубликованный hashed overlay только с
тестами и refusal seam; baseline обязан реально достичь CUT и REFUSED.
Candidate должен достичь CUT, COMPLETE и итогового точного PASS без SKIP,
включая capture/standby transaction cuts. GEN1 timeout не считается успешным
воспроизведением. Этот опыт использует явный diagnostic30, а strict12/4
выполняется отдельными jobs.

Изолированная проверка итогового a9bd worktree: адресный DP PASS1.484с;
Linux app с razvilka_native_fixture crosscompile PASS. Native/generic runs
нового SHA оценивать отдельно. [Единый план](../../../../ROADMAP.md).

## Native a9bd8d75: новая достигнутая граница

[Run42563038017](https://github.com/ArtixSx/RAZVILKA/actions/runs/42563038017):
Strategy pair + восстановленная панель вновь PASS. Strict DNS selected и
canceled-ready оба дошли до GEN1, но publication12с не достигнута (14.09/14.16с).
137 full hashes≈5.01GB и250/260 child table reads не дают заявить выигрыш whole
workflow от переноса098. Core NFQWS probe9.84с, HTTP32.13с и closing-source/
runtime/control/environment проверки PASS; full LAN52.56с и manual21.89с FAIL:
activation deadline, затем COMMON retirement не подтверждён. Race job FAIL.

[Mihomo42563038068](https://github.com/ArtixSx/RAZVILKA/actions/runs/42563038068):
post-CAS rollback PASS. После исправления rotation оба сценария проходят Check
и достигают stopped-plan-ack; полного Stop/reapply пока нет. Следующий
`12879f78` исправляет сравнение собственного original compiler Plan с его
опубликованной wire shape, сохраняя bookkeeping allowlist и exact before/target
FD/bytes. Реальный BuildAt regression доFAIL/послеPASS, обаACK и20 intent
mutation refusals проверены. [До](stopped-compiler-wire-before.txt),
[после](stopped-compiler-wire-after.txt). Native нового fix ещё ожидается.

DNS preparation pair достиг CUT во всех4 случаях, включая baseline. Candidate
отказывает на восстановлении source/capture до expected partialACK:
[независимая проверка](a9bd8d75/preparation/independent-review.json).
Это полноценное воспроизведение отказа, но не успешная cleanup приёмка.
При разборе найдена невозможная pointer equality двух independently issued
retirement views; исправление должно сохранить оба оригинала, проверить
каждый closed ledger и точные mapping/source/control coordinates.
Diagnostic30с/10с этого опыта не заменяет strict12с/4с.

Все новые raw logs и [SHA256](a9bd8d75/manifest.json) сохранены отдельно от
предыдущих. Ни failure-prefix duration, ни metadata microbenchmark не выдаются
за ускорение полного LAN workflow.

## Повтор VLESS на a9bd8d75

[Run42563038104](https://github.com/ArtixSx/RAZVILKA/actions/runs/42563038104)
SUCCESS. [Парные данные](../ci-a9bd8d75/paired-analysis.json): baseline0e и
candidatea9bd на одном runner, все182 строки проходят identity/verdict/cleanup
проверки; одинаковый Xray26.3.27, алгоритм current-reuse, N12.
Full live p50/p95 398.299/411.203→307.620/310.551мс; selected2 completion
2445/2490→1285/1405мс. Это самостоятельный опыт, не сравнение между runners.
Cancel full wall p95 здесь хуже:360.734→494.051мс; sample2 содержит startup209мс
и configuration41мс, cleanup101мс, canceled verdict и подтверждённая очистка
сохранены. Выброс не удалён; универсальный выигрыш по всем метрикам не заявляется.

## Следующий проверяемый кандидат

`efe6cf3f` объединяет только concrete original capture read: один полный
resource.Current по-прежнему проверяет material/source, child, файлы, registry,
config и network на каждом обращении. Повторные чтения того же material
заменены точными локальными ассоциациями, closing не вызывает callbacks.
Public/custom owner paths прежние, ни один guard перед effect не удалён.
Ускорение до native измерений не заявляется.

`2f08886a` сохраняет два исходных independently issued retirement views вместо
невозможного pointer equality между ними: каждый по-прежнему должен совпасть
со своим holder, mapping/binding/control точные, оба closed observations
проверяются независимо. Genuine factory test создаёт два разных view одного
источника до Close и проверяет оба joined ledger.

Независимые проверки PASS: DP0.447с, DNS1.032с; Linux tagged app crosscompile
PASS. В изолированном checkout кода9bed: DP0.590с, DNS1.355с PASS.
`98df8b32` добавляет только fixed COMMON subphases NFQWS без изменения порядка
действий или неизвестных исходов; это диагностика следующего failure, не fix.
Native приемка новых изменений ещё ожидается.

## Завершённый прогон d5fd9774 и следующие исправления

[Generic PR CI42564590641](https://github.com/ArtixSx/RAZVILKA/actions/runs/42564590641)
SUCCESS; push42564585991 был отменён, поэтому не считается PASS.
[Исходные результаты и SHA256](d5fd9774/manifest.json) сохраняют также все
неудачные native сценарии. Перечисленные ниже отказы — программные задачи,
а не отсутствие физического роутера.

- Mihomo проходит прежний stopped-plan-ack, но Stop останавливается на
  terminal-close: закрывающая scope проекция теряла оригинальную Mihomo row,
  необходимую reader9. `2e613a61` сохраняет только точный собственный ресурс;
  header admission, обе journal images и общий reader gate прежние.
  Regression до FAIL / после PASS, independent review и vet PASS.
- DNS preparation: baseline и три candidate действительно достигают CUT.
  Candidate теперь проходит восстановление capture/source и оба частичных
  ACK, но завершается journal refusal из-за listener witness с отменённым
  forward context. `2924cd74` отзывает CAS только исходный joined listener
  после обоих ACK и повторных проверок restored standby, до снятия fences.
  Наблюдение после отзыва требует свежего GLOBAL absence; чужой listener
  продолжает запрещать очистку. Portable real-child regression и Linux
  crosscompile PASS; это ещё не положительная native приёмка.
- Strict DNS12с/4с: selected14.19с, canceled-ready14.23с, GEN1 не опубликована.
  Selected достигает capture-prepared/11effects; предыдущий a9bd достигал
  planned/6effects. Снижение времени standalone standby на разных runners
  не является парным измерением ускорения. 201 full hashes≈7.35GB и530
  table children включают больше выполненной работы. Full lifecycle FAIL.
- Managed NFQWS: причина отказа retirement локализована до policy-remove;
  неизвестный результат сохраняется, retirementStarted не сбрасывается.
  `02ca980d` помещает только свежий post-Add readback в существующий bounded
  readonly observation, симметричный post-Delete. Add остаётся снаружи;
  opening/closing/current/error/cancel checks сохранены. Изменение прошло
  before/after regression, независимое ревью и vet. Выигрыш полного LAN
  workflow требует native измерения.

Изолированная проверка интегрированного `2924cd74`: адресные DP тесты PASS
12.233с. Первая попытка native2924 частично остановилась на загрузке pinned
assets (HTTP504), до выполнения соответствующих тестов; это не доказательство
регрессии или исправления runtime. Повтор выполняется на том же SHA.

## Дополнительная парная проверка d5fd9774

[Run42564585882](https://github.com/ArtixSx/RAZVILKA/actions/runs/42564585882)
SUCCESS. [Анализ и полный набор](../ci-d5fd9774/paired-analysis.json): все182
строки, exact identity, verdict, cleanup и одинаковый pinned binary проверены.
Для каждого сценария12 повторных плюс отдельно первый образец; nearest-rank.

| Сценарий | Baseline0e p50/p95, мс | Candidate d5fd p50/p95, мс |
| --- | ---: | ---: |
| Full live Check, включая cleanup | 407.730 / 417.270 | 314.351 / 361.279 |
| Отмена, full wall | 365.018 / 367.141 | 278.459 / 302.356 |
| Single enqueue→completion | 789 / 800 | 695 / 708 |
| Selected2 enqueue→completion | 2706 / 2741 | 1543 / 1575 |
| All2 enqueue→completion | 2727 / 2780 | 1549 / 1600 |

Это отдельная пара на одном runner; между runners результаты не смешиваются.
Baseline запускается первым, cache/load bias остаётся; первый образец не
означает холодный OS cache. Actual Mihomo HTTP handler также PASS без SKIP:
3321мс=preparation573+adapter2747+округление, N1, не парное ускорение.
HTTP/TLS service и common cleanup этого probe не доказывают Apply/Stop/LAN.

## Native2924: восстановление подтверждено, strict deadline ещё нет

[Lifecycle42566485742](https://github.com/ArtixSx/RAZVILKA/actions/runs/42566485742)
в целом FAIL. При этом strategy-pair SUCCESS, включая совместимые бинарники,
native/race и восстановленную панель; preparation pair также SUCCESS.
[Независимый аудит preparation](2924cd74/preparation/independent-review.json)
и [сырые данные с SHA256](2924cd74/manifest.json) фиксируют все четыре случая:

| Случай | Фактический исход | Время теста, с |
| --- | --- | ---: |
| Baseline c439, идентичный failure seam | Настоящий CUT → ожидаемый CLEANUP_REFUSED | 94.57 |
| Candidate clean | CUT → CLEANUP_COMPLETE → точный PASS | 128.45 |
| Candidate capture transaction ACK | Сбой удерживает fence; retry исходного владельца → COMPLETE → PASS | 136.57 |
| Candidate standby transaction ACK | Сбой удерживает fence; retry исходного владельца → COMPLETE → PASS | 128.79 |

Дополнительно проверены отсутствие child после cleanup, CheckExecutionRecovery
и реальный прежний alias с исходными адресом/портом LAN-клиента и маркером
сервиса. Нет SKIP. Это завершённый сценарий original successor preparation
recovery с явным diagnostic30с/10с, не generic GEN1 recovery и не strict12с/4с.
Время baseline заканчивается раньше на отказе, поэтому эту таблицу нельзя
использовать для заявления ускорения.

Strict selected FAIL19.25с: достигнут capture-ready, kernel-observe2 и
mapping-compare1, но GEN1 не опубликована в12с. Поздний diagnostic stack уже
в AcceptTCP не устанавливает точное время открытия readiness до/после deadline.
Все12 DNS gate attempts отказали; это не доказательство, что виноват только
polling. 208 hash reads; профиль SHA≈4.61с. Canceled-ready не выполнился:
официальный asset download вернул HTTP504. Бюджеты и отрицательные результаты
не изменялись. [Подробное сравнение](2924cd74/domain-comparison.json).

Mihomo lifecycle42566485704, обе попытки, не упражнял новые runtime fixes:
HTTP504 на pinned Xray26.10.31 до установки fixtures. Managed production core,
AppHTTP и closing проверки PASS, LAN/manual не начались из-за HTTP504; race
также не получил необходимые assets. Предыдущие реальные LAN ошибки d5
остаются открытыми, такой setup failure не заменяет их проверку.

Загрузчик `scripts/fetch-native-fixture.sh` добавляет только официальный
Release Assets API fallback при ошибке HTTP. Все пять прежних pins сохранены;
сначала проверяется SHA, потом публикуется файл. Успешный HTTP с неверными
байтами отказывает без fallback. Реальные архивы независимо скачаны и сверены
([mapping](2924cd74/official-native-fixture-assets.json)); повторная живая загрузка
через сам helper прошла direct504→API→точный SHA. Шесть контролируемых случаев
проверяют оба транспорта, wrong bytes, общий отказ и unknown asset, сохранность
старого файла и удаление временного: [результат](2924cd74/results.json).
Авторизация не требуется; production downloader не менялся.

Следующая узкая оптимизация: три standalone standby Current используют
существующее ограниченное наблюдение immutable file bytes только для concrete
original owner; обе process/source проверки сохраняются. Наблюдение закрыто
до inspector/Start/effect, custom producer остаётся на прежнем полном пути.
Independent focused PASS0.250с; интегрированный Windows DP PASS12.454с;
Linux tagged crosscompile PASS. Новые native тесты проверяют primitive4→2
full reads, повторное хеширование следующего bracket и mutation refusal;
это не измерение ускорения LAN workflow.

## Парный probe2924, повтор после setup outage

[Run42566485696, attempt2](https://github.com/ArtixSx/RAZVILKA/actions/runs/42566485696/attempts/2)
SUCCESS; attempt1 тесты не запускал. [182 проверенные записи](../ci-2924cd74/paired-analysis.json),
тот же baseline0e, binary, сценарии, N12 и ограничения фиксированного порядка:
full live p50/p95 **403.157/405.602→312.937/316.020мс**, selected2 server
completion **2604/2622→1423/1437мс**. Actual Mihomo service/common cleanup и
HTTP handler также PASS без SKIP. Сигнал стабильного сокращения двух найденных
простоев повторился; минутный WAN случай и router lifecycle не воспроизведены.
