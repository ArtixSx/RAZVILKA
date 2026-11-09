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
