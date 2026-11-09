# Mihomo: подтверждённые затраты и границы измерений

Дата аудита: 2026-11-09. Исторические Actions ниже относятся **только** к
`a2d1c3c77edd194741e5c46610de09ebb2570601`. Они заново прочитаны через GitHub API;
повторный запуск не выполнялся. Это не подтверждение локального `0e2db5ab`
или последующих изменений.

## Что показывают исходные журналы

[Native lifecycle run 41452796506](https://github.com/ArtixSx/RAZVILKA/actions/runs/41452796506)
завершился FAIL. Начальный Apply занял 86.758 с и прошёл два mandatory probes.
Следующий fresh Check после освобождения Apply отказал с
`dataplane transaction journal is unavailable`; до Stop этот запуск не дошёл.
Сценарий check-settlement в том же run получил такую же ошибку после Apply
85.388 с, до предусмотренного fault cut. Более старый отказ повторного Stop
нельзя подставлять вместо этой фактической точки отказа.

| Этап первого Apply | Время, мс |
| --- | ---: |
| Snapshot | 2234.110 |
| Stage | 1475.373 |
| Validate | 2537.121 |
| Canary | 2085.420 |
| Activate | 9478.335 |
| Health | 32963.835 |
| Commit adapter | 2965.208 |

Эта таблица не покрывает всё время HTTP Apply: подготовка и внешние наблюдения
также входят в его 86.758 с. Суммировать её с вложенными CPU длительностями нельзя.
Профиль родительского тестового процесса содержит 112.18 CPU-секунд на 89.21 с
wall всего теста. `sha256.blockSHANI` занимает 87.53 CPU-секунды, **78.03%**
семплов; системные вызовы — ещё 19.84%. Профиль включает setup и контроллер,
не включает CPU дочерних Mihomo/Xray. Это подтверждает стоимость повторных
полных чтений и SHA, а не медленный ответ API `/delay`. Никакого процента
ускорения по одному неуспешному запуску не вычисляется.

[Same-boot run 41452796574](https://github.com/ArtixSx/RAZVILKA/actions/runs/41452796574):
normal consumer PASS 91.50 с. Вложенные наблюдения: `source-current` — 245 вызовов,
32.467 с; `home-current` — 25 вызовов, 47.802 с; actual native witness callbacks —
74.092 мс. **Inclusive длительности перекрываются.** Race producer отказал на
Activate с `route-process-unavailable`, rollback/verify прошли; race consumer
не запускался. Это самостоятельная программная неисправность, не отсутствие
физического роутера.

SHA-256 скачанных текстовых журналов `gh run view --log`:

- Lifecycle: `defc766016309b208fd591015c5eb25b13f91b3955b0be184658a3ef32d5870a`.
- Same-boot: `ecadfe17cc694d2a24978d3fb19700588b5b8811a580356251f0380cd0aba065`.

Полные журналы оставлены вне исходников в
`C:/RAZVILKA-research-20261109/mihomo-a2d-{lifecycle,sameboot}.log`.
Предыдущие профили и ограничения описаны в
[историческом исследовании чтений](../../2026-11-02/mihomo-live-source-observation/README.md).
Парное библиотечное ускорение SHA уже реализовано и отдельно измерено:
[reference/new](../../2026-11-02/parallel-artifact-816/README.md).
Повторно ослаблять source/ownership bookends без воспроизводимого native
сравнения оснований нет.

## Исправленный пробел наблюдаемости isolated probe

`MihomoProbeAdapter.Check.DurationMS` измерял только adapter, включая его
cleanup. Он не включал компиляцию, DNS, исходную ReviewMihomoProbe и её проверку
артефактов до Check, а также `source.Close`, `control.Close`, release после Check.
При ошибке HTTP ответ терял даже это время.

В существующие JSON ответы probe добавлен объект `timing`:

- `handler_elapsed_ms`: от входа в probe handler до подготовки ответа,
  после явной попытки финализации;
- `preparation_ms`: в том числе admission внутри handler, компиляция, DNS и
  проверка source;
- `adapter_check_ms`: исходный Check вместе с его собственным cleanup;
- `postcheck_ms`: отдельный closing environment guard;
- `finalize_ms`: исходные source/control Close и release.

Отсутствующее поле означает, что этап не запускался; 0 — наблюдавшийся этап
короче миллисекунды. Время не является evidence или разрешением применить
маршрут. Middleware queue, передача HTTP, сериализация и deferred notification
после записи ответа не измеряются. Существующие 400 text / operation failure
ответы и отдельный recovery endpoint не меняются. Ошибка финализации сохраняет
cleanup-pending, исходный owner и защитный отказ.

Windows/Go1.26.5: адресные App тесты PASS, включая отказ до запуска, пропущенные
этапы, измерение ошибки финализации и отсутствие request/error secrets в JSON.
Тест финализации здесь модельный; он не заменяет native cleanup.

## Воспроизводимый Linux сценарий

Используется существующий `scripts/test-mihomo-probe-native.sh`, без изменения
production deadlines. Он создаёт disposable network/mount namespaces, временный
`/opt`, локальную CA и настоящие VLESS/TLS peers. Основные проверки:

- `TestMihomoOriginalNativeServiceAndCommonCleanup`;
- `TestMihomoOriginalNativeHTTPServiceAndCleanup` — настоящий HTTP handler,
  новые timing assertions, неизменность config, original custody release,
  terminal COMMON `removed`.

Нужны Linux root с разрешённым `unshare`, Go1.26.5, iproute2/util-linux,
ca-certificates, официальный Xray26.3.27 и Mihomo1.19.33. SHA архивов уже
зафиксированы в workflow. HEV/TUN и действующий роутер для этого isolated probe
не нужны. Пример после установки проверенных assets:

```sh
sudo env PATH="$PATH" GOTOOLCHAIN=local \
  GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" \
  RAZVILKA_XRAY_NATIVE=/usr/local/lib/razvilka-fixtures/xray-node26.3.27/xray \
  RAZVILKA_MIHOMO_ARCHIVE=/usr/local/lib/razvilka-fixtures/mihomo.gz \
  sh scripts/test-mihomo-probe-native.sh
```

Требуется фактический PASS обоих тестов без SKIP. Компиляция Linux-target на
Windows этого не подтверждает. Повторный запуск этого скрипта создаёт новый
процесс: его нельзя обозначать как проверку уже прогретого runtime. Native
изолированный service probe, generic CI и физический router/LAN acceptance
остаются разными уровнями доказательств.

## Текущий isolated native результат: 71b6f969

Отдельная новая проверка относится к
`71b6f969579833e3ba217b331dc3c1a24bb150f7`, а не к историческому a2d выше.
[Job 128966328195 / run 42557481299](https://github.com/ArtixSx/RAZVILKA/actions/runs/42557481299/job/128966328195)
завершился **SUCCESS**. Оба обязательных native теста реально выполнены без SKIP:

- `TestMihomoOriginalNativeServiceAndCommonCleanup`: PASS, 12.61 с вместе с
  complete, required-semantic-failure, excluded-required-scenario и
  panic-after-listener. Успешный adapter Check отдельно занял 3010 мс.
- `TestMihomoOriginalNativeHTTPServiceAndCleanup`: PASS, 5.14 с со всем setup.
  Новые timing assertions и прежние проверки config/COMMON/custody пройдены.

Один успешный HTTP probe на том же Linux runner:

| Измерение | мс |
| --- | ---: |
| Handler до подготовки ответа | 3641 |
| Preparation, включая source review | 631 |
| Adapter Check, включая собственный cleanup | 3009 |
| Closing environment guard | 0 |
| Source/control finalization | 0 |
| Клиент: запрос → прочитанный ответ | 3642.777 |

Нули означают наблюдавшиеся длительности меньше 1 мс. Разница между суммой
этапов и wall включает округление и код между границами; этапы не покрывают
middleware queue. Это N=1, без парного сравнения до/после: **ускорение Mihomo
по этим цифрам не заявляется**. Результат доказывает isolated HTTP/VLESS/TLS
service check и его original cleanup на Linux; он не закрывает исторический
live Apply→fresh Check blocker, физический WAN/LAN или готовность роутера.
Статус всего Actions run следует оценивать отдельно от этого завершённого job.

[Исходный журнал job](mihomo-handler-native.log), SHA-256:
`7c2dc81eb9c261d2424627a927f69eb1039b4ce4027355dff162f7a73c91145b`.
Журнал получен через Actions jobs/logs API, сохранён без изменения после
проверки отсутствия открытых токенов/ключей. Идентификаторы и адреса native
fixture не являются пользовательскими credentials.
