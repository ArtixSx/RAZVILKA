# Дальнейшая работа

Приёмка кандидата 0.20.0 продолжается. Состав и ограничения описаны в
[примечаниях к выпуску](releases/0.20.0.md); результаты проверок и оставшиеся
условия выпуска — в [текущем статусе](CURRENT_STATUS_RU.md).
Этот план не подтверждает готовность выпуска или завершение аппаратных проверок.

Текущая карта механизмов, подтверждённые исправления и приоритетная очередь
завершения находятся в [аудите обходов от 31.10.2026](BYPASS_REVIEW_2026-10-31_RU.md).
Главные зависимости — управляемый сетевой подбор NFQWS2, точная маршрутизация
доменных сервисов и единое представление фактических возможностей исполнителей.

После текущей приёмки:

- Проверить MIPS и MIPSel на физических роутерах. Сборка бинарника не заменяет
  проверку установки и сетевой работы на устройстве.
- Развить обход NFQWS2 для отдельных устройств через нативную обработку
  соединений и connmark. До реализации и проверки действуют ограничения
  [матрицы платформ](RUNTIME_SUPPORT_RU.md).
- Развить совместную работу двух DPI-обходов с явными границами управления,
  проверкой результата и восстановлением после сбоя.
- Расширять поддержку доменных сервисов через VPN и прокси только после
  реализации точного ограничения трафика выбранными доменами. Общий IP сайта
  сам по себе не разрешает перехватывать трафик других сайтов на том же адресе.
- Продолжать проверку подключений VLESS/Xray, Generic WireGuard и AmneziaWG
  через общий сетевой исполнитель, с отдельным подтверждением каждого
  поддержанного сценария.

Исторические рабочие планы интеграции не являются инструкцией установки
публичного выпуска. Успешные проверки на моделях не заменяют испытания на роутере.

## Общая очередь реализации 31.10.2026

Ведущий интегрирует `work/bypass-integration-20261031` поверх PR #22/#23.
Один файл редактирует один владелец; Review проверяет рискованные переходы.
Незавершённая реализация ниже — работа команды, а не внешний блокер.

| Направление | Владелец | Работающий сценарий | Доказательства | Оставшиеся действия | Конкретный блокер |
| --- | --- | --- | --- | --- | --- |
| A: backup/restore | Ведущий; независимое ревью Backup/Review | Encrypted import/export и совместимая snapshot3 пара binary/StrategyLab; история/manual intent; unknown/finalizing; удержание до Stop/Wait; запуск восстановленной панели | `fc3062ba`, run41390372917/job125100213165: native/race/restored panel PASS | На reader8 HEAD `4bcb7d0d` focused A/job125129182177 и полный Linux CI PASS; HTTP encrypted export→preview/import→strict Store reload нового ручного Mihomo selection локально PASS2.603с и включён в общий CI. Повторить после оставшихся lifecycle изменений | Программного внешнего блокера нет. Power-loss/reboot: нужен выделенный роутер и отдельная авторизация |
| B: точный scope, DNS, исключения | Review; Backup независимое ревью; ведущий интеграция | Never-issued cleanup; DNS publication → Stop → cached-alias TLS; SAME-owner retry после потери alias0 ACK; исходные FD журналов и in-flight UDP dedup | `96f46bf4`: baseline47.42с/alias0 retry59.66с PASS; `0d554b44` fullCI41385320410 PASS, остальные6 native cases остановились до DNS. `a90cfe3f` actual historical FD mutation/race PASS. Pool `2f095f7c`: baseline46.67с, alias0 retry41.21с, global-ACK retry51.55с PASS; остальные cases и два поколения пока до DNS FAIL30s. Принятые Guard/history8files опубликованы в `4a4298eb` | Pure standby Guard `ac6760f8`: full hash4→2 при сохранении двух original Current, 13 наблюдений в каждом из трёх сценариев ([данные](measurements/2026-11-02/domain-standby-read/results.json)); end-to-end ускорение не заявлено. Initial keeper `f2410ed7`: source/FD race PASS, native остановился до gen1 DNS, сам переход не проверен. Проверить pool8: два поколения, selected/mismatch/opaque, source-port collision; завершить terminal/failure retirement и retry; устранить задержку до DNS без переноса evidence через эффекты | Внешнего программного блокера нет. Native failures и незавершённый retirement — работа команды, не основание закрыть направление |
| C: managed NFQWS2 | Ведущий; Backup независимое ревью | Реальные TLS/counter/sole Wait/COMMON cleanup; три HTTP probes и ручной выбор; физический WAN/bridge/included/excluded scope и drift refusal. Первый manual запуск теперь удерживает runtime directory от original Snapshot FD | Matched single pair core9.851→8.789с и HTTP33.20→31.35с PASS: [измерения](measurements/2026-11-02/native-extension-path/README.md). Directory custody/замена inode/сохранение Close-ошибки: `37101f6f`, run41404553563 normal/race PASS; Close failure — явно отмеченная ACK model. `90d2f191` native manual FAIL на prepared.active | Довести LAN Apply → included/excluded packets → Stop/recovery и race. Pure tool-read оптимизация исправлена после двух native отказов (pre-Acquire binding и исходный IP rule-show ABI); `b762c478` original IP read ABI и mutation gates normal/race PASS, повторный static version batch metadata3→2 при каждом фактическом IP child. Production finite TLS/HTTP PASS, manual перешёл к prepared.policy-apply, но FAIL; race FAIL. Scratch hash `2b0a8df1` проходит отдельный native прогон; успешное ускорение полного LAN пути не заявлено | Программного внешнего блокера нет. Полный manual/native LAN пока не завершён; ошибочные/устаревшие владельцы и unknown cleanup остаются fenced |
| D: полное время VLESS | Capabilities; ведущий интеграция | Actual Xray26.3.27 full Check, queue, dead/cancel и joined cleanup; один физический сервисный запрос вместо двух | N12 controlled40ms: p50/p95 wall509.784/512.177→405.332/408.381мс; SELF CPU50.238/52.002→41.037/45.266мс; CHILD64.397/65.188→59.230/60.736мс;143 строки/0 RSS errors. Повтор `fc3062ba` PASS; integrated `4bcb7d0d` native job125129182077 PASS. [Сырые данные](measurements/2026-11-01/native-vless-resources-570b/README.md) | Повторить на итоговом HEAD; browser paint и физический WAN измерять отдельно | Снижение RAM не заявлено. Аппаратные измерения требуют выделенного стенда; программный сценарий подтверждён |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий ревью/интеграция | Фактическая регистрация и tri-state availability; isolated probe и package update ведут в исходные reviewed endpoints | Независимые Go/UI проверки PASS; общий CI `fc3062ba` PASS. Manual Mihomo API/UI и CAS интегрированы в `4bcb7d0d`, readiness остаётся false | После F пройти настоящий HTTP preview/apply/Stop, включить только проверенную per-plan readiness; повторить UI/API/AUTO и encrypted import без повышения health от истории | Внешнего программного блокера встроенной панели нет. Для отдельного внешнего сайта отсутствуют URL/репозиторий |
| F: lifecycle/update/recovery | Capabilities: warm Mihomo/HEV; Backup: same-boot; ведущий: cold/COMMON/WG | Pinned component update, HEV TUN/HTTPS/cleanup; WG четыре native suites; Mihomo persistent child/kernel ownership; post-boot offline retirement и CLI; reader8 health archive | WG [native evidence](measurements/2026-11-01/native-wireguard/README.md). Cold integrated `4bcb7d0d` normal/race41399878590 PASS; `1f059b40` fullCI41392355404 и normal/race41392355393 PASS; public66.25/79.32с, CLI38.67/45.01с с реальными пятью leases. Old-boot history моделируется, текущие наблюдения настоящие: [результаты](validation/2026-11-02/mihomo-cold/results.json). Health `dfde3e66` fullCI41395075922 и normal/race41395075898 PASS; integrated `4bcb7d0d` normal/race41399878588 PASS: [результаты](validation/2026-11-02/mihomo-health/results.json), terminal rows modeled. Warm `71edb546` actual child normal/race7.52/15.03с, FD mutation4.70/11.27с и original kernel/read-view6.80/14.92с PASS. App39.92wall/38.93CPU FAIL health deadline, последнее место preflight-closing-guard; node transit rollback-failed остаётся fenced | Завершить live Apply/health/Stop/repeat и HTTP/manual; проверить интегрированный reader6/7/8 на итоговом SHA; реализовать same-boot offline cleanup после parent death. Исправление настоящего forwarding archive `d3fce287` проверено на базе `193cf851` в `aa511163`: run41407641893 normal/race PASS, public51.67/117.76с, CLI30.08/68.43с. Прежний cold fixture не содержал forwarding manifest; текущий покрывает реальный формат, но old boot остаётся моделью. CPU baseline60.50с/59.95CPU,79.72% SHA256; forward bracket57.42с/56.63CPU, но оба failed workflow — ускорение завершённого пути не заявлено. Forward+cleanup brackets проверены отдельно; следующий шаг — убрать подтверждённые вложенные чтения в health, сохранив исходные лимиты | Внешнего программного блокера нет. Роутерный WAN/reboot не проверен. Source/ownership/unknown fences сохраняются до полного доказательства |
| G: независимая приёмка | Ведущий CI/интеграция; независимый reviewer каждого рискованного пакета | Полный Linux normal/race/vet/UI/cross-build/Entware; отдельные isolated native сценарии | `fc3062ba`: PR41390377465/push41390372929 SUCCESS; focused A/D/WG PASS, Bselected/C FAIL. `ddca25a6` pinned deadline fix10 повторов PASS1.849с, полный PR41394916123/push41394909779 SUCCESS; `4a4298eb` full push41397099584/PR41397103694 SUCCESS; focused A/D/WG PASS, B/C FAIL. Coherent F/reader8/manual/backup интегрированы в `4bcb7d0d`, full CI41399878610/41399884332 SUCCESS; focused A/D/WG PASS, B/C FAIL. `cabd038e` full push41402801596/PR41402814129 SUCCESS; cold41402801656 и health41402801652 normal/race PASS; `193cf851` полный push41405831679/PR41405839979 SUCCESS, cold41405831838/health41405831802 PASS, focused B/C и warm FAIL | Интегрировать принятые пакеты, исправить адресные failures и дождаться CI точного итогового SHA; актуализировать runtime matrix и draft PR | Merge/release/deploy не разрешены. Аппаратные испытания требуют выделенного устройства, LAN-клиента и явной авторизации; [порядок проверки](ROUTER_ACCEPTANCE_RU.md) подготовлен |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.
