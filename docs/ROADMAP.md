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

| Направление | Владелец | Работающий сценарий и доказательства | Следующее действие / внешнее ограничение |
| --- | --- | --- | --- |
| A: backup/restore и совместимая пара | Ведущий: интеграция/CI; Review: независимое ревью | Encrypted import/export, snapshot3 binary/state pair, reader7/reader5/legacy transitions, history/manual selection, unknown/finalizing fences и actual Stop/Wait retention проверены. На8522538a native/race и запуск восстановленной панели PASS: run41267351685/job124732823120 | Программный сценарий этого этапа подтверждён. Повторять на итоговом HEAD; аппаратный power-loss/reboot требует выделенного роутера |
| B: scope/DNS/исключения | Review: coordinator/capture/baseline/retirement; ведущий: независимое ревью/интеграция | Reader4 standby custody и unpublished retirement интегрированы. В6371b57d подтверждённо очищенный DNS owner архивируется с исходными FD/байтами; повтор частичной записи и гонка чужого назначения не снимают fence. Изолированный875: все11 setup effects выполнены, но диагностический30с маршрут FAIL на capture-prepared до kernel-observe/DNS;287 Current,338 SHA/12.36GB,786 version Starts и550 table reads. Адаптация standby в7e принята вf75fc3d5 после portable tests и tagged vet; её native результат ожидается | Устранить повторные полные обходы внутри одного readonly сравнения, завершить LAN→selected TLS и mismatch/opaque. Затем published retirement/durable Apply/NAT/VPN. Внутренние задачи; аппаратная приёмка отдельно |
| C: managed NFQWS2 | Backup: consumer/native fixture/измерения; ведущий: независимое ревью/интеграция | f48e7d3a/job124729629801: первый полный production consumer PASS8.370467348с — actual TLS/catalogue HTTP200, exact queue/source counters, soleWait/ACK и COMMON cleanup. Late Wait + same-owner retry PASS, unknown/finalizing сохраняются. Source mutation/lifecycle PASS production0.54с/race1.60с. [Парные43cf→f48 данные](measurements/2026-11-01/native-nfqws-f48/README.md): production14.926FAIL→8.370PASS; race15.010FAIL→15.012FAIL, разные endpoints не дают whole-workflow speedup | HTTP admission исправлен31dd5fbf (реальный middleware test PASS). Вa5f36c1f/job124731602306 actual HTTP три probe→preferred→GET→manual Frozen=true/Healthy=false→дважды fresh source bridge PASS39.28с; Store неизменён. Core production PASS10.546с. Closing source/runtime/control revocation PASS; environment fixture получил настоящий config.ErrRevisionChanged вместо ожидаемого sentinel — assertion исправленаf75, повтор ожидается. Race capture ещё превышает15с. Реальный LAN App Apply/recovery — текущая внутренняя работа Backup |
| D: полное время проверок | Capabilities; ведущий: интеграция | Actual Xray26.3.27 Check N12, physical service requests2→1, dead/cancel/cleanup и App queue PASS. Серия570b/job124710713791: p50/p95 wall509.784/512.177→405.332/408.381мс, SELF CPU50.238/52.002→41.037/45.266мс, reaped CHILD CPU64.397/65.188→59.230/60.736мс.143 строки,0 RSS errors. Повтор8522538a/job124732822978 PASS; [сырые данные](measurements/2026-11-01/native-vless-resources-570b/README.md) опубликованы | Подтверждено20.49% по p50 controlled40ms service; reference не исторический release, снижение RAM не заявляется. Аппаратные WAN/LAN и browser paint отдельно |
| E: capabilities/API/AUTO/UI | Capabilities; ведущий: интеграция | Общий inventory и tri-state availability; API/AUTO используют фактическую регистрацию. Mihomo UI использует исходный isolated_probe getter. Вd6101ba3 package_update связан с исходным adapter/manager и остаётся available:null; обычная кнопка ведёт в тот же reviewed HTTP endpoint. Независимые Go/UI проверки PASS | Повторить actual HTTP/API/UI после B/C/F и итогового SHA. Для внешнего сайта нужен конкретный URL/репозиторий; GitHub About указывает Telegram, отдельный сайт не установлен |
| F: lifecycle механизмов | Capabilities: Mihomo App/API/UI/recovery; ведущий: core/интеграция; независимое ревью взаимное | HEV2.17.1 TUN/HTTPS/cleanup/install/crash/next-boot PASS. Mihomo install/reinstall/package recovery/native validation PASS. d187/job124719152402: реальный HTTP service/COMMON cleanup2.275607154с; reader4 fallback2.794947656с со старым неизменённым бинарником. Failure/exclusion/panic сохраняют отсутствие evidence. Post-boot retirement normal/race PASS (старый boot моделируется). На97b228ce реальный HTTP update1.19.32→1.19.33 PASS7.488544279с: старый переименованный процесс, неверные receipt/hash/size отвергнуты; после original sole Wait новая пара принята. Actual idle observer PASS0.92с, subprocess crash cuts PASS (байты моделируются). Ordinary Main/default HTTPS negative PASS. Cold CLI и восстановленная panel admission на07f0c096 PASS: реальная смерть parent/Pdeath, чужие PID namespace/copy/lease отказы. HEV пять повторов по два actual запуска/cleanup PASS07f; исходная причина разовогоc2 failure не установлена | На852 isolated WG выявил несовместимость точной диагностики пустой FIB. Исправлениеfc60db86 независимо проверено: наdbce66e4/job124736820125 все WG native suites PASS, включая endpoint lifecycle и dual-family LAN TCP/UDP/NAT/excluded MAC/privacy/receipt recovery ([доказательства](measurements/2026-11-01/native-wireguard/README.md)). Полный обычный App startup этим не подтверждён. Tagged Main852 ранее отказал HTTP502 по этим WG readers; повтор после исправления ожидается. Capabilities реализует постоянный held-FD live Apply/health. Это внутренние задачи; физический WAN/reboot отдельно |
| G: независимая приёмка | Review; ведущий CI | d187: A/job124719152306 и D/job124719152411 PASS. Scoped/job124719152402 FAIL по B и новым proc fixtures; C/job124719152194 FAIL. F service/reader4 и HEV шаги PASS. Full d36: Go normal/race/vet/UI PASS, MIPS build FAIL; build tags исправленыdeabfe50, локальные Linux amd64/arm64/mips/mipsle builds PASS. Full d187 push/run41262742557/job124719152603 PASS включая четыре cross-build; дублирующий PR/run41262746899 FAIL только по общему180с backstop тяжёлого race helper. Независимо проверено test-only увеличение whole-fixture до240с (outer300с) с диагностикой фаз; production-лимиты неизменны | Полные проверенные checkpoints07f0c096 и8522538a: оба PR CI PASS целиком. Pushed8522538a: A/D PASS; C/scoped/WG FAIL по указанным сценариям; Full push41267351743 FAIL: только гонка UDP/TCP ephemeral port в file-only standby retirement fixture; исправлена1f0b9bf3 и count10 PASS. Full PR41267354412/job124732831261 SUCCESS целиком (normal/race/vet/UI/four-build/Entware). Локальныйfc60db86 включает принятые B/C/WG правки, targeted portable и Linux tagged vet PASS. Отменённые полные97/c2 не считаются PASS. Полный CI итогового интегрированного SHA обязателен. PR23 draft без merge. Аппаратные LAN/WAN/reboot требуют выделенного устройства, LAN-клиента и авторизации; воспроизводимые native сценарии в scripts/tests; [порядок аппаратной приёмки](ROUTER_ACCEPTANCE_RU.md) подготовлен |

Для отдельного сайта требуется установить конкретный URL/репозиторий; встроенная
панель находится в этом репозитории. Рабочий роутер не изменяется. Аппаратные
испытания потребуют выделенного устройства/LAN-клиента и отдельной авторизации
на изменение устройства. Эти ограничения не блокируют программную реализацию.
