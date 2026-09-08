# Архив статуса RAZVILKA на 6 сентября 2026 года

Этот исторический снимок сохранён при сокращении главной страницы статуса
8 сентября. Открытые пункты и формулировки ниже отражают момент записи;
актуальная готовность находится в [CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md).

Обновлено: 6 сентября 2026 года, сверка с редакцией 18 единого плана<br>
Проверенный main / последний проверенный в CI commit: `bd36e160af5eabd40c0a8bab77c2454d4e4fb06d`<br>
Последний стабильный релиз: [`v0.18.0`](https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.18.0)<br>
Текущий цикл разработки: `0.18.1-dev` — Truth & Safety

Опубликован предварительный релиз [`v0.18.1-rc.1`](https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.18.1-rc.1).
Он не заменяет стабильную версию и не устанавливался на роутер в ходе этой работы.

CI этого SHA [успешен](https://github.com/ArtixSx/RAZVILKA/actions/runs/34018287405);
результат повторно прочитан через GitHub API 6 сентября. Это проверка исходной
базы, а не CI локальных исправлений [повторного аудита](AUDIT_2026-09-06_RU.md).
Их проверки и ограничения перечислены отдельно в отчёте.

Этот файл — краткий источник правды о фактически доказанной готовности. Старые
gap-аудиты сохранены как исторические снимки и не описывают текущий `main`.

## Что означают уровни

- **В main** — функция присутствует в указанном SHA; это не stable-релиз.
- **Реализовано локально** — изменения рабочей копии, ещё без собственного CI.
- **CI** — полный workflow прошёл на указанном commit.
- **Роутер** — конкретный сценарий проверен на эталонном Keenetic ARM64.
- **Экспериментально** — функция доступна, но ещё не прошла необходимую
  аппаратную матрицу или не имеет полного владения жизненным циклом.

## Матрица возможностей

| Область | Уровень | Что подтверждено | Что ещё требуется |
|---|---|---|---|
| Entware install/upgrade/rollback | Реализовано · CI · Роутер | Транзакционное обновление `0.17.0 → 0.18.0`, сохранение учётной записи и конфигурации | Reboot/power-loss и MIPS/MIPSel HIL |
| Transaction engine | Реализовано · CI · Роутер | Plan, snapshot, stage, validate, canary, commit/rollback и LKG-журнал | Fault injection во всех commit points |
| NFQWS2 adapter | Реализовано · CI · Роутер | Запуск, читаемые runtime-списки, проверка фактического процесса и YouTube HTTP `204` | Native ownership стратегий, NFQUEUE lease и event-driven recovery |
| Sing-box/Xray candidate | Реализовано · CI · частично Роутер | Локальная проверка конфига, loopback proxy-canary, bounded URLTest pool | Полная Evidence v2 и длительная проверка узлов |
| NodeStore и NB1 | N1.1–N1.4 · main · CI; NB1/native lifecycle/UI · Роутер | Exact check → preview → одноразовый Apply; PC HTTP 200 на A/rollback-A/B и через фактический UI A/B; посторонние черновики сохранены | WAN/restart recovery и отдельные Reality/Hysteria2/TUIC gates |
| NET1: сессия WAN | Локально · частично Роутер | Fresh underlay epoch; защита node proof/plan/apply/recovery и scoped TestLab/SmartRoute; ARM64 снимки, DNS file ABA и lifecycle tests | Реальный WAN reconnect/ABA, Linux/race; скрытый DNS upstream не наблюдается |
| Proxy forwarding | Локально · Роутер для PC /32 и all-LAN | gVisor, exact outbound, owned FORWARD/NAT; all-LAN расширяет подтверждённые bridge prefixes, 28 правил/6 IPv6 kernel checks; PC IPv4 HTTP 200, WAN ingress negative, cleanup PASS | Настоящий IPv6 HTTPS не проверен: Telegram не дал AAAA; другие LAN topology требуют отдельной проверки |
| WARP MASQUE/USQUE | База · main; новый HIL · неустойчиво | Новый собственный профиль: первый H2/H3 прогон по две PASS; финальный повтор дал смешанные PASS/ошибки; cleanup и отрицательный контроль прошли | Две устойчивые подтверждённые попытки и полный client path; текущие данные не разрешают promotion |
| WARP WireGuard | Native generation/reuse/migration/backup · Роутер; scanner · безопасный отказ | Один POST и staged-only; copy-only migration/reuse без нового POST; encrypted export/preview/import сохранил image и applied state, runtime STOPPED; четыре порта дали trace-request-failed | Успешный exact tunnel/service HIL; install lifecycle итогового artifact |
| AmneziaWG | Реализовано · CI · Экспериментально | Импорт/валидация и адаптер транзакции | Отдельный аппаратный canary и compatibility registry |
| DNS | Реализовано · CI · Экспериментально | Типизированный каталог, read-only probe, scoped drafts и negative control | Полный live-adapter с recovery gate |
| Source Hub и PF1 | База · main · CI; PF1 UI · Роутер | Ручной preset/HTTPS sync, строгие parser/partial consent/dedup и лимиты; фактический UI сохранил 4 unchecked узла без Apply; origin/health не продлеваются от 304 | Персистентный subscription CRUD, scheduler и отдельные check/switch opt-ins; они не нужны для ручного MVP |
| Автопилот | Реализовано · CI · Экспериментально | Ограниченная сверка применённых AUTO-сервисов; черновики и явные маршруты не меняются | Evidence v2, shadow mode, HIL и защита от flapping |
| Web UI | PR-NFQ0/PR-NFQ1 · main · CI; NB1/PF1 · Роутер | Фактические A/B check/preview/Apply с PC HTTP 200, сохранность нового WARP draft; feed import без auto-Apply | Новая сборка с backup/boot recovery требует финального аппаратного повторения; модули, i18n и accessibility — следующие улучшения |
| Другие платформы | Проектирование | Capability-модель описана в roadmap | OpenWrt/GL.iNet/Asuswrt adapters и отдельная HIL-матрица |

## Проверки базового релиза

- CI `main`: [успешно](https://github.com/ArtixSx/RAZVILKA/actions/runs/33297901023).
- Release `v0.18.0`: [успешно](https://github.com/ArtixSx/RAZVILKA/actions/runs/33297901840).
- Keenetic ARM64: RAZVILKA `0.18.0`, dataplane `committed`, NFQWS2 process
  running, runtime-списки `0644`, YouTube `generate_204` вернул `204`.
- WARP WireGuard на этой сети: официальный UDP-набор проверен, handshake не
  подтверждён; кандидат удалён, рабочий маршрут не изменён. Это доказанный
  безопасный отказ, а не доказательство работы WARP.

## Известные ограничения

Текущий read-only NFQ snapshot нужно отличать от исторического baseline выше:
применённых NFQ services/routes сейчас 0, но процесс `nfqws2` обнаружен один
(`.hil/production-nfq-current-process-count.json`, 2026-09-06 12:56:37 UTC).
Прежние journals/config snapshots не являются командой вернуть старые managed
блоки. Наличие процесса отдельно не доказывает владение им или текущий service
flow; старый HIL не переносится на сегодняшнюю конфигурацию.

1. Не каждый service probe уже использует строгую семантику Evidence v2.
   Открытый порт, запущенный процесс или произвольный HTTP-ответ нельзя считать
   подтверждением сервиса.
2. NFQWS2 пока частично остаётся внешним supervised-компонентом.
3. Публичные VLESS-источники являются недоверенными кандидатами. Их TCP-статус
   не доказывает VLESS/Reality handshake, egress или доступность сервиса.
4. Успешная аппаратная поддержка сейчас заявлена только для эталонного Keenetic
   ARM64. Остальные сборки существуют, но требуют отдельного HIL.
5. Автопилот остаётся ограниченной экспериментальной функцией и не имеет права
   включать community proxy, менять глобальный DNS или регистрировать аккаунты.

## Локальный NET1 и аппаратная проверка 6 сентября

Этот подраздел фиксирует ранний изолированный NET1-прогон. Более поздние
запуски development candidate, публичных узлов и WARP описаны ниже и не
подменяют его исходный baseline.

[NET1](NET1_2026-09-06_RU.md) связывает exact proof, node/group plan и AUTO/TestLab
наблюдения с текущей сетевой сессией. Активные решения получают свежий снимок;
пассивный десятисекундный кэш не даёт права сохранять proof или применять план.
Unknown, потеря наблюдателя и наблюдаемая смена сети отзывают старую identity.
Скрытый DNS upstream локального forwarder остаётся вне этой гарантии.

На Netcraze ARM64 прошёл финальный systemprobe test binary: Fresh на `eth3`
стабилен, изменения и замена временных DNS-файлов обнаруживаются. Изолированный
network namespace недоступен; реальный WAN reconnect **не проверен**.
Два разных собственных VLESS дали DNS PASS и transport timeout за 3 секунды;
очистка прошла. Они не подтвердили protocol/egress/service, поэтому gate
переключения между двумя рабочими узлами остаётся открытым.

Рабочий daemon не менялся; запускались только собственные временные test
binaries. Снятая база: SafeMode=true, revision=64, appliedRevision=62; drafts
сохранены. Финальный Go suite (44 пакета), vet, девять UI/supervision scripts и
четыре Linux architecture builds прошли. На ARM64 также прошли NET1 lifecycle
tests с подставными адаптерами, включая отмену и cleanup. Linux/race остаётся
открытым; эти тесты не заменяют live node failover.
Это локальная реализация с частичным HIL, без нового CI/release.

## Продолжение 6 сентября: ручной пользовательский сценарий

NB1 и PF1 уже реализованы локально; начинать их заново не требуется. Получение
feed, точная проверка узла и применение к одному сервису — отдельные действия.
NB1 использует существующую транзакцию, краткоживущий одноразовый review и
повторные проверки полномочий. Кроме точного PC /32, отдельный all-LAN HIL
подтвердил scope только наблюдаемых Linux bridge и назначенных private IPv4/ULA
connected prefixes: 28 правил, 6 IPv6 kernel route checks, PC IPv4 HTTP 200,
WAN-source/ingress negative, counters и cleanup/global-file preservation PASS.
Настоящий IPv6 HTTPS не подтверждён: у Telegram не наблюдалось AAAA.

После недоступности двух прежних собственных VLESS три публичных кандидата
прошли exact API/service checks на роутере. Initial A commit тоже прошёл, но
первый запрос с компьютера не прошёл: локальная проверка прокси скрыла проблему
system-stack TUN и router forwarding. Исправлены gVisor/exact-outbound gate и
собственные FORWARD/NAT правила. Финальный native lifecycle HIL прошёл:

- Два VLESS с разными server endpoints, но одинаковым наблюдаемым egress,
  прошли exact checks. Это не доказательство независимости провайдеров выхода.
- Native commit A → PC Telegram HTTP 200; B активирован и прошёл штатный health,
  после чего контролируемая ошибка вызвала rollback A. Config/journal/runtime
  hashes восстановлены, повторный native health A и PC HTTP 200 прошли.
- Обычный commit B тоже завершился PC HTTP 200. Маршрут выбранного PC проходит
  через TUN, маршрут контрольного второго PC — нет; счётчики TUN растут.
- Cleanup checker/adapter/kernel resources и сохранность hashes/mode/mtime
  исходных глобальных файлов — PASS. Проверялся настоящий бинарник с gVisor
  и собственными filter/NAT правилами, без внешних временных разрешений.

Локальный EngineLab false blocker для собственных endpoint-exclusion rules
исправлен точным сопоставлением private policy; чужие похожие правила не
игнорируются. Финальное повторение через **фактический UI** прошло:
A check → preview → Apply → PC HTTP 200, затем B check при активном A →
preview → Apply → PC HTTP 200; новый посторонний WARP draft сохранился.
Артефакты: `.hil/candidate-ui-lifecycle.json`, `.hil/native-lan-lifecycle-2-results.json`.
PF1 через UI импортировал 4 узла в ожидании проверки без автоматического Apply.

[Встроенный WARP generator](WARP_CANDIDATE_HARNESS_RU.md) готов локально и
прошёл unit/API/UI tests. Native registration выполняет один POST; pending
checkpoint переживает рестарт, повторное действие восстанавливает тот же
аккаунт offline либо сообщает неопределённый исход без новой регистрации.
`fresh=false` переиспользует валидированный аккаунт. Старые аккаунты и рабочий
профиль сохраняются, новый профиль только staged. Обычный app API на роутере
выполнил один реальный POST; reuse с `accept_tos=false` сохранил account/profile
hash и одну attempt-директорию без нового POST (`.hil/warp-native-app-hil.json`).
Новый [canonical private backup/restore](NATIVE_WARP_BACKUP_RESTORE_RU.md)
включает current/pending/original key/raw response/provider history в общий
зашифрованный архив. Импорт старой копии не стирает более новый pending;
координированные rollback и process-crash recovery локально прошли. Аппаратная
legacy → canonical миграция тоже PASS с неизменными исходными legacy/profile/key
hashes (`.hil/native-migration-router-results.json`). Общий encrypted
export/preview/import в отдельный control plane тоже PASS: canonical SHA равен
исходному, account зарегистрирован, offline reuse не меняет image,
AppliedServices/AppliedRevision неизменны, runtime STOPPED
(`.hil/native-backup-router-results.json`).

Новые реальные WG/MASQUE регистрации выполнены с отдельного разрешения
пользователя. WG не подтвердился на четырёх выданных портах. MASQUE сначала
прошёл H2/H3, но окончательный повтор дал по одной PASS и по одной ошибке на
transport: `working_modes=[]`, общий `ok=false`. Очистка и negative controls
прошли. Это не готовый устойчивый резервный маршрут и не основание AUTO.

Проверки native generator: полный Go suite `warp/cloudflareprovider/app`, vet,
UI recovery/generation script, JS syntax и ARM64 cross-build — PASS. Новые
локальные результаты не наследуют CI базового SHA. Короткий перечень оставшихся
MVP gates находится в начале [актуального roadmap](ROADMAP_2026-08-30_RU.md).
Реальный Windows/amd64 race detector прошёл проверку намеренной гонкой, затем
**полный `go test -race ./...`** (`.hil/race/final-full-windows.jsonl`). Полные
обычные tests/vet, 12 UI и 2 supervision проверки и четыре Linux cross-build
прошли для снимка до последующих recovery/cleanup исправлений. Оба Go suites:
47 пакетов, 1519 успешных тестов и 16 ожидаемых platform/helper skips.
ARM64 SHA-256 этого проверенного снимка, а не будущего release artifact:
`48f3e1efab048b0f5f8f3ce8948283b62e94e6fd53547370724ae9eaab89a34c`.
Это не Linux-specific race: Linux sysfs/rtnetlink ветви под Windows
detector не выполнялись. Новый CI итогового commit отдельно не объявлен.

ARM64 read-only NET1, DNS file ABA/replacement и underlay event tests тоже
прошли (`.hil/final-net1-readonly-router.json`). Они не имитируют настоящий
WAN disconnect и не заменяют его HIL. Полный installer lifecycle на снимке
`48f3e1ef…` прошёл в изолированном BASE: upgrade/rollback, conflict/corrupt
restore, отказ при неудачной остановке и uninstall; собственные процессы и
временные файлы убраны, глобальные файлы и kernel state сохранены
(`.hil/final-entware-results.json`). Более поздние исправления требуют новой
сборки и её ограниченного installer smoke; финальный релизный SHA пока не задан.

WARP/AWG cleanup теперь требует собственную policy/runtime пару с точным
interface/config digest. Нет файлов — нет kernel-команд; partial/corrupt или
hashless state сохраняется с отказом. Runtime-only не разрешает удалять чужой
интерфейс после неудачного старта. Полные dataplane tests/vet прошли локально;
[граница владения](WARP_CANDIDATE_HARNESS_RU.md#остановка-адаптера-и-подтверждение-владения).
Native upgrade/rollback проверяет schema capability также для legacy markers
и файла restore journal, включая повтор после recovery; подробный
[контракт сохранности](NATIVE_WARP_BACKUP_RESTORE_RU.md).

## История разработки после стабильного релиза

Следующие записи сохраняют формулировки на момент выполнения. Описанный код
уже находится в проверенном main, если явно не отнесён к повторному аудиту.
HIL ниже — результаты прежних работ из документации, не измерения этого аудита.
В [общей переписке](https://chatgpt.com/s/cx_6a9d30dddd048191b05c838956e6b490)
последнее сообщение также сообщает обновление роутера до `0.18.1-dev`, Telegram
HTTP 200 и `warp=on`, но Safe Mode оставлен включённым со старым
`rollback-failed`. Это не закрывает gate нового managed apply и не является
повторной проверкой текущего состояния роутера.

PR-NFQ0 зафиксировал read-only baseline нативного NFQWS2, внешнего z2k и
отсутствующего движка. PR-NFQ1 локально разделяет выбранное, рассчитанное,
применённое и подтверждённое состояние, добавляет Lite/Pro и честную панель
NFQWS2 без изменения route behavior. Gap следующего read-only этапа описан в
[NFQWS2_PR_NFQ1_GAP_RU.md](NFQWS2_PR_NFQ1_GAP_RU.md).

На эталонном роутере отдельно подтверждён `HTTP 200` Telegram через работающий
USQUE `opkgtun0`. Ошибка выбора RAZVILKA происходила до canary: legacy staging
USQUE был `0755`, а приватный reader требует `0700`. Каталог исправлен на роутере,
а startup/upgrade теперь безопасно нормализуют только allowlist каталогов
RAZVILKA. Позже процесс и TUN оставались видимыми, но exact-запросы начали
завершаться timeout; штатный restart вернул Telegram `HTTP 200` и Cloudflare
`warp=on`. Это подтверждает необходимость exact canary вместо проверки PID.
Повторный managed apply пока не считается пройденным.

Подключён [online-журнал приватного импорта](PRIVATE_RESTORE_ONLINE_RU.md):
Store sessions проверяют startup bindings, журнал сохраняется до обновления
кэшей, неопределённый исход закрывает новые API/фоновые операции до recovery.
HTTP больше не использует прежнюю компенсацию; ProviderSnapshots по-прежнему
отклоняются. Принудительные process-crash tests и проверки кэшей прошли на Windows.
Health/S99 отличают временную занятость от ошибки и не требуют restart из-за
импорта. Добавлен [протокол upgrade/rollback](PRIVATE_RESTORE_UPDATE_PROTOCOL_RU.md):
stop и recovery выполняются до snapshot, staging и Cloudflare private copies
входят в снимок, manifest завершается последним, а rollback не игнорирует ошибку
остановки и не заменяет журнал. Windows Go/JS/shell-ветки прошли. На Keenetic
ARM64 подтверждён цикл `0.18.0 → 0.18.1-dev → 0.18.0`: health обоих запусков,
точный возврат staging, удаление созданного provider-каталога и сохранение idle
journal. **До релиза обязательны Linux/race, MIPS/MIPSel и аварийная матрица**.
Полный изолированный Entware regression на
том же ARM64 (fresh/update/rollback/conflict/incomplete snapshot/uninstall) тоже
прошёл; отдельный fault-run подтвердил fail-closed при живом PID после stop и
повреждённом journal. Изменения локальные, не новый стабильный релиз.

Добавлена [общая блокировка операций при приватном импорте](PRIVATE_RESTORE_OPERATION_GATE_RU.md).
HTTP (включая GET discovery), фоновые проверки и conntrack не пересекаются с
импортом. Занятая система отказывает до изменений; UI отличает такой отказ от
неудачного восстановления. Отмена запроса не освобождает ещё работающую операцию.
Проверки прошли локально, новые concurrency-сценарии — десять повторов.
Это in-process ownership; следующий online-блок выше добавил журнал/Store sessions.

Добавлен [общий offline coordinator и startup recovery](PRIVATE_RESTORE_COORDINATOR_RU.md).
Пять типов хранилищ объединены в ограниченную транзакцию с проверкой всех целей
до отката. `main` восстанавливает журнал до загрузки config/Store и создания
токена; второй новый экземпляр исключён lifetime lease. Реальные аварийные
тесты и пять повторов прошли на Windows; Linux-сборки только скомпилированы.
HTTP-импорт теперь использует online coordinator, ProviderSnapshots в нём запрещены.
Admission, Store sessions, согласование кэшей и online journal подключены;
полный аудит upgrade/rollback остаётся обязательным.

Добавлен [Cloudflare recovery adapter](CLOUDFLARE_RESTORE_ADAPTER_RU.md):
общая с обычным импортом `.import.lock`, bounded exact-byte CAS, merge без
активации и явная ошибка неподтверждённой записи. Реальные process-crash tests
проверяют возврат файла/его отсутствия и защиту последующей правки. Ёмкость
обычного provider Store сохранена; образ общего журнала ограничен 4 МиБ.
Он включён в общий offline coordinator и recovery до загрузки Store/API.
Общий импорт ProviderSnapshots пока закрыт; роутер не менялся.

Добавлен [адаптер черновиков обходов](ENGINE_DRAFT_RESTORE_RU.md):
editor/import/discard разделяют per-file lease, пакетный откат учитывает ошибку
после фактической записи, есть guarded post-success undo. Аварийный тест проверяет
возврат отсутствующих, пустых и незавершённых draft-файлов. Секретный Content
исключён из результата batch stage. Startup coordinator подключён локально;
новый journal ещё не используется production HTTP-импортом.

Добавлены [адаптеры каталога и устройств](REGISTRY_RESTORE_ADAPTERS_RU.md).
Обычные writers этих реестров используют per-file OS lease и сравнение исходных
байтов. Ошибка сохранения discovery больше не скрывается в панели. Аварийный
тест трёх настоящих хранилищ проверяет recovery до загрузки кэшей и отказ при
неизвестной внешней правке. Main recovery включён локально; общий online App
restore, Linux/HIL ещё требуются.

Добавлен [адаптер конфигурации для журнала](CONFIG_RESTORE_ADAPTER_RU.md).
Обычные записи config уже используют per-file OS lock и сравнение исходных
байтов: устаревший Store не затирает новую правку. Настоящее восстановление config
до загрузки кэша проверено в аварийных тестах и включено в main. Общий HTTP
coordinator и HIL остаются.

Добавлена [основа журнала восстановления импорта](PRIVATE_RESTORE_JOURNAL_RU.md):
before/after, commit decision, повторный откат после сбоя процесса и отказ
затирать неизвестное состояние. Реальные аварийные сценарии проверены локально
на синтетических файлах, затем с реальными адаптерами в offline coordinator.
Startup подключён; нужны online-владение изменениями и Linux/HIL. UI-импорт пока не получил
автоматическое восстановление после перезапуска.

Исправлен [откат общего приватного импорта](PRIVATE_BACKUP_GUARDED_RESTORE_RU.md):
отмена не перезаписывает более новые правки через те же хранилища, ошибки
возврата файлов больше не скрываются, UI различает откат и неподтверждённый
результат. Это компенсация внутри процесса, не crash recovery и не общий
router+provider restore. Полный локальный Go/JS-прогон прошёл; Linux runtime/HIL
ещё требуются.

Добавлен [writer recovery копий Cloudflare](CLOUDFLARE_WRITER_RECOVERY_RU.md):
системная блокировка освобождается после сбоя процесса без удаления постоянного
lock-файла. Проверены аварийное завершение до/после commit и конкурирующие Store
на Windows. Старые неизвестные lock, Linux/race, power-loss/HIL и общая
транзакция router+provider требуют отдельной работы. Это не восстановление
подключения WARP/USQUE и не изменение опубликованной версии.

Добавлено [явное копирование старых профилей с роутера](CLOUDFLARE_LOCAL_MIGRATION_RU.md):
фиксированные источники, повторная проверка содержимого перед записью, сохранение
исходника и изоляция отдельного config. Это copy-only миграция, не передача
владения работающим WARP/USQUE и не подтверждение связи.

Новое локальное продолжение PR-1.1: [отдельный архив копий Cloudflare](CLOUDFLARE_COPY_BACKUP_RU.md)
в API/UI — шифрованная выгрузка, предварительная проверка, атомарное добавление
без замены существующих ключей и общий лимит HTTP-криптоопераций архивов.
Это не общий restore роутера, не регистрация и не активация WARP.

PR-0.1 сохранён локальным commit `5522735`. В PR-0.2 добавлен общий строгий
HTTP-классификатор, отрицательные fixtures, защита от повышения неподтверждённых
результатов и понятные итоги в UI. Это локально тестируемая разработка
`0.18.1-dev`, не новая аппаратно подтверждённая версия.

Уточнение после публикации: PR-0.1 и PR-0.2 теперь входят в `v0.18.1-rc.1`.
[Linux CI](https://github.com/ArtixSx/RAZVILKA/actions/runs/33333075931) прошёл,
включая race detector, реальные `/proc`/дочерние процессы и сборки четырёх архитектур.
Архив, контрольные суммы и подпись GitHub attestation проверены локально.
Аппаратная проверка новых изменений остаётся незавершённой.

Локальный блок PR-0.3 (`7d9e6b1`): ограничения диагностических процессов,
loopback-only проверочные порты, исправление проверки имён Sing-box/Xray,
защита временных каталогов и записей — [отчёт](PR_0_3_SAFETY_RU.md).

Локальный PR-0.4: защищённая загрузка источников, атомарный receipt, TTL,
карантин и LKG; автопилот не меняет область маршрута вместе с обновлением
списка. Подробности и оставшиеся ограничения — [отчёт](PR_0_4_SOURCE_TRUST_RU.md).
Оба блока на GitHub в ходе этой работы не публиковались.

PR-1.1 начат отдельно: [пассивная основа Cloudflare Provider](CLOUDFLARE_PROVIDER_FOUNDATION_RU.md)
с публичной моделью, импортом копий WG/USQUE и ограниченным приватным хранилищем.
Миграция рабочего состояния и регистрация ещё не подключены.
Продолжение PR-1.1: сверены и добавлены адаптеры USQUE/wgcf, распознавание
архивных неподдержанных форматов, encrypted backup и атомарное объединение копий
при restore — [детали и ограничения](CLOUDFLARE_LEGACY_IMPORT_RU.md).
Следующий локальный блок подключил аутентифицированные preview/import/list API
и свёрнутый раздел копий в «Настройки». Он не активирует обходы, не включает
копии в общий backup и не меняет маршруты — [API/UI и проверки](CLOUDFLARE_COPY_UI_RU.md).

Область изменения и оставшиеся gates (включая независимый direct-leak control
для внешних туннелей) описаны в [PR_0_2_GAP_REPORT_RU.md](PR_0_2_GAP_REPORT_RU.md).

Продолжение PR-0.2: добавлен локальный паспорт управляемого SOCKS-runtime с
проверкой конфигурации, процесса и владельца порта. Потеря этого подтверждения
отзывает прежний успех в Smart Route. Это **не** независимое доказательство
удалённого egress. Область поддержки, проверки и ограничения зафиксированы в
[ROUTE_PASSPORT_LOCAL_RU.md](ROUTE_PASSPORT_LOCAL_RU.md).

## Исторические записи реализации

Новый приоритет редакции плана от 2026-09-05: безопасность импорта отдельных
узлов. Локально реализован [PR-N0.1](PR_N0_1_VLESS_IMPORT_RU.md): неизвестный
VLESS transport/security/flow/packet encoding отклоняется, XHTTP не превращается
в TCP, неоднозначные query/JSON и insecure VLESS запрещены. URI/Base64/native
JSON/Clash используют согласованную проверку. Ошибка API не меняет старый
черновик. Go tests/vet и 20-секундный fuzz прошли на Windows. На роутер и GitHub
изменения не загружались. Локально добавлен [N0.2](PR_N0_2_PARTIAL_IMPORT_RU.md):
частичный импорт, причины отказов без ключей, дедупликация, защита старого черновика
и одна явно подписанная кнопка сохранения принятых узлов. Неподдерживаемые записи
изолируются в отчёте; постоянного retry quarantine ещё нет. Добавлена
[основа NodeStore N1.1](NODESTORE_FOUNDATION_RU.md): приватное атомарное хранение,
stable ID, provenance/TTL, lease и copy-only migration helper. Она подключена к
startup и безопасному read-only API/UI, но не к рабочим маршрутам; health
остаётся `not_checked`.
Добавлен [N1.1b backup/restore lifecycle](NODESTORE_BACKUP_RESTORE_RU.md): узлы
входят в типизированный зашифрованный payload, восстанавливаются с merge и
участвуют в общей journal-транзакции с rollback/process-crash recovery. NodeStore
подключён к startup и общему export/preview/import; пустое хранилище не создаёт
документ. Старый и новый журналы имеют раздельные scope и lifetime lease. Узкий
Cloudflare restore отклоняет смешанный архив.
Подготовлена N1.2: `/api/v1/nodes` и отдельная страница «Узлы»
показывают только безопасные карточки, источник, срок и счётчики; есть поиск и
фильтр. Все записи остаются недоступными для выбора (`selectable=0`), UI прямо
отделяет импорт от проверки работоспособности. URI, endpoint, SNI, UUID, пароли
и SecretRef обычный ответ и страница не содержат. Alias, disable и атомарное
delete подключены; reveal требует подтверждения, возвращается с `no-store` и
очищается интерфейсом после закрытия. Отдельная кнопка сохраняет все принятые
записи в NodeStore, не создавая маршрут и не запуская Sing-box. Схема 1 читается
без фоновой записи и переходит на актуальную схему только при явном изменении.
Локально завершён [N1.3 Exact Node Checker](EXACT_NODE_CHECKER_RU.md): отдельный
Sing-box outbound проверяется через изолированный loopback runtime, закреплённый
публичный адрес, паспорт процесса, IP выхода, direct-leak control и catalog-owned
canary выбранного сервиса. Результат хранится с TTL и профилем сети; UI показывает
IP и понятную стадию. На Keenetic ARM64 подтверждён полный VLESS → Sing-box → Telegram
сценарий с отличающимся egress IP и очисткой. Для старого ядра без `ns/net`
добавлен узкий fail-closed fallback; подробности зафиксированы в отчёте N1.3.
Локально завершён [N1.4](NODE_SCOPED_ROUTES_RU.md): проверенный узел или группа
появляются только у доказанного сервиса и текущей сети; fallback удерживает
последний рабочий узел, приватная конфигурация создаётся внутри транзакции, а
адреса её серверов получают прямые исключения от самозацикливания. Более новый
отказ отзывает старый PASS. Аппаратная проверка переключения и отката ещё не
выполнена, поэтому стабильный релиз не публикуется.
Linux race и отдельный HIL Reality/Hysteria2/TUIC ещё не выполнены.
Оставшаяся работа Cloudflare/USQUE ниже сохраняется
в backlog. [Автообновление публичных источников](PUBLIC_PROVIDER_SOURCES_RU.md)
добавлено в план как opt-in после этих зависимостей, без скрытой смены маршрута.
По разрешению пользователя отдельно проверен импорт 32 публичных ссылок:
28 разобраны, 4 безопасно отклонены. Никаких соединений с proxy-узлами,
сохранения ключей или переключения маршрутов не выполнялось. Это parser smoke,
не подтверждение работоспособности VLESS. Race на Windows недоступен без CGO.

Локально завершён безопасный ремонт известного конфликта `ndmc` в init-скрипте
USQUE. Doctor сначала выполняет read-only распознавание; действие появляется
только для однозначной старой формы и требует отдельного подтверждения. Перед
записью создаётся закрытая точная копия, изменение проводится через постоянный
журнал и проверяется `sh -n` и `ndmc` с системными библиотеками. Любая ошибка
возвращает исходный файл, а незавершённая операция разбирается до HTTP и фоновых
задач. Служба USQUE, DNS, сессия и маршруты автоматически не меняются. Реальный
роутер проверен read-only: его текущий `S51usque` уже содержит два корректно
изолированных вызова, поэтому ремонт на нём не нужен. Подробности:
[USQUE_NDMC_SAFE_REPAIR_RU.md](USQUE_NDMC_SAFE_REPAIR_RU.md).
Изолированный ARM64-набор нового ремонта также полностью прошёл на роутере;
временный бинарник удалён, рабочая версия и её состояние не менялись.

Doctor также получил безопасную проверку bootstrap до регистрации USQUE:
достоверность часов, наличие CA bundle, разрешённый публичный HTTPS endpoint,
публичность всех DNS-ответов и TLS/HTTP. В интерфейсе эти причины собраны в
короткий блок «До регистрации»; точные DNS-адреса не отображаются и не
сохраняются. Проверка не использует proxy из окружения и не меняет системный
DNS. В Doctor добавлена отдельная проверка имени регистрации через выбранный
DNS-профиль, без изменения рабочего резолвера. Проверяются A/AAAA и доступные
UDP/TCP/DoH/DoT endpoint; FlashStart не допускается. Проверка TLS через выбранный
DNS, NFQWS2-кандидат и новая регистрация остаются следующим этапом.
На Keenetic ARM64 прошёл [отдельный аппаратный DNS-тест](USQUE_DNS_CANDIDATE_RU.md):
Quad9 unfiltered вернул публичные ответы по UDP/TCP/DoT; DoH не прошёл.
Рабочая RAZVILKA `0.18.0` и её процесс не менялись. Это проверка DNS, не WARP.

Начат PR-1.2: [локальный Cloudflare registrar](CLOUDFLARE_LOCAL_REGISTRAR_RU.md)
создаёт X25519-ключ внутри процесса и передаёт mock API только публичную часть.
Ответ строго проверяется, а публичный кандидат не содержит private key, device
ID или access token и честно имеет состояние `registered-unverified`. Реального
Cloudflare endpoint, сохранения кандидата, UI и запуска транспорта в этом блоке
нет; это тестируемый контракт для следующего адаптера, а не работающий WARP.
Registrar-тесты также прошли на ARM64 Keenetic без системных изменений.
Следующий локальный срез добавил неактивное атомарное сохранение такого
кандидата и round-trip через зашифрованный private backup. Публичный импорт не
может выдать произвольный профиль за `local-registration`; восстановленная
запись остаётся неподтверждённой и не запускается.

Этот расширенный набор также прошёл на ARM64 Keenetic, включая шифрованный
round-trip; временный тест удалён.

Следующий слой добавляет least-privilege доступ к tunnel material локального
кандидата: только через ограниченный внутренний callback, без account token,
публичного API, файла экспорта или запуска транспорта. Пассивный импорт не
получает эту возможность автоматически.
Контракт проверен непосредственно на ARM64 Keenetic; временный тест удалён,
рабочая версия осталась `0.18.0`.

На этом основании добавлен чисто временный
[WireGuard candidate builder](CLOUDFLARE_WIREGUARD_CANDIDATE_RU.md): bounded
endpoint/MTU/keepalive, без DNS и hooks, с redacted preview и истекающим
секретным lease. Он пока не создаёт интерфейс и не является проверкой WARP.
Его тесты прошли на ARM64 Keenetic без перезапуска установленной `0.18.0`;
временный бинарник удалён.

Для следующего шага добавлена строгая
[модель доказательств Endpoint Scanner](CLOUDFLARE_ENDPOINT_SCANNER_EVIDENCE_RU.md).
Она требует handshake, отдельный egress, `warp=on`, точный service route, MTU и
cleanup минимум в двух попытках; сетевого runner и нового рабочего маршрута пока
нет.
Evaluator прошёл на ARM64 Keenetic, включая все отрицательные сценарии; это был
локальный тест модели без сетевых мутаций, временный бинарник удалён.
Строгий trace parser также подключён к прежнему WARP WireGuard canary вместо
простого поиска `warp=on`; это усиливает существующий Apply, но ещё не заменяет
полный новый Scanner.
Для нового Scanner добавлен bounded orchestrator двух-трёх последовательных
attempts с per-attempt timeout, jitter, cancellation, immutable identity и
немедленной остановкой после неподтверждённого cleanup. Реальный runner ещё не
подключён.
Контракт orchestrator также прошёл на ARM64 Keenetic, включая позднюю ошибку
после двух PASS; она не была повышена до `verified`. Временный тест удалён.

Добавлен версионированный
[официальный каталог WARP endpoints](CLOUDFLARE_ENDPOINT_CATALOG_RU.md), который
различает consumer/Zero Trust и registrar-issued значения. Он только аннотирует
кандидата и не выполняет discovery или сетевые изменения.
Каталог и новый candidate fingerprint прошли на ARM64 Keenetic; временный тест
удалён, установленная `0.18.0` не перезапускалась.

Добавлена непостоянная модель endpoint health: Evidence TTL, score, failure
cooldown `1/5/30` минут, запрет наследовать подтверждение между разными
candidate identity и невозможность восстановить trusted state из публичного
JSON. Persist/LKG подключатся только вместе с журналом Scanner.
Модель endpoint health прошла ARM64 gate на Keenetic: TTL boundary, backoff
`1/5/30`, reset после success, forged JSON, changed identity и cleanup zero-score.
Временный тест удалён; установленная `0.18.0` не перезапускалась.

Добавлен [приватный журнал Endpoint Health](CLOUDFLARE_ENDPOINT_HEALTH_JOURNAL_RU.md):
bounded schema/generation, строгий decode, account material binding, общий
Provider writer lock, atomic commit и fail-closed startup при повреждении.
`ScanAndRecord` сохраняет PASS только после durable commit, а отрицательный scan
— как cooldown. Health не экспортируется и после restore требует новой проверки.
Restart/TTL, cooldown, changed identity, forged report, corrupt startup и
`ScanAndRecord` прошли ARM64 gate; временный тест удалён, `0.18.0` не менялась.

Подготовлен source-bound HTTP-слой будущего Cloudflare runner: независимый direct
trace, строгий WARP trace и Evidence v2 для exact service route. Он fail-closed
на blocked/ambiguous/unsafe ответах, не ослабляет TLS и переиспользует защищённый
client прежнего WARP canary. ARM64 gate пройден без сетевых мутаций; реальный
временный интерфейс ещё не подключён.

Исправлена граница ownership прежнего WARP canary: cleanup удаляет source rule и
интерфейс только после доказанного успешного создания именно этой попыткой.
Ошибка/гонка во время старта больше не позволяет удалить появившийся чужой или
неопределённый интерфейс. Позитивный cleanup и uncertain-start прошли ARM64 gate.

Добавлен изолированный Cloudflare Scan runner: owned-интерфейс `rz-cf-scan`,
отдельная table `220`, source-only rule, приватный одноразовый конфиг,
межпроцессная OS-блокировка и fail-closed cleanup. Он собирает strict HTTP,
handshake и MTU evidence, но пока не подключён к UI/AUTO. Полный project test и
vet прошли; ownership, cleanup failure, lock contention и timestamp validation
проверены на ARM64 Keenetic без настоящих сетевых мутаций. Следующий gate — live
кандидат и Cloudflare/Telegram HIL в поддерживаемой сети.

Подготовлена [разовая проверка явно выбранного WARP WireGuard-профиля](CLOUDFLARE_REVIEWED_WIREGUARD_SCAN_RU.md):
passive copy не получает runtime capability, ключи живут только внутри callback,
а bounded Scanner не сохраняет health и не включает Apply/AUTO. Небезопасные
endpoint/PSK/маршруты и занятый tunnel address отклоняются до старта. Контракт
прошёл полный test/vet и ARM64 platform gate; live Cloudflare HIL всё ещё нужен.

Hostname endpoint теперь не резолвится скрыто при запуске: отдельный краткоживущий
DNS-preview показывает публичные IP, пользователь pin-ит один из них, после чего
Scanner работает только с literal. Mixed private DNS, изменённый профиль,
истёкший/восстановленный/отредактированный preview и неподтверждённый адрес
отклоняются. UI этого review ещё не подключён.

Порядок дальнейшей разработки находится в
[ROADMAP_2026-08-30_RU.md](ROADMAP_2026-08-30_RU.md). Формулировки о «первом
live scan» и будущем NB1 выше относятся к прежним срезам: новый HIL и ручной
сценарий отражены в разделе «Продолжение 6 сентября» этого документа.
