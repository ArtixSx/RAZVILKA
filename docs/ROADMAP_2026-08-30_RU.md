# Актуальный roadmap RAZVILKA

Дата пересмотра: 5 сентября 2026 года<br>
База: стабильный `v0.18.0`, commit `8fa1d61914cb7fcfb354259408e18ce1dc72e354`

Этот roadmap переносит порядок единого master-plan на фактическую историю
версий. Опубликованный `v0.18.0` не переименовывается, поэтому номера будущих
этапов сдвинуты, но зависимости и требования безопасности сохранены.

## Приоритет редакции 2026-09-05

Повторно изучена редакция 9 пользовательского master-plan от 5 сентября
(SHA-256 исходного файла
`33e814d28b16024ff1b2753e6e5d57b11ffcd2453be0689b1782d41d519ed602`).
Оперативными считаются раздел 47, затем раздел 33 и неизменяемые ограничения
раздела 4. Статусы и commit из приложенного документа являются снимком момента
его подготовки: фактическая локальная линия уже содержит более поздние этапы
NodeStore, поэтому готовность определяется кодом, тестами и этим roadmap.

Новая редакция добавляет обязательные gates, не меняя порядок разработки:

- внешний TCP connect/latency имеет уровень
  `tcp_reachable_from_github_runner`, но не `working` и не protocol-ready;
- `warp-gen.github.io` считается мёртвым шаблоном; его нельзя предлагать как
  рабочий источник;
- новый WARP binary без ожидаемого digest или доступного verifier всегда
  помещается в quarantine и не запускается;
- WARP `ready`, `routed`, IPv4 и IPv6 отображаются раздельно; mark/table/rules
  требуют owner lease и проверки коллизий;
- для будущего NFQWS2-подбора обязательны типизированный `ProbeIntent`,
  round-trip Strategy Fidelity, direct gate и проверка ответного направления;
- GitHub governance остаётся release gate и не смешивается с dataplane-PR.

Разделы 26–37 обновлённого пользовательского master-plan уточняют ближайший
backlog. Выполненные Cloudflare/USQUE блоки не повторяются и не удаляются.
Ближайший порядок: N0.1 строгий VLESS parser → N0.2 поштучный quarantine →
NodeStore/migrations и узлы UI → exact outbound check → node/group bindings →
provider subscriptions → Effective Route Resolver/NFQWS2 ownership →
опциональный Community Hub. Платформы и широкая автоматика остаются после
соответствующих safety/HIL gates.

Локальная реализация N0.1 описана в [контракте импорта](PR_N0_1_VLESS_IMPORT_RU.md).
Добавлен [N0.2: частичный импорт](PR_N0_2_PARTIAL_IMPORT_RU.md) с причинами отказов,
дедупликацией и явным сохранением принятых записей. Persistent quarantine/NodeStore
ещё не реализованы этим блоком.
Подготовлена [основа N1.1 — NodeStore](NODESTORE_FOUNDATION_RU.md): атомарный
приватный документ, локальная идентичность, provenance/TTL и copy-only helper.
Startup lifecycle подключён; API/UI и health promotion ещё отсутствуют, реестр
пока не используется рабочими маршрутами.
Подготовлен [N1.1b — backup/restore lifecycle](NODESTORE_BACKUP_RESTORE_RU.md):
типизированный snapshot внутри зашифрованного архива, merge без удаления более
свежих узлов, общий journal rollback и recovery после смерти процесса. Перед
startup используются отдельный versioned journal и lifetime lease старого
журнала. Общий зашифрованный export/preview/import узлов подключён; следующим
этапом остаются изменяющие операции управления узлами.
N1.2 реализован локально: API и пользовательская страница не раскрывают
приватный материал, показывают источник, срок и честный статус `не проверен`,
не разрешают выбор непроверенных записей. Подтверждённый импорт сохраняет все
принятые записи отдельно от одного выбранного черновика Sing-box. Alias,
disable/delete и reveal имеют отдельные безопасные контракты; reveal требует
подтверждения, запрещает кэширование и очищается UI после закрытия. Миграция
Старые schema 1/2 переходят на schema 3 только при явной записи.
N1.3 Exact Outbound Checker реализован локально и описан в
[отдельном контракте](EXACT_NODE_CHECKER_RU.md): DNS/transport/protocol,
route identity, proxy egress, direct-leak control и сервисный canary сохраняются
с TTL и профилем сети. N1.4 node/group bindings также завершён локально и описан
в [контракте привязок](NODE_SCOPED_ROUTES_RU.md): выбор ограничен exact proof,
fallback удерживает LKG, endpoint идёт напрямую, а транзакционный отказ возвращает
рабочий runtime. Перед стабильным релизом остаётся N1.4 HIL двух реальных узлов.
HTTPS/TLS-canary через выбранный DNS для USQUE сохранён в backlog, но не
смешивается с изменением импортера. Публикация выполняется проверенными
группами изменений, а не на каждый небольшой локальный коммит.

### Синхронизация master-plan редакции 13 от 2026-09-06

После N1.4 следующим обязательным gate остаётся аппаратная проверка двух узлов:
LKG, подтверждённый отказ, переход на резерв, endpoint-exclusion, canary rollback
и восстановление после reboot/WAN reconnect. До неё N1.4 не входит в стабильный
релиз.

Новая оперативная продуктовая очередь после этого gate:

1. `PR-NFQ0` — read-only fixtures/baseline и доказательство независимости от z2k;
2. `PR-NFQ1` — честное разделение Desired/Planned/Applied/Observed без изменения
   route behavior;
3. дальнейшая нативная очередь `PR-NFQ2..NFQ13` по одному этапу, без установки,
   вызова или runtime-зависимости от z2k;
4. отдельная ветка Selective Smart DNS `PR-DNS0..DNS10`, начиная с терминологии,
   schema migration и модели; обычные resolver-профили не выдаются за geo bypass.

NFQWS2 и Smart DNS нельзя смешивать в одном mutation PR. При конфликте маршрута
действует инвариант одного Effective Route и одного владельца потока.

## Неподлежащие нарушению условия

- сохранять рабочий NFQWS2/YouTube baseline и WAN `eth3` эталонного Keenetic;
- не менять одновременно NFQWS2, firewall, DNS и WAN routing;
- не захватывать чужие firewall, DNS, PBR, NFQUEUE, интерфейсы и процессы;
- mutation проходит inventory → plan → validate → snapshot → stage → isolated
  canary → exact-route health → commit/rollback → observe;
- все операции имеют timeout, ограниченную параллельность и cancellation;
- приватные WARP/AWG/WG-ключи создаются локально и не уходят публичным
  генераторам;
- TLS verification не отключается, HTTPS не понижается до HTTP;
- public proxy feeds всегда недоверенные, выключенные и помещённые в карантин;
- TCP-open, ping, process/listener-ready и общий HTTP-код не равны успеху
  сервиса.

## Этап 0 — `v0.18.1` Truth & Safety

1. Единая версия, commit/date/dirty metadata и актуальный статус возможностей.
2. Evidence v2 без ложных PASS на redirect, portal, `403`, `451`, неверный TLS,
   поддельный JSON и direct leak.
3. Loopback-only candidate listeners, process timeout и owned-path guard.
4. Source Hub trust foundation: strict redirect/SSRF, digest, provenance, TTL,
   LKG, quarantine и redaction.

Срез 31 августа: пункты 1–2 опубликованы в `v0.18.1-rc.1`, Linux CI прошёл.
Пункты 3–4 реализованы локально с автоматическими тестами; новые Linux/race
и аппаратные gates ещё не пройдены. Полный Source Hub review/scheduling остаётся
дальнейшей работой. Регистрация аккаунтов и расширение живой автоматики до
подтверждения безопасности не выполняются.

## Этап 1 — `v0.19` Unified Cloudflare Provider

1. Provider model и локальное secret state.
2. Локальная генерация ключей и тестируемый registrar без передачи private key.
3. WARP Configurator generate/import/export без системных мутаций.
4. Endpoint Scanner с реальным handshake, egress, trace и service evidence.
5. Единый USQUE lifecycle и Safe Repair Wizard.
6. AmneziaWG compatibility registry и аппаратный canary.
7. `wgcf` только как явно выбранный import/fallback и compatibility oracle.

Локальный срез 31 августа: модель копий, типизированные legacy imports,
отдельный зашифрованный архив/API/UI и явное copy-only чтение старых профилей
реализованы. Добавлен [writer recovery после сбоя процесса](CLOUDFLARE_WRITER_RECOVERY_RU.md)
без удаления чужих блокировок. Пункт 1 ещё не закрыт полностью: общая транзакция
backup/recovery, secret access contract, lifecycle ownership и Linux/HIL остаются.
Подготовительный [guarded rollback общего приватного импорта](PRIVATE_BACKUP_GUARDED_RESTORE_RU.md)
реализован локально. Следующим блоком добавлена отдельная
[основа журнала](PRIVATE_RESTORE_JOURNAL_RU.md) с process-crash tests. Подключение
[первого config adapter](CONFIG_RESTORE_ADAPTER_RU.md) и защита обычных config
writers выполнены локально. Также готовы [catalog/devices adapters](REGISTRY_RESTORE_ADAPTERS_RU.md)
с защитой обычных записей и crash test трёх реестров; ошибка сохранения discovery
показывается в UI. [Staging adapter и guarded post-success undo](ENGINE_DRAFT_RESTORE_RU.md)
тоже готовы локально, с process-crash тестами. [Provider adapter](CLOUDFLARE_RESTORE_ADAPTER_RU.md)
готов локально: та же `.import.lock`, bounded CAS, merge без активации и аварийные
тесты до OpenStore. [Offline coordinator и startup recovery](PRIVATE_RESTORE_COORDINATOR_RU.md)
реализованы локально: все пять типов хранилищ, порядок leases, восстановление
до Load/API, lifetime gate и process-crash tests. [Online admission](PRIVATE_RESTORE_OPERATION_GATE_RU.md)
подключён к существующему HTTP-импорту, фоновому циклу и conntrack.
[Session-backed online journal и cache handover](PRIVATE_RESTORE_ONLINE_RU.md)
подключены локально: общий HTTP import, проверка bindings, recovery fence,
process-crash tests и busy health/supervision. Следующий обязательный блок —
snapshot после исключения writers, сохранение/совместимость private journal
при upgrade/rollback и Linux/Entware/HIL. Общий HTTP-импорт Provider-архивов
остаётся закрытым; весь PR-1.1 пока не завершён.

Локальное продолжение 1 сентября: добавлен первый слой пункта 2 — X25519-ключ
создаётся внутри Provider, API-контракт получает только публичный ключ, а mock
registrar возвращает неподтверждённого кандидата без публичного представления
private key, device ID или access token. Неактивное сохранение кандидата в
private Store и его encrypted backup/restore затем добавлены. Живой Cloudflare
API и runtime намеренно отсутствуют до golden fixtures и следующих gates.
Для будущего изолированного builder добавлен ограниченный tunnel-material
callback без account credentials; публичный API секретов по-прежнему отсутствует.
Следующий локальный блок добавляет сам inert WireGuard candidate builder с
bounded options и secret lease, но без runtime/route/DNS и без заявления о
handshake. Подробности: [CLOUDFLARE_WIREGUARD_CANDIDATE_RU.md](CLOUDFLARE_WIREGUARD_CANDIDATE_RU.md).
Также готов чистый evaluator
[Endpoint Scanner evidence](CLOUDFLARE_ENDPOINT_SCANNER_EVIDENCE_RU.md), который
не допускает `verified` без двух полных exact-route попыток. Реальный runner/HIL
остаётся следующим gate.
Официальные WireGuard ranges/ports вынесены в отдельный версионированный
[endpoint catalog](CLOUDFLARE_ENDPOINT_CATALOG_RU.md); undocumented registrar
endpoint не блокируется, но не считается официальным или рекомендуемым.
Контракт: [CLOUDFLARE_LOCAL_REGISTRAR_RU.md](CLOUDFLARE_LOCAL_REGISTRAR_RU.md).
TTL/score/cooldown получили непереносимый
[приватный health journal](CLOUDFLARE_ENDPOINT_HEALTH_JOURNAL_RU.md) с material
binding, атомарным commit и строгим startup recovery. Журнал прошёл ARM64 gate;
до появления изолированного runner этот state не подключается к UI или AUTO.
Для runner готов первый dataplane-слой direct/source-bound trace и strict service
Evidence. Изолированный runner теперь владеет временным `rz-cf-scan`, table 220,
source-only policy и cleanup под межпроцессной OS-блокировкой. Platform gate
прошёл на ARM64 с детерминированными системными адаптерами. Реальный Cloudflare
handshake/egress/Telegram HIL ещё обязателен; до него runner не подключается к
UI, AUTO или рабочему Apply.
Явно выбранный пользователем WireGuard-файл теперь можно передать в тот же
bounded Scanner как ephemeral candidate без записи в Store/health; passive
копия сама это право не получает. Hostname resolution реализован как
двухшаговый preview → pinned public
IP без повторного DNS во время запуска. Перед UI остаются его пользовательское
представление, live HIL и durable promotion/recovery contract.

## Этап 2 — `v0.20` Proxy Provider и Node Lab

1. Типизированный и fuzz-tested parser VLESS/Reality, затем Trojan/SS.
2. Quarantine store с trust tier, TTL, provenance, dedupe и diff.
3. Реальная цепочка Node Lab: handshake → egress → exact service probe.
4. Подписки пользователя с Conditional GET, jitter, LKG и review.
5. Goida/VLESS Checker только как выключенные Pro-шаблоны источников.
6. Истекающая оценка узлов, cooldown и запрет вечного статуса «работает».

Уточнение пользователя: [публичные источники резервных обходов](PUBLIC_PROVIDER_SOURCES_RU.md)
должны поддерживать автоматическое обновление списков и отдельную локальную
проверку узлов. Сначала NodeStore и exact-node evidence, затем opt-in расписание;
обновление списка не даёт разрешения менять рабочий маршрут.

## Этап 3 — `v0.21` Native NFQWS2

Последовательно выполнить `Z0–Z13`: golden baseline, inventory/ownership,
typed strategy compiler, adoption, NFQUEUE lease, Keenetic events, registry,
Strategy Lab, LKG state, restriction analyzer, resolver, gated adaptive mode,
updates и Lite/Pro UI. Автоматическое переключение запрещено до аппаратных
ворот и сохранения `legacy-stable`.

## Этап 4 — `v0.22` Lite/Pro

- один backend и API, простой Lite по умолчанию и диагностический Pro;
- typed API/client, frontend modules, design tokens и i18n;
- task-first Overview/Services/Devices, onboarding и symptom-first diagnosis;
- Pro: Routes, Engines, Providers, Sources, Labs, Evidence, Recovery и Audit;
- локальная работа без CDN, mobile 360 px, клавиатура и reduced motion.

## Этап 5 — `v0.23` Platform Core

Извлечь capability/platform contracts без изменения Keenetic-поведения, затем
добавлять Generic Linux/Entware, OpenWrt, GL.iNet и Asuswrt-Merlin. MikroTik
начинается только с read-only inventory/controller plan.

## Этап 6 — `v1.0`

Автопилот проходит режимы recommend → shadow → один AUTO-сервис с известным LKG
→ расширение после HIL. `v1.0` возможен только при route passports, Evidence с
TTL, автоматическом rollback, recovery после reboot/WAN/firewall, native/adopted
NFQWS2, local-key Cloudflare Provider, Lite/Pro и подтверждённых capability
матрицах Keenetic и OpenWrt.

Фактическая готовность каждого этапа фиксируется в
[CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md); номера версий не являются заменой
CI и аппаратным доказательствам.
