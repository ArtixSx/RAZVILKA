# План RAZVILKA

Текущая линия — **`0.18.2-rc.4`**, исправленный DC1. Канонический подробный
план и критерии приёмки находятся в
[ROADMAP_2026-08-30_RU.md](ROADMAP_2026-08-30_RU.md), подтверждённые результаты —
в [CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md).

Опубликованный rc.4 прошёл CI, обновление через SSH, перезапуск приложения
и восстановление VLESS на Netcraze aarch64. Фактический путь свежих клиентских
соединений подтверждён через TUN в обычном и контролируемом маркированном
сценарии. [Отчёт и ограничения](releases/0.18.2-rc.4-validation.md).
Контроль другого адреса LAN был маршрутным запросом, без физического
второго клиента. Все варианты чужих конфликтов и аварийного отката
на железе этим результатом не закрыты.

Следующие этапы: аппаратная
устойчивость маршрутов и автономного управления; единая проверка DNS + маршрут +
сервис (DC2); применение DNS к выбранным клиентам (DC3); ограниченный
автоматический выбор пары (DC4). Облачные подсказки остаются отдельной будущей
работой; текущий каталог проверяется только офлайн.

Основное управление, подписки и задания на роутере уже реализованы.
[Отчёт DC1](DC1_REVIEW_2026-09-13_RU.md) описывает исправления, а
[план DNS/Community](DNS_COMMUNITY_UNIFIED_DC1_RU.md) — незавершённые контракты.
Итоги проверки финального релизного бинарника смотрите в `VALIDATION_RU.md`
на [странице выпуска](https://github.com/ArtixSx/RAZVILKA/releases).

<details>
<summary>Архив выпущенных этапов и прежних релизных условий</summary>

Ниже сохранена история до DC1 review. Слова «current», «remaining» и старые
версии/хэши относятся к своему срезу и не описывают готовность `0.18.2-rc.4`.
Полезные технические критерии остаются в силе, пока не подтверждены отдельно.

## История roadmap

> Актуальный подробный план реализации находится в
> [ROADMAP_2026-08-30_RU.md](ROADMAP_2026-08-30_RU.md). Подтверждённые уровни — в
> [CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md). `MASTER_PLAN_RU.md` — архив.
> Этот файл сохраняет историю уже
> выпущенных этапов и релизные ворота.

> 8 сентября 2026: после нового запроса работа возобновлена. Реализованы
> [управление и интерфейс по 11 замечаниям](UI_CONTROLS_2026-09-08_RU.md):
> режим, выключатель маршрутов, компактные сервисы, таймер и обновления.
> AUTO1 — основа для applied fallback groups, AUTO2+ не выполнены.
> По запросу пользователя подготовлен [тестовый выпуск v0.18.1-rc.2](releases/0.18.1-rc.2.md),
> публикуемый после Release CI. Аппаратные ограничения перечислены в его описании.
> Результаты прежней остановки — в [итогах этапа](PHASE_2026-09-08_RU.md); исторические
> подтверждения ниже не заменяют приёмку новой автоматики.

## Completed milestones

- `v0.0.2–v0.0.10`: source/control plane, clean Entware Lab, service selectors, honest telemetry model, multi-architecture CI, security gate, transactional installer and component versions/updates.
- `v0.1.0`: registration/password UI, installer-visible recovery URL, service-first redesign, guided/expert engine editors, custom services, WARP generator and one-command install.
- `v0.2.0`: allowlisted community catalog, provenance/conflict preview and guarded WARP candidate rotation.
- `v0.3.0`: Engine Lab, isolated evidence, persistent Smart Route, session controls and 35 Russia-oriented manifests.
- `v0.4.0`: secret-free profile exchange, draft-only preview/import, recovery-key reset/reissue and domain/IP inspector.
- `v0.5.0–v0.5.1`: deterministic dataplane plan, ownership, preflight/blockers and truthful installed/configured/running/Safe Mode state.
- `v0.9.0–v0.9.1`: active transactional adapters, recovery, device policy,
  diagnostics, release verification and real-Keenetic compatibility fixes.
- `v0.10.0`: z2k discovery/NFQUEUE ownership protection, guided Safe Mode
  results, resilient WARP registration and user-facing «Обходы» terminology.
- `v0.11.0–v0.12.x`: on-demand bypasses, Strategy Lab, resource/traffic UI,
  WARP workflow and real-router usability fixes.
- `v0.13.0–v0.14.0`: route-quality evidence, WARP recovery, official Telegram
  CIDR coverage, explicit tunnel roles and pre-Apply transport diagnostics.

## Current development — evidence hardening and adaptive routing

[NET1](NET1_2026-09-06_RU.md), NB1 node check/preview/explicit service Apply,
PF1 persistent opt-in subscriptions and the built-in WARP generator are
implemented locally. Native registration performs one POST with private
checkpoints and offline recovery; it only stages a candidate. Native enrollment
now participates in the encrypted private backup and coordinated restore,
with old-backup/pending conflict protection and process-crash tests.

Native migration and encrypted export/preview/import also pass on hardware,
preserving the canonical image, applied settings and stopped service runtime.
The remaining core MVP gates are real WAN/restart recovery and a tested installable
ARM64 build. The complete isolated installer lifecycle passed on the earlier
`48f3e1ef…` snapshot; newer recovery/cleanup fixes still need a rebuilt candidate
and bounded installer smoke. That hash is not the final release artifact.
Native client-path HIL now passes for an explicit PC /32:
A commit, failure-injected B activation with rollback to A, and normal B commit
all deliver Telegram HTTP 200 from that PC. A second PC stays outside the TUN;
counters, cleanup and global-file preservation pass. The two server endpoints
have the same observed egress, so independent upstream resilience is not claimed.
gVisor and owned scoped FORWARD/NAT fixes are included. The actual UI A/B
check-preview-Apply sequence now passes with PC HTTP 200 and unrelated drafts
retained. Manual feed import saves four unchecked nodes without applying.
All-LAN bridge scope also passes PC IPv4 traffic and IPv6 kernel route checks;
actual IPv6 HTTPS is not proven. The full Windows race suite passes with a verified working
detector; Linux-specific race remains separate. WARP MASQUE
passed an initial H2/H3 run but failed repeatability; WireGuard trace failed on
all four server-issued ports. Neither is promoted as a stable fallback.
See [ROADMAP_2026-08-30_RU.md](ROADMAP_2026-08-30_RU.md) for bounded acceptance
criteria. Scheduler, AutoPilot, native NFQWS2, live DNS and new platforms are
subsequent capabilities, not prerequisites for a proven manual MVP.

The requested node browser and subscription follow-ups are now implemented:
country/transport cards, filtering, batch checks, five saved-source presets,
refresh scheduling and applied fallback-group recovery. Their current contract
and source-specific native observations are recorded in
[PUBLIC_PROVIDER_SOURCES_RU.md](PUBLIC_PROVIDER_SOURCES_RU.md).
The final hardware/installer pass and aarch64/mipsel/mips GitHub publication
remain separate release gates; this implementation note assigns no release hash.

WARP/AWG cleanup now requires an exact owned policy/runtime pair. No state
means no interface calls; partial or mismatched state is preserved with an
error. Native enrollment downgrade gates also cover legacy markers and the
restore journal file, including a check after recovery. Local regressions pass;
these safeguards do not promote the unsteady WARP transport to a usable fallback.

Implemented in the current development cycle: ordered route evidence,
automatic DIRECT controls, Apply conflict gates, a bounded local audit,
Recovery Safe Mode with a boot-loop guard, WAN-scoped Smart Route memory and a
non-live DNS profile/probe/ownership plan. Telegram route tests use several
required scenarios instead of one landing page. Transactional DNS activation
remains deliberately disabled until the platform adapter and rollback are
proven on hardware.

Evidence is now visible per service and per transaction in the UI and in the
privacy-safe diagnostic report. Desired or reviewed plans cannot promote it.
The journal also keeps the latest reviewed plan separate from the last
successfully committed plan, so a Safe Mode preview cannot hide the route used
for reboot recovery or AUTO evidence.

Apply preflight now also reads IPv4/IPv6 policy rules and routing tables in the
adapter-owned ranges. A foreign rule becomes an explicit adapter blocker;
RAZVILKA reports it and never deletes it automatically.

The 2026-08-25 architecture review is recorded in
[ARCHITECTURE_GAP_2026-08-25.md](ARCHITECTURE_GAP_2026-08-25.md). The first
scoped-draft slice now covers Services, Devices, DNS and Sources independently;
an unused WARP/DNS profile or unconfirmed source selection no longer changes or
blocks an unrelated page. The Apply preview now separates included and deferred
scopes before confirmation. A safe USQUE re-registration experiment (including
an optional temporary Quad9 candidate) is planned in
[USQUE_RECOVERY_PLAN_RU.md](USQUE_RECOVERY_PLAN_RU.md); it is not implemented
as a live router mutation yet.

Public VLESS sources and explicit HTTPS subscriptions have persistent CRUD,
serial refresh jobs, conditional requests, cancellation, private backup/restore,
strict parsing, deduplication and explicit partial-import acceptance. Limits are
32 sources, 128 retained candidates per feed and 512 nodes in the local store.
New candidates remain unverified; synchronization neither renews local health
nor switches routes. TCP checks and exact service checks are separate bounded
jobs. Automatic replacement is restricted to an applied fallback group and a
complete sing-box node plan with unchanged service/client scope. Its final
native acceptance is tracked in the current status, independently of code completion.

## Implemented dataplane foundation

- Runtime adapters for NFQWS2, usque, WARP-WG, AmneziaWG, sing-box and Xray.
- Bypass cards explain whether a method works locally, uses Cloudflare, or requires a remote server/profile; Sing-box is presented as a client rather than a standalone unblocker.
- One locked transaction: snapshot, stage, native validation, activation, route/service health, adapter commit and reverse rollback.
- Atomic execution/recovery/policy/deactivation journals and committed-plan boot recovery.
- Exact process/PID ownership, isolated interfaces/tables/priorities and endpoint/self-loop guards.
- DNS-to-IP policy refresh, IPv4/IPv6 kernel route evidence and source-scoped device policies for tunnel adapters.
- LAN device discovery/names/groups and confirmed conntrack Connections producer.
- Encrypted private backup, privacy-safe diagnostic report and official application update notification.
- GitHub/Sigstore artifact attestations for release bundles.
- Graceful shutdown, slower-router recovery allowance and non-blocking transaction status.

## Hardware release-candidate fixes

Only evidence-driven fixes found by the release matrix belong here. Compatible corrections increment the patch (`0.9.1`, `0.9.2`). A format/behavior redesign increments the minor.

Required matrix:

- ARM64 plus MIPS or MIPSLE Keenetic/Netcraze;
- clean install, upgrade, rollback and uninstall;
- NFQWS2, WARP and proxy adapter individually and simultaneously;
- IPv4/IPv6, PPPoE/regular WAN, NFQUEUE/TUN and offload modes;
- power loss/kill at every transaction phase, manager crash and reboot order;
- port/TUN/table/DNS/third-party engine conflicts;
- low-memory/OOM, large lists/conntrack and multi-day soak;
- LAN authentication/origin/permissions/backup/diagnostic security review.

## `v1.0.0` — first mass-use release

Tag only after the supported-device matrix is recorded as passing. The default remains Safe Mode; the UI must never convert desired/planned state into observed evidence.

Post-1.0 candidates:

- priority-aware schema for different routes of the same service on different device groups;
- signed third-party community publisher workflow beyond the attested bundled catalog;
- optional bounded traffic history and richer protocol-aware TCP/UDP/QUIC decisions;
- additional engines only when they implement the same ownership/rollback/evidence contract.

</details>
