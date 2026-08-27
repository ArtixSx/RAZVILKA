# Gap-аудит RAZVILKA на 2026-08-25

Аудит фиксирует состояние ветки `main` около `v0.15.0`. Статус `PARTIAL`
означает, что реальный backend существует, но ещё не закрыты все аппаратные,
evidence, rollback или UX-критерии. Наличие карточки в UI не означает готовность.

| Возможность | Статус | Текущее состояние и файлы | Основной пробел / следующий тест | Фаза |
|---|---|---|---|---|
| Service model/catalog | PARTIAL | Каталог, пользовательские сервисы, домены/CIDR и per-service route: `internal/catalog`, `internal/customservices`, `internal/app` | Service Pack, subservices, зависимости и SLO | P1/P4 |
| NFQWS2 runtime | PARTIAL | Транзакционный адаптер и ownership: `internal/dataplane/nfqws2.go` | Canary, реальный client evidence, offload matrix | P0/P1 |
| NFQWS Strategy Lab | PARTIAL | Ограниченный подбор и память: `internal/strategylab`, `internal/smartroute` | Network/device key, TCP/QUIC раздельно, confidence UI | P1 |
| USQUE / MASQUE | PARTIAL | Компонент, secret config, isolated SOCKS + sing-box sidecar: `internal/components`, `internal/dataplane/proxy.go`, `internal/engineconfig` | Безопасная перерегистрация, DNS candidate, endpoint scan, Telegram matrix; см. `USQUE_RECOVERY_PLAN_RU.md` | P2 |
| WARP WireGuard | PARTIAL | Генератор, candidate и policy adapter: `internal/warp`, `internal/dataplane/warpwg.go` | Endpoint scanner, handshake на hardware, egress/service evidence | P2 |
| sing-box | PARTIAL | Safe URI/subscription/Clash import и proxy adapter: `internal/providerprofile`, `internal/dataplane/proxy.go` | Provider registry, refresh, capability/schema detection, egress | P2 |
| Xray | PARTIAL | Конфиг и общий proxy adapter | Реальные supported-profile tests и причина существования рядом с sing-box | P2 |
| AmneziaWG | PARTIAL | Конфигурация/маршрут поддерживаются общим policy contract | Совместимый сервер, kernel/userspace matrix, handshake evidence | P2 |
| Safe / write mode | COMPLETE | Явный режим и блокировка live write: `internal/app`, `internal/securitygate` | Повторная UX-проверка терминов | P0 |
| Auth / CSRF / secrets | PARTIAL | Локальная аутентификация, origin gate, recovery key, redaction и `0600`: `internal/security` | Rate-limit/security review, session cookie evolution | P0/P6 |
| Lifecycle serialization | PARTIAL | Dataplane operations сериализованы и context-aware | Единая state machine для component/engine/provider/DNS операций | P0 |
| Engine staging | COMPLETE | Draft/live/backup и validation: `internal/engineconfig` | Scoped transaction UX | P0/P5 |
| Transactional Apply | PARTIAL | plan/snapshot/stage/validate/activate/health/commit: `internal/dataplane` | Настоящий canary перед заменой live | P0 |
| Rollback / recovery | PARTIAL | Reverse rollback, journals, boot recovery | Kill/power-loss hardware matrix и last-good UI | P0/P6 |
| Test Lab attribution | PARTIAL | Explicit SOCKS/interface/NFQUEUE evidence: `internal/routeprobe`, `internal/testlab` | Route Sandbox для каждого адаптера и negative controls | P0 |
| Egress identity | MISSING | Отдельные диагностические фрагменты существуют | Единая модель IP/country/ASN/stickiness | P2/P4 |
| Provider/subscriptions | PARTIAL | Ручной безопасный импорт до 64 узлов | Локальный registry, expiry/refresh, node health | P2 |
| Source Hub / Free Pool | PARTIAL | Встроенные validated lists и независимый persisted desired/applied выбор | Внешние provider provenance/dedupe/trust/quarantine и локальная проверка | P2.5 |
| Devices | PARTIAL | LAN discovery, имена, группы, scoped policies: `internal/devices` | Стабильная идентичность DHCP/IPv6 и device class | P4/P5 |
| DNS | PARTIAL | Профили, независимый черновик/Apply guard и read-only probes: `internal/dnscontrol` | Platform apply, port-53 ownership, leak test, rollback | P3 |
| Logs / audit | PARTIAL | Локальный redacted audit: `internal/auditlog` | Полный old/new path, evidence и rollback correlation | P0/P5 |
| Timeouts / cancellation | PARTIAL | Ключевые Apply/network/component операции ограничены | Полная инвентаризация subprocess/DNS/fetch и bounded workers | P0 |
| Component Manager | PARTIAL | opkg/GitHub components, планы, версии: `internal/components` | Signed compatibility registry, smoke/rollback per component | P6 |
| UI | PARTIAL | Service-first страницы, scoped Apply и multi-scope preview для Services/Devices/DNS/Sources | Simple/Advanced split, Repair Wizard, mobile | P5 |
| Tests / CI | PARTIAL | Go/JS/release tests и часть артефактных проверок | ARM64+MIPS hardware matrix, fault injection, soak, SBOM | P6 |

## Ближайшие обязательные изменения

1. Route Sandbox/canary и единый evidence contract.
2. USQUE recovery candidate без необратимого изменения DNS или live-сессии.
3. Provider registry для пользовательских профилей sing-box.
4. DNS platform adapter только после hardware rollback test.
5. Source Hub — последним из перечисленных блоков, не раньше trust boundary и
   локальной service-проверки.
