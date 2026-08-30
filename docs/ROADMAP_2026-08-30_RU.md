# Актуальный roadmap RAZVILKA

Дата пересмотра: 30 августа 2026 года  
База: стабильный `v0.18.0`, commit `8fa1d61914cb7fcfb354259408e18ce1dc72e354`

Этот roadmap переносит порядок единого master-plan на фактическую историю
версий. Опубликованный `v0.18.0` не переименовывается, поэтому номера будущих
этапов сдвинуты, но зависимости и требования безопасности сохранены.

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

## Этап 1 — `v0.19` Unified Cloudflare Provider

1. Provider model и локальное secret state.
2. Локальная генерация ключей и тестируемый registrar без передачи private key.
3. WARP Configurator generate/import/export без системных мутаций.
4. Endpoint Scanner с реальным handshake, egress, trace и service evidence.
5. Единый USQUE lifecycle и Safe Repair Wizard.
6. AmneziaWG compatibility registry и аппаратный canary.
7. `wgcf` только как явно выбранный import/fallback и compatibility oracle.

## Этап 2 — `v0.20` Proxy Provider и Node Lab

1. Типизированный и fuzz-tested parser VLESS/Reality, затем Trojan/SS.
2. Quarantine store с trust tier, TTL, provenance, dedupe и diff.
3. Реальная цепочка Node Lab: handshake → egress → exact service probe.
4. Подписки пользователя с Conditional GET, jitter, LKG и review.
5. Goida/VLESS Checker только как выключенные Pro-шаблоны источников.
6. Истекающая оценка узлов, cooldown и запрет вечного статуса «работает».

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
