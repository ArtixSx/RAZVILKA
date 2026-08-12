# UI / control-plane research notes

RAZVILKA intentionally studies mature network/proxy/router panels before freezing its own product model. These are **UX/architecture references**; their code is not copied into RAZVILKA.

## XKeen-UI

Useful patterns:
- selector cards for proxy/service groups;
- current chain expansion;
- per-node latency testing/history;
- live connection table with chain, host, protocol, source, traffic and age;
- logs/config validation in the same operational panel.

RAZVILKA decision: keep the selector + connections mental model, but normalize it across NFQWS2, WARP, sing-box and other adapters instead of tying it to Mihomo/Clash.

## MetaCubeXD / Zashboard

Useful patterns:
- immediate current-state feedback after an action;
- live traffic/connection/rule/log diagnosis;
- latency and node/group testing;
- connection filtering/sorting and route-chain drill-in;
- responsive/mobile operation;
- lightweight no-font build options in Zashboard demonstrate value of small static router UI assets.

RAZVILKA decision: Connections is an evidence/diagnostic surface, not a decorative dashboard. Use SSE + bounded state and keep charts optional.

## Pi-hole / AdGuard Home

Useful patterns:
- query/activity log as “client → destination” history;
- top clients/domains and strong filtering;
- client identity/friendly names;
- APIs separate frontend presentation from backend state.

RAZVILKA decision: add a dedicated Devices surface and eventually merge friendly identity with connection route evidence, so diagnosis can answer “which device used which service and which route?”.

## MagiTrickle

Useful patterns:
- visible unsaved-change state;
- explicit Apply rather than implicit disruptive writes;
- import/export;
- enable/disable/reorder groups and rules;
- domain/wildcard/regex/IPv4/IPv6 rule types.

RAZVILKA decision: adopt staged desired/applied generations. Keep raw rules in Advanced mode; the default workflow remains service-first.

## AntiGoblin

Useful patterns:
- one-command router-hosted install;
- URI/subscription workflows;
- routing groups with selected outbound;
- backup before generated config overwrite;
- self-heal/reboot hooks;
- a state source-of-truth that generates runtime artifacts.

RAZVILKA decision: profile/subscription import and self-heal are useful, but generated artifacts must live under RAZVILKA ownership and participate in one cross-engine transaction/rollback generation.

## HomeProxy / PassWall class of managers

Useful pattern and warning:
- native engine config generation/validation before start;
- mature handling of DNS/firewall/routing as one system;
- engine schema evolves and can be incompatible with older core versions.

RAZVILKA decision: a simple “binary installed” indicator is not enough. Every adapter gets an exact version/capability matrix and native config validation before Apply.

## SKeen

Useful product constraint:
- router resources matter; using a static dashboard/API rather than embedding a large application stack can reduce local complexity.

RAZVILKA decision: keep manager + UI small, static and local. Do not require Node, PHP, a database, or external CDN assets to operate the control plane.

## Final RAZVILKA information architecture

```text
Overview
  current health / important route state / pending generation

Services
  service ON/OFF
  AUTO or fixed route
  desired vs planned vs applied

Connections
  observed live/closed traffic
  device → service/host → protocol → actual route chain

Outbounds
  NFQWS2 / WARP / sing-box / Xray / AWG inventory
  concrete user nodes/subscriptions later

Devices
  friendly identity / group / policy / activity later

Sources
  vendor manifests / classifiers / block observations / validation state

Diagnostics
  preflight / version matrix / dry-run / probes / rollback readiness

Settings
  safety / export / generations / update channel
```

## UI invariants

1. Never show a planned route as if it were observed traffic.
2. Never fabricate devices or live connection rows for a prettier demo.
3. Any disruptive change creates a draft first.
4. Apply must report what passed/failed and leave a rollback target.
5. Basic mode is service-first; raw domains/CIDRs/firewall rules stay in Advanced.
6. No UI feature may require internet/CDN access to operate locally.

## Hiddify

Useful patterns:
- profile/subscription as a first-class object rather than raw config text;
- delay-based automatic node selection;
- automatic subscription refresh;
- profile metadata such as remaining time and traffic usage.

RAZVILKA decision: proxy subscriptions should become managed Providers, while individual imported nodes become selectable outbounds. AUTO may use latency, but only after service health succeeds.

## 3x-ui

Useful patterns:
- clear separation between panel health and core health;
- per-client/per-outbound traffic accounting;
- multi-hop route attribution;
- subscription-based outbounds;
- batched outbound connection tests;
- modern releases increasingly support live apply without killing unrelated connections.

RAZVILKA decision: show **Manager** and **Dataplane** health independently, preserve actual multi-hop route chains in telemetry, and eventually allow an adapter to hot-apply only when the engine explicitly supports a safe live-update path.

## OpenClash / PassWall

Useful lessons:
- full router routing products must coordinate DNS, TUN/TPROXY, firewall and rule data rather than treating the proxy core in isolation;
- dependency footprint can become large;
- core/data-format evolution (for example sing-box rule/geodata changes) forces the UI/manager to maintain compatibility logic.

RAZVILKA decision: keep dependencies minimal on Keenetic, make capability/version handling a first-class adapter responsibility, and never let one engine silently become the owner of every network subsystem.
