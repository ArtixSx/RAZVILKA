# UI / control-plane research notes

RAZVILKA uses independent implementations while studying mature router/proxy UI patterns.

## Adopted patterns

- XKeen-UI: selectors and observed connections are separate; configuration editing tracks unsaved changes; generic file tabs can load/save a known file through an API.
- nfqws-keenetic-web: structured form for NFQWS settings plus a generic known-file editor. RAZVILKA generalizes the concept to every engine.
- Zashboard / MetaCubeXD: latency history, chain visibility, live connection filtering.
- MagiTrickle: draft/apply semantics, import/export and bulk rule management.
- AdGuard Home / Pi-hole: client identity plus activity/query log style diagnostics.
- Hiddify / Clash Verge: profiles/subscriptions and node-centric management.
- HomeProxy: generated config must pass the core's native config check before start/apply.
- AntiGoblin: backup before apply and rollback-aware router operations.
- SKeen: router-hosted UI must remain lightweight.

## RAZVILKA interpretation

The UI is not an engine frontend. It is an orchestrator:

```
Services -> desired route
Engines  -> managed config + lifecycle
Test Lab -> route/service evidence
Connections -> observed live traffic
```

The manager never equates desired/planned with observed.
