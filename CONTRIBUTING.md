# Contributing to RAZVILKA

RAZVILKA is currently developed against Keenetic/Netcraze + Entware with a strong preference for reproducible, reversible changes.

## Before submitting code

Run:

```sh
./scripts/check.sh
```

Changes that touch routing, firewall, DNS, engine lifecycle, or secrets should include:

- a Safe Mode path;
- validation before apply;
- bounded command timeouts;
- rollback behavior;
- no arbitrary shell execution from the Web UI;
- no fake telemetry or synthetic service-test success.

## Terminology

- **Service**: YouTube, Discord, ChatGPT, etc.
- **Engine**: NFQWS2, usque, WARP, sing-box, Xray, AmneziaWG, etc.
- **Desired**: what the user selected.
- **Planned**: what RAZVILKA intends to use.
- **Applied**: committed configuration.
- **Observed**: evidence from the live dataplane.
