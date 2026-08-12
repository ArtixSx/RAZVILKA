# RAZVILKA v0.0.8-security-gate

This build is designed for a clean secondary Entware USB on Keenetic / Netcraze.

## Phase A — clean control-plane test

Run:

```sh
chmod +x scripts/*.sh
./scripts/lab-bootstrap.sh
```

Collect:

```sh
cat /opt/var/log/razvilka/preflight-after-install.txt
```

Open the URL printed by the bootstrap (normally `http://<LAN-IP>:8787`).

Before the first state-changing action, read the local administrator token:

```sh
cat /opt/etc/razvilka/admin.token
```

The Web UI requests this token on the first Apply, Discard, refresh, test run or config edit and keeps it only for the current browser tab.

Verify:

1. Overview / system preflight.
2. Services: create a routing draft, Apply/Discard it.
3. Engines: NFQWS2/usque files are listed even when packages are not installed.
4. Config Center: a non-sensitive imported file can be staged and validated without touching `/opt/etc/<engine>`.
5. Test Lab: `Check current configuration` performs real service probes using current router routing.
6. Connections remains empty until a dataplane adapter provides real route evidence.

## Safety semantics

`Safe Mode = ON` means:

- engine config draft: allowed;
- validation: allowed;
- import/export of non-sensitive config/list files: allowed;
- service-route draft/apply in the manager state: allowed;
- write to live NFQWS2/usque/sing-box/etc config: blocked;
- firewall/DNS/policy-route modification: blocked;
- engine restart triggered by RAZVILKA: not enabled yet.

Secret configurations (WireGuard private keys, VLESS/Reality credentials, Xray/sing-box credentials) remain redacted even after authentication; v0.0.8 does not expose them to the browser.

## Test Lab semantics

`Current` is a real probe through whatever routing is currently active on the router. It is **not** proof that a particular engine caused the success.

If preflight reports `route_test_contamination=possible` (for example an existing `nwg3`, WireGuard, TUN or `opkgtun` route), CURRENT results may traverse that external route. Route-isolated DIRECT/engine evidence must not be inferred from CURRENT.

The engine matrix is intentionally conservative:

- `NOT READY`: engine absent/stopped;
- `ADAPTER`: engine is available, but route-isolated probe adapter is not connected yet;
- `PASS/PARTIAL/FAIL`: reserved for actual probe evidence.

This avoids reporting planned routes as observed behavior.
