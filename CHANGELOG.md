# Changelog

## v0.0.7-control-lab — RAZVILKA GitHub foundation

- Project renamed to **RAZVILKA**.
- Binary/runtime paths renamed from the internal prototype name to `razvilka`.
- Go module prepared for `github.com/ArtixSx/razvilka`.
- GitHub repository hygiene added: CI, `.gitignore`, security and contribution notes.
- Real Netcraze/Entware lab findings recorded for the next engine-integration iteration:
  - BusyBox `ip` does not support `-br` on the tested router;
  - existing KeeneticOS tunnels/routes can contaminate naive DIRECT tests;
  - per-engine service tests must be route-isolated;
  - runtime logging and lifecycle evidence need to be first-class.
- Follow-up hardening from the first real Netcraze bootstrap:
  - preflight now uses BusyBox-compatible `ip -o` commands;
  - external tunnel routes are surfaced as possible Test Lab contamination;
  - bootstrap creates its log directory before the first redirected preflight;
  - `rc.func` is required before install;
  - installer no longer hides a failed manager start.

## v0.0.6-control-lab — internal prototype

- Service selectors with desired/planned/applied state.
- Config Center with staged validation and Safe Mode write gate.
- Current-routing service probe and non-faked route matrix readiness states.
- Multi-architecture Entware lab bootstrap and preflight.
