# RAZVILKA engineering

- Preserve existing work; one owner per changed file. Review network/lifecycle changes independently.
- Keep exact scope, exclusions, native VPN policies, ownership, cancellation,
  generation/evidence freshness and joined cleanup. TCP/SOCKS/delay is not service or LAN proof.
- Read [current status](docs/CURRENT_STATUS_RU.md), [roadmap](docs/ROADMAP.md)
  and [runtime matrix](docs/RUNTIME_SUPPORT_RU.md) before changing admission.
- Research sources belong outside this tree. Record pinned revisions, licenses,
  reproducible commands and limits in [the lab ledger](docs/RESEARCH_LAB_20261109.md).
- Go 1.26.5: focused `go test ./internal/dataplane ./internal/app ./cmd/nodeeval`
  selections first; Linux full gate `sh scripts/check.sh`. Native fixtures and
  [router acceptance](docs/ROUTER_ACCEPTANCE_RU.md) are separate from generic CI.
- Update existing documents rather than creating a competing roadmap.
- Merge, release, production deployment and changes to a live router require
  explicit user authorization. Ordinary reversible work and draft PRs do not.
