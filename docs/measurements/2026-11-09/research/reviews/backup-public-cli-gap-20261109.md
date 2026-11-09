# Backup/update audit, 2026-11-09

Measured commit `0f0439020d10e1bbb15a8310be360517bf45581f`, lifecycle run42630488013, strategy-pair job129205220080: SUCCESS. Exact log hash and result: `lifecycle-0f043902/strategy-pair-results.json`.

## Already exercised

- Actual current binary capability readers: StrategyLab7, component6, execution9, private snapshot4. Actual old577 binary missing StrategyLab/snapshot readers is rejected; actual reader5 cannot authorize supervised settled schema5 as a standalone compatible controller.
- All StrategyLab, encrypted private backup and private restore package tests with race instrumentation. Includes original online/offline restore leases and handover, crash after config or StrategyLab write restoring before-images, candidates/history/manual selection preservation with stale health invalidated, unknown/finalizing fences.
- Focused updatecheck/command/App/dataplane/gate race tests, including binary/state paired snapshot3, failed install rollback, recent history retention, state/reader/source drift rejection, and actual stopped-controller before/after/StrategyLab retention cuts.
- Actual restored Main panel in isolated network namespace: two boots, HTTP status, unchanged restored history/manual bytes. PASS0.19s. This is panel availability, not a live restored route or router reboot.

## Confirmed remaining software scenarios

1. The public executable producer and offline restore acceptance tests exist but are not selected/configured by workflows: `TestNativeExternalBootstrapPublicExecutableProducer` and `TestNativePairedRestorePublicExecutableCaller`. Without their explicit candidate/archive/ID coordinates they skip. The library native rename test uses modeled runtime/owner callbacks and does not close this gap.
2. Those command tests contain stale `/opt/var/lib/razvilka`, `/opt/var/run`, and old offline archive paths. Actual production uses `installpath.State`, `installpath.Run`, and `/opt/razvilka/state-offline-recovery`. They require test-path correction before genuine execution.
3. `restorePairedOffline` retains `.paired-offline-*` stages on every error; `offlineRestorePlan` refuses any such stage on the next attempt. `TestPairedOfflineRestoreCutsKeepOldExecutableOfflineAndRefuseOrphans` reproduces this even at `before:offline-effects`, where no active target changed. This is safe refusal, not working automatic retry. A future original-owner pre-effect cleanup capability can remove only its actual retained staged identities after fresh unchanged-target proofs; unknown rename/start/crash outcomes must remain fenced. No production change proposed until independent contract review.
4. Source0.19.3's stock init defaults to legacy `/opt/var` layout, while current external bootstrap requires current fixed `/opt/razvilka` layout. A first disposable fixture can explicitly configure the actual old binary via its existing source init variables. It must not be represented as default legacy-layout migration acceptance.

## Proposed first complete public CLI fixture

- Build actual old tag817783493f0c2784ccc70aa73868cd64e9437634 (`v0.19.3`), current candidate, cmd tests and a complete current9-required-file release archive. Verify actual versions and SHA; no fake receipts or fabricated GitHub release provenance.
- Before isolation hold actual outer network namespace FD. Enter private mount/network/PID namespace, verify private mount propagation, remount private proc, mount disposable `/opt`; host/router `/opt` untouched. Use fresh loopback only, real busybox interpreter/daemon and actual trusted kernel/tool inventory.
- Start actual old panel with explicitly configured fixed current layout, safe/stopped config and genuine PID/service lifetime. Invoke current candidate's actual `self-update-bootstrap-old193`. Its producer must create every archive/header/review/helper/process receipt and joined command itself.
- Only platform classification uses existing `razvilka_native_fixture`; original network namespace/source, image metadata/bytes, runtime inventory, all effect admission and joins stay real. Top-level candidate and two actual command-helper hops need narrowly tagged forwarding of only the original outer net FD, private native review coordinate and TMPDIR; normal build forwarding is a no-op.
- After real bootstrap has joined, issue current durable Stop through the original operationgate API, not by writing a receipt. Run `self-update-paired-restore` as the actual candidate. Verify old binary bytes, guarded init scripts, stopped config/revision/exclusions, unchanged current Stop and protected journals, and no panel PID. Keep restored source offline.
- Run actual failures as failures; preserve sanitized categories and exact fixture state. Generic CI, tagged Linux classification, configured source layout and physical router acceptance remain separate.

No production guard, orphan fence, timeout or live device changed by this audit.
