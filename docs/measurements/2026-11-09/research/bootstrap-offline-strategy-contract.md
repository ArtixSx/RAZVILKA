# Original offline bootstrap StrategyLab contract

Source commits: a3cf7ec6 (per-call full executable comparison), efe47ac6 (excluded unchanged state).
Independent reviews: bootstrap-role-image-independent-review-20261109.json and bootstrap-offline-strategy-independent-review-20261109.json.
No local Go execution. Full actual public native acceptance remains pending.

## Confirmed failures on 8434e9ae

Empty public bootstrap failed at the unchanged 2-second scoped DNS inactivity deadline: proc-closing/proc.installer-role-close. The controller-group reader repeatedly hashes the same full candidate image. New per-call reader still opens/reads every actual executable occurrence to EOF, compares bytes, and checks process/argv/incarnation bookends; only repeated SHA computation changes. One logical retained image per synchronous role call, less than64MiB owned data. GC/RSS/global concurrency and router readiness are not established by this bound. Actual reader measurement logs retained_bytes and streaming_fallback.

Draft public bootstrap reached genuine old193 HTTP AddCandidate/GET and failed file-review because ordinary sealStrategyPair deliberately rejects bootstrap. Old193 has no modern state/snapshot reader ABI. This is not schema parsing failure.

## Narrow implemented consumer

- Only original external preparation can create Bootstrap.OfflineStrategy.
- Exact unchanged settled schema1 state, offline source intent, no ordinary StrategyPair.
- Actual pinned candidate metadata probe, original preparation/current bookends; old193 gains no reader ABI.
- Every admission observes complete current state bytes and modern control/candidate/installed binary hashes. Unknown/finalizing, schema/byte drift, changed binaries, ordinary retention, cancellation refuse forward action.
- Private snapshot remains schema2 and excludes StrategyLab. No new mutable replay target.
- Complete original paired archive retains old bytes. Existing public offline restore preserves CURRENT StrategyLab and restore fences; it never overwrites them with archived state.
- Explicit refusal of start/live, replace-to-rollback, direct restorePrivateSnapshot and strategyRollbackImages for this proof.
- Existing empty bootstrap serialization/path unchanged. Older strict decoders reject the new optional field rather than interpreting it as compatibility.

## Verification still required

Focused: TestBootstrapOfflineStrategy*, TestBootstrapImage*, TestOrdinaryImage* (normal/race as wired by root).
Actual public matrix: scripts/test-paired-public-native.sh with empty mode and RAZVILKA_PAIRED_NATIVE_HISTORY=draft.
Required draft marker: actual_public_pair_retained_draft preserved=true original_old_http_writer=true current_reader=true old_live_compatibility=false manual_selection=false.
Required full marker: actual_configured_old193_public_pair complete=true source_restored_offline=true original_stop_retained=true guards_preserved=true tagged_platform_classification=true.
A pre-cut/model/reader success alone is not full public workflow acceptance. Configured old193 layout and Ubuntu tagged platform classification remain distinct from default old /opt/var migration or physical router readiness. Completed history/manual selection and restored old live panel are separate unproved scenarios.
