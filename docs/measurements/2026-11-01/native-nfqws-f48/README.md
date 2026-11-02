# Native NFQWS2: original source observation batches

Exact candidate `f48e7d3ab1936a09d50f77513cab6e74c2ae779c`, integrated source in `a4e864aa`.
The fixed reference is `43cf7891ad5d518ec235015617295a0274a27d90`.
Each build mode ran reference and candidate consecutively on the same worker;
production and race used separate workers. Go 1.26.5, Linux amd64, actual pinned
zapret2 v1.0.6, private mount/network namespaces. Platform/WAN classification is
modeled; real TLS, source socket, packet counters, child Wait and cleanup are not.

| Mode | Before Execute | After Execute | Before/after ToolCheck wall | Consumer result |
| --- | --- | --- | --- | --- |
| Production | 14.926097792 s | 8.370467348 s | 9.654335467 / 4.104422050 s | FAIL / PASS |
| Race | 15.009592372 s | 15.011572384 s | 4.211495797 / 3.641803911 s | FAIL / FAIL |

One sample per condition: no percentile or repeatability claim. Failure and
success endpoints differ, so this is not a measured speedup of two completed
workflows. The production candidate first completes the actual consumer including
COMMON cleanup. ToolCheck durations overlap the Execute span; do not add them.
Actual calls increased 272→382 (production) and 49→84 (race), because the candidate
reaches more work before completion/deadline.

The same candidate passed actual held-image/extension mutation, late context,
callback error/panic, effect refusal, joined reads and concurrent original Close
in production (0.54 s) and race (1.60 s). Late child exit + same-owner cleanup also
passed production, retaining unknown/finalizing and refusing delayed evidence.

The complete job remains FAIL. Race still reaches the capture deadline. Production
HTTP reached a separate shared/exclusive middleware defect before its first probe;
the subsequent original-owner revocation tests were not reached. These results do
not establish full HTTP/manual-selection/live-apply or router acceptance.

Evidence: [production job](https://github.com/ArtixSx/RAZVILKA/actions/runs/41266277782/job/124729629801),
[race job](https://github.com/ArtixSx/RAZVILKA/actions/runs/41266277782/job/124729629861),
[samples](samples.json), [production excerpt](production-excerpt.txt),
[race excerpt](race-excerpt.txt). Reproduce using the pinned reference worktree
and `RAZVILKA_MANAGED_PROBE_BUILD_MODE=production` or `race` with
`scripts/test-managed-probe-native.sh` in the isolated Linux fixture environment.
