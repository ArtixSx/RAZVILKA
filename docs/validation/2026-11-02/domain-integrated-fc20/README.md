# Integrated DNS ownership validation

Commit `fc20a792f1735f3b545bcdae5e263865cfa15fe2`, [run41429725627](https://github.com/ArtixSx/RAZVILKA/actions/runs/41429725627).

Actual DNS publication, original Stop and cached-alias TLS passed for baseline (27.04s), clean detach (52.03s), alias0 lost ACK (39.54s), alias1 lost ACK (52.82s), global lost ACK (53.45s) and foreign history refusal (44.85s). These seven collected jobs contain no skipped tests. Registry case failed before publication at the diagnostic 30s window (whole test43.97s); this does not exercise its injected registry ACK cut. All five initial-ACK generation jobs also failed. The overall workflow is FAILURE.

These are DNS-only ownership scenarios. They do not establish the selected-service continuation, multiple-generation workflow, completed canceled-child cleanup or router readiness. The fixture explicitly reports a diagnostic30s publication window and10s client deadline; production12s/4s performance acceptance is not established. Different hosted workers and incomplete failed prefixes do not support a before/after speed claim.

[Results](results.json) records exact jobs, outcomes, durations and raw-log SHA256. [Original excerpts](raw-excerpts.txt) retain measured operation counts, diagnostic boundaries and test results. Complete logs remain linked from the workflow. Remaining implementation belongs to Review; the leading agent owns integration and this evidence.
