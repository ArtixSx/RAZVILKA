# Initial SOCKS readiness cadence: controlled comparison

Date: 2026-11-09. Windows/amd64, Go1.26.5, AMD Ryzen 7 7800X3D,
benchmark suffix `-16`. Baseline production implementation:
`71b6f969579833e3ba217b331dc3c1a24bb150f7`, with the benchmark fixture added.
Candidate: the accompanying change to `ExactNodeChecker.startSession` in this
commit. Both retain the eight-second readiness context and original process,
identity, service and cleanup checks.

Old pauses: 100ms throughout. Candidate pauses: 10,20,40,30ms initially,
then 100ms. Nominal attempts are 0/10/30/70/100/200/...ms; real process and
socket work adds elapsed time. The candidate adds at most three early probes
to the eight-second instantaneous-failure schedule (83 instead of 80).
This is not a permanent 10ms polling loop.

The actual loopback TCP server rejects SOCKS greetings before its configured
readiness time, then accepts them. It does not hold a greeting until readiness.
The process controller is modeled; Xray/Mihomo, credentials, TLS service
acceptance, routing and LAN are not exercised by this fixture.

Three benchmark runs per case, each reporting the mean of ten measured checks:

| Server becomes ready | Baseline mean range, ms | Candidate mean range, ms | Greetings/check before → after |
| --- | ---: | ---: | ---: |
| 25ms | 100.926–101.023 | 31.401–31.686 | 2 → 3 |
| 80ms | 100.919–100.993 | 102.747–102.912 | 2 → 5 |

The slower case exposes about 2ms of extra socket/timer work on this PC.
Strict performance non-regression is not claimed. These are benchmark means,
not p50/p95 or a full VLESS speedup. The separate native Xray workflow must
compare identical whole-Check cases before making that claim.

Raw outputs: [before](before-71b.txt), [after](after.txt),
[existing ExactNode/SOCKS regression suite](regressions.txt).
The latter passed in 8.984s, including the late-greeting deadline, cleanup,
stale/network guards and cancellation tests.

## Reproduce

Use separate baseline/candidate worktrees. Copy the archived
[fixture source](nodecheck_startup_backoff_test.go.txt) into each worktree as
`internal/dataplane/nodecheck_startup_backoff_test.go`; baseline71b already
contains its `nodeReadinessProcesses` helper. The candidate already contains
the fixture. The archived source adds no production changes.

Run the same command in each worktree (PowerShell, this PC's Go location):

```powershell
& C:/Projects/RAZVILKA/tools/go/bin/go.exe test ./internal/dataplane `
  -run '^TestExactNodeStartupWaitsForDelayedSOCKSReadiness$' `
  -bench '^BenchmarkExactNodeDelayedSOCKSReadiness$' -benchtime=10x -count=3 -v
```

For regression checks, run:

```powershell
& C:/Projects/RAZVILKA/tools/go/bin/go.exe test ./internal/dataplane `
  -run 'TestExactNode|TestSOCKSReadiness' -count=1
```

The behavioral test requires actual readiness after the configured delay,
without a brittle 100ms upper performance threshold. A loaded machine may
perform its first exchange only after readiness; that valid first success
must not be mistaken for a test failure. The benchmark records the actual
number of greetings for every measured run.
