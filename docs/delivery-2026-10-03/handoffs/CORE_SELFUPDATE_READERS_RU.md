# CORE D11: immutable reader3 and retained startup consumer

07.10.2026. Checkpoint A consumes the accepted OPS retained helper/file scanner
and parser at Root `1a5b678319ea3c45316dfd4e031ee4c54bee2ff4`. The separate DNS
fixture correction is parent `5341999150c43742fb33e1408047b41f025925fe`; no DNS
production guard is weakened. OPS dependencies already in that ancestry are
`b1f34a9d99eeb959dd90daebd20b5351cd362aa1`, mandatory reader2 compatibility
`08dbc49e137870854be9101abb215ca344ee1e02`, metadata/private CAS follow-ups
`7074022a1430a66d3aabf5995be0a9c7cf077313` and
`cc5e32ec080b632f458a1556bbf4e15030218442`, and native fixture repair
`dd422b30c3a0aa50c45cef4a4d268e009fd12bc6`.

## Exact CLI contract

* Standalone `-self-update-read-version` returns exactly `3\n`, exit0 and empty
  stderr. This immutable format capability runs before command dispatch,
  scanner, flag/bootstrap processing or any Store/admission/control access.
  It remains available under durable Stop and damaged retained journals. There
  is no scanner-to-metadata-child recursion and no 3c/Start grant.
* Standalone `-check-self-update-state` returns exactly `{"ok":true}\n`, exit0
  and empty stderr if the existing OPS `RequiredSelfUpdateJournalReadVersion`
  confirms a supported retained maximum. It uses only fixed `/opt`,
  `/opt/var/lib/razvilka/self-update` and
  `/opt/var/lib/razvilka/self-update-files`; public config/path flags and env
  cannot relocate this check. Unsupported/future/corrupt/unsafe/orphan retained
  evidence returns exit3, empty stdout and a fixed sanitized diagnostic.
  Mixed arguments, boolean assignments and double-dash aliases return exit2
  before any scanner or bootstrap. Both commands require the exact single flag.
* `-self-update-schema` remains0. Readability is not installation, replacement,
  live acceptance, stopped settlement or Resume authority.

The scanner has a ten-second context bound. It uses the accepted OPS bounded
current and retained helper/file receipt/image inventory without executing any
controller probe, writing journals, repairing permissions or deleting history.
Known pending formats can be read; existing Pending/Stop/operation admission
still refuses runtime effects or replay. Reader checks add no effect authority.

## Actual early consumers

Main checks retained formats before configured helper/file recovery, legacy
staging permission repair, private restore, migration/default creation and
ordinary Store/runtime bootstrap. Effect-bearing early dispatcher paths also
check before the real producer: NFQWS managed supervisor, component package
supervisor and its supervision probe, installer/command helpers, runtime
quiesce and matching file actions. Component refresh CLI checks before manager
fetch/write work. Existing command shape validation and independent Stop,
auth/CSRF, private filesystem, ownership and CAS checks remain in their owners.
Readonly current/status and immutable metadata do not receive runtime authority.

The production entry point constructs fixed roots directly. Explicit private
root arguments to the internal main/dispatch helpers serve only isolated tests;
the test fixture env is compiled solely in `_test.go`, not the application.

OPS agreed the shell ABI and fail-closed policy. Installed managed reader2/3,
future or unknown responses do not allow legacy raw replacement, including new
reader3/schema0 with an empty successful scan. Only the existing verified old
unsupported-flag legacy path without retained/control artifacts remains. The
scanner does not inspect an arbitrary selected external shell backup or replace
other node/private gates. OPS owns the separate shell consumer
`be7e4c9a659fbf5912cd24f38f4c902ce25091fc` and follow-ups; CORE edits no scripts.

## Verification and limits

Windows targeted CLI/early startup/helper/Stop/read-only/downgrade refusal
regressions passed0.739s; related cmd SelfUpdate/NodeHistory/NFQWS command/component
regressions passed1.251s. The separately built actual Windows application
returned canonical `3\n` and `0\n` with empty stderr. Windows cmd vet, Linux
amd64 cmd vet/test cross-compile, ARM64 main build and diff check passed.
Temporary binaries were removed. No Linux execution/race/native/router run was
performed by CORE.

`TestSelfUpdateRetainedReaderVersionsAndFutureCLI` prepares actual six-file
schema2 and data-only stopped schema3 receipts with explicit fixture-only
evidence; no process or production settlement is invoked. It verifies scanner
reader2/3 boundaries, successful real CLI, byte-identical images and rejection
of a future archived receipt despite readable current state. The actual OPS
filesystem scanner requires Linux UID0, so this case explicitly skips elsewhere;
Root runs it on the accepted source in its native window. Portable metadata,
empty-scan and early refusal tests run on Windows.

Checkpoint B (explicit independent stopped settlement consumer) and reviewed
Resume/new epoch remain absent and must be separate accepted changes after A.
No Xray factory/main `c2` or owner WIP is included; capability remains closed.
