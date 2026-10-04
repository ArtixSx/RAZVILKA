# CORE: actual D11 main/CLI and stopped compensation checkpoint

04.10.2026. Production registration replaces the previous nil provider on Linux
at the fixed `/opt` installation/helper/file/control roots. Other platforms and
private root overrides retain no production effect provider. Main connects the
concrete OPS `NewSelfUpdateFileAdapterWithAuthority` and initializes/seals
`Updater.FileAuthorityReview` against the existing independent control authority.
Initialization never clears Stop, changes a sealed installation identity or
renews the epoch of a retained review.

## Actual consumer

The existing early command dispatcher now handles installer helper, command
worker and runtime quiesce before ordinary bootstrap. Installer helper uses
`RunInstallerHelperWithAuthority` around the existing `SelfUpdateFiles.RunHelper`;
it no longer omits the OPS helper identity seal. Command helper uses the same
CORE Stop/admission/runtime callbacks. Quiesce first verifies the exact worker,
current child, old panel absence, private snapshot and command journal through
`RuntimeQuiesceAuthority`, then uses the existing registered Manager Deactivate
and fresh `Manager.VerifyRuntimeInactive`. Independent restore/execution fences
are checked before and after. No old deactivation report is used as proof.

The Manager aggregator is the accepted DEFAULT `dfe82e1b3156cd9836b89fc76cd2c03a32203257`,
normally merged through accepted Root `1f197d9f580648663557ec95d5b692a2fccb06a0`.
The helper constructs one private registry with all ordinary adapters and
ScopedDNS. Missing owner observer support refuses before Deactivate effects;
fresh actual runtime observation remains solely in the Manager. No adapter
implementation, Manager/Plan file or owner lifecycle was edited by CORE.

Main consumes the fixed S99 `-self-update-job` and `-self-update-helper-pid`
arguments, requiring an actual matching supervised startup before permission
repairs, migrations, default files or ordinary Store bootstrap. This PID is the
command worker, distinct from the installer PID retained in the helper job.
The same distinction is preserved throughout the startup node recovery guard.
Absent/mismatched arguments cannot borrow a pending installer's startup lease.

## Stop and matching rollback

`operationgate.WithSelfUpdateStoppedEffectAdmission(ctx, controlRoot, id,
sealedInstallationID, sealedPreStopSequence, reviewedRevision, action, effectID,
begin)` requires canonical matching Stop intent, installation ID, transaction ID,
revision and current sequence exactly sealed sequence plus one. It admits only
bounded cleanup/rollback syscalls under the existing control lock. Wait, Store
locks, payload preparation and fsync remain outside it. The record is unchanged.
OPS remains the sole exact private target registry/ownership/quiescence owner.

Known stop/quiesce worker/child commands and rollback-file0..5/private restore
classes are eligible; Start, install, live, wrong effect class and read-only
effects are refused. Normal admission still refuses every Start after Stop.
The existing authenticated HTTP recovery path now carries an action-specific
matching scope. Known file rollback/private restore can proceed under matching
Stop; independent recovery fences, revision and provider proof still apply.
Unknown commands cannot replay or restore without valid observation. Neither
rollback nor resolve-unknown grants Resume or live acceptance.

## Verification and remaining required portions

Before the DEFAULT merge, Windows addressed SelfUpdate tests passed:
operationgate 0.790s, app 6.164s, cmd 0.559s; vet/diff RC0. Linux amd64 main tests
compiled, Linux vet passed and ARM64 main built; temporary binaries removed.
After binding to the accepted aggregator, addressed SelfUpdate plus
NetworkPolicyManager tests passed: operationgate 0.863s, app 6.487s, cmd 0.588s,
dataplane 0.124s; Windows vet/diff RC0. Final cmd SelfUpdate repeat passed 0.525s.
Final source Linux amd64 main test compilation, Linux vet and ARM64 main build
passed; fresh retained NodeHistory tests passed 0.559s. Temporary binaries were
removed. Model process observers are explicit; no CORE native/router/race run is
claimed.

Capability remains0 for concrete outstanding producers, not missing main
registration. OPS must admit the initial installer `cmd.Start` with sealed
authority and provide stopped data-only file/helper settlement. Resume requires
that settlement, fresh complete runtime absence and a reviewed new control
epoch; current code does not clear Stop. NET/VLESS/LAN owners provide their
observer methods; NFQWS identified its legacy lease ambiguity and Root assigned
the actual managed process/kernel ownership lifecycle producer. Missing or
ambiguous owner evidence remains refusal even for an unused adapter. Full D11,
production capability2, native Stop/candidate/rollback/Resume acceptance and
physical power-cut remain open.
