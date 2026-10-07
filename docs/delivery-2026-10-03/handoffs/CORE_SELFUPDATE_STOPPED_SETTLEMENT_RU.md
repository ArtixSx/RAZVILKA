# CORE D11: explicit stopped rollback settlement consumer

07.10.2026. Checkpoint B follows accepted A `5b90f42f8fd0f35aee44b25428ac2528ef550ce1`
and Root `7e8304ae107b7bc4cb56dc5e0cdb7c3c387fdd02`, normally merged as
`c9c0c0c2de3b2a04e28c1386454b7fd9555930d7`. Before implementation OPS explicitly
confirmed exact signatures, synchronous lifetime and readonly scanner/writer
compatibility. OPS provider, journal, control protocol and runtime owners are
unchanged. No held Xray `c2` or owner WIP is included.

## Optional provider and actual binding

The required App `SelfUpdateFileAdapter` interface is unchanged. A private
optional interface consumes exactly the existing OPS
`StoppedSettlementEligibility(ctx,id)` and
`SettleStoppedRollback(ctx,id,SelfUpdateStoppedSettlementAuthority)` methods.
Missing provider or trusted readonly `SelfUpdateFiles.JournalReadGuard` refuses.
Legacy/mixed reader2 review eligibility is false, never a permissive default.

The actual fixed Linux constructor assigns `JournalReadGuard` to the accepted
A retained scanner, requiring exact reader3 and using the original callback
context. Nonproduction overrides and other platforms keep both effect provider
and reader binding unavailable. Public DTO/env/path values cannot issue them.

## Explicit action and admission

Authenticated POST `/api/v1/self-update/recovery` accepts the existing strict
transaction/revision/confirmation DTO with action `settle-stopped-rollback`.
It retains auth, Origin/CSRF, current-ID matching, installer-lock refusal,
bounded original request context, existing `Operations.Exclusive` and
independent recovery fences. Fixed CLI is
`self-update-files settle-stopped-rollback <transactionID> <revision>`; this
action additionally requires canonical positive decimal revision. The existing
A early helper gate precedes the fixed consumer. No caller path/permission or
proof data is accepted.

The action is classified only as `replace-to-rollback`. Its dedicated branch
calls the exact OPS provider before opening any CORE file Store. OPS retains
the sole existing file writer and actual six restored files/hash/metadata,
private restore, ECHILD/dead supervisor, original/captured process identities
and fresh complete `selfUpdateRuntimeInactive -> Manager.VerifyRuntimeInactive`
producer. CORE does not manufacture native process/runtime evidence.

The CORE Check callback freezes the complete validated independent Stop, then
re-reads canonical current/request state before and after config/independent
guards. Every call requires matching transaction, installation, reviewed
revision and exact pre-Stop plus one epoch with overflow refusal. Both callback
and original operation cancellation are checked; a cancelled callback returning
nil cannot complete the action. Config is rechecked after independent readers.
CORE holds no config/control lock across the provider or callbacks.

AdmitReaders requires matching transaction and exact reader3, then calls the
trusted A scanner with the provider's callback context. OPS already checks the
sealed retained controller fleet before AdmitReaders; CORE does not duplicate
inventory or execute version probes/Start after Stop. `WithTimeout(ctx,...)`
preserves OPS's active same-directory/SameFile `writerObservation`. The scanner
does not acquire a second writer. After OPS returns, CORE reads the published
schema3 terminal binding and closes the original scope checks again.

## Result and recovery

Success reports `stopped_settlement_completed=true`, `live_accepted=false` and
`rollback_accepted=false`. Independent Stop remains byte-identical and
`recovery_required=true`; ordinary Resume/startup/live remain fenced. Failed
settlement has a fixed sanitized HTTP diagnostic. CORE does not call
`InitializeSelfUpdateControl`, `RecordSelfUpdateStopped`, `Finish`, `Live` or a
command/process producer on this path. A file-terminal/helper-publication cut
retries through the same OPS method and fresh guards, without effect replay.

## Verification scope

Targeted actual HTTP/auth/Origin/strict DTO/config/file-journal tests passed on
Windows with explicitly modelled supervision/runtime evidence. They cover
successful data-only publication, interrupted publication and repeated retry,
byte-identical current/request Stop and unchanged config/files/no new commands
or live acceptance; missing independent Stop/provider/reader, legacy2,
wrong-ID/revision/epoch, unknown command, independent/runtime refusal and
cancel-nil/config/Stop drift. The writerObservation bridge is exercised by real
readonly `RequiredReadVersion` during the real retained writer callback.

Initial addressed B suite passed App4.720s/cmd0.228s. Portable actual CLI
subprocess checks canonical revision, no caller fields, no provider fallback
or public-root creation. These CLI missing-platform cases explicitly skip on
Linux so regular tests cannot touch fixed native production paths. Root owns
actual fixed Linux CLI/provider/aggregate acceptance; model success is not a
native or full D11 claim. Related checks and cross-compilation results accompany
the finished commit packet. No CORE Linux execution/race/native/router run.

Final related App/cmd SelfUpdate and retained-reader regressions passed
10.693s/1.126s. Windows App/cmd vet, Linux amd64 App/cmd vet and test
cross-compilation, ARM64 main build and diff check passed. Temporary binaries
were removed. Go sources remained unchanged throughout these final checks.

Capability `-self-update-schema` remains0. Reviewed Resume/new control epoch is
a separate future checkpoint after B acceptance and is not implemented here.
