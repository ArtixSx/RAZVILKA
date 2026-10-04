# CORE: typed node-history admission before incoming private writes

Finished actual registration follow-up: Root accepted OPS reader3
`a83614c8b731c2351aef553b1f259979d5562d24`, NodeStore inspector
`1e10c7209c9115f51033dabafa23f71174407d8b` and providerfeed callback
`d572a45bf61419f15b0561698816fa2200ef5a9b`; CORE normal-merged those
finished commits without owner WIP. Manual import invokes the pure incoming
inspector after canonical/partial acceptance, then the existing sanitized
material admission before Import. Actual main binds that same OPS CheckWrite
to the app and feed manager after Open and before any workers start. Every
feed page, including a cached 304 page, uses the owned providerfeed guard.
Its existing pre-fetch retry reservation remains intact; incoming body,
cursor, country, expiry and canonical material writes require admission.

RAW check/route writes now use NodeStore's immutable exported
XrayHistoryReadVersion2, replacing the temporary local constant. RAW import
minimum1, RAW Xray history2 and unchecked XHTTP3 remain distinct; OPS takes
the maximum with actual current/retained images and requires every retained
controller to cover it. Exact immutable metadata version flags stay read-only
under Stop; no additional runtime-start gate was introduced for those flags.
Manual/feed refusal responses are sanitized HTTP409 with stable compatibility
codes. Typed inspector failure, missing/old controller, panic or cancel-after-
nil cannot persist unchecked XHTTP. No network activation is granted here.

Actual Handler regressions cover RAW/XHTTP, nil/reader2/reader3/panic/cancel,
held operation admission and unlocked Store read, exact one callback, retained
private bytes/generation on refusal, preserved minimum after success and no
private response strings. Startup tests verify shared callback/context, no
constructor probe, compatible RAW2, rejected XHTTP3 and cancellation. Related
cmd/app/updatecheck/nodestore/providerfeed tests passed
0.262s/11.770s/0.810s/0.812s/2.664s with Windows journal tests enabled;
vet/diff RC0. Linux amd64 cmd test compilation and Linux arm64 main build
passed; temporary outputs removed. Root owns actual Linux/native integration.

The historical first-checkpoint description below is superseded only for its
pending manual/feed and OPS reader3 dependencies. Held Xray constructor
`c2f698b` remains absent from this branch; generic/scoped runtime dispatch and
full D11 stopped-runtime settlement remain separately owned work.

04.10.2026. This first checkpoint covers private restore only. After strict
backup validation and all participant-availability checks, under the existing
exclusive operation admission, `restorePrivateDraft` obtains the incoming
NodeSnapshot's minimum reader from the accepted NodeStore typed validator. It
invokes the trusted startup-bound `NodeHistoryWriteGuard` before RestoreOnline
creates a prepared restore record or writes any incoming participant. The
guard runs without a Store lock and receives the original operation context.

Missing guard refuses RAW Xray history2 and unchecked XHTTP material3. Legacy
material1 keeps standalone compatibility; a bound guard is still invoked for
it so OPS can enforce a higher current/retained requirement. Errors, panic and
cancel-after-nil refuse before writes with sanitized preflight status; callback
failure details never enter private restore responses. No old data is deleted
or automatically adopted. OPS owns controller-fleet scanning and actual
executable read-version probes, independently of the self-update journal ABI.

Actual restore fixtures cover incoming minima1/2/3, missing/error/panic/
cancel-nil/allow, exact single callback, original context and exclusive gate,
unchanged nodes/config/custom/device state on refusal, secret-free failure
responses and preserved typed minimum after an admitted restore. Standalone
legacy encrypted NodeStore backup roundtrip remains covered. Related app
PrivateRestore/PrivateBackup/Operations/NodeEngine/XrayNode/NodeImport tests
passed 6.858s with Windows journal tests enabled; vet/diff RC0. Native/race and
production executable probes are not claimed by this checkpoint.

Dependencies: accepted NodeStore `516f014`/`b0d27a9`/`30b432f` and CORE RAW
minimum correction `c1aed6e`. This branch is `sol/core-admission-20261004` in
the assigned sol-core worktree; it excludes held main-constructor `c2f698b`.
Manual import and feed admission/main binding await the separately agreed
XHTTP RequiredImportReadVersion/HistoryWriteAdmission API. OPS reader3 scanner
and candidate-admission follow-up is also required for production admission.
