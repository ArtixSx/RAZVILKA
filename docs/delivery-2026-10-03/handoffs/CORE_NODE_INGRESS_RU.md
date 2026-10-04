# CORE: typed node-history admission before incoming private writes

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
