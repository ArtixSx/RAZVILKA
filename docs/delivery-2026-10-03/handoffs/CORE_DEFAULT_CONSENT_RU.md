# CORE: concrete revisioned default consent

Parent CORE `5be9925cfc5526602b0f94441a42d8852e4a0be1` (Root `da187f8`),
itself over CORE `c62cc552` / Root `60c54ae`. Cherry-pick only this slice onto
those accepted primitives. No OPS/VLESS/NFQ/DEFAULT unfinished owner files.

## Durable explicit intent

Existing Config gains optional `DefaultRouteConsent`, schema 1: exact approved
full NetworkPolicy, exact resolved grant/provider class+ID/source IDs+kinds/
canonical private protocols, installation/control sequence, approval/config
revisions and comparison digest. Nil legacy approval grants nothing, including
legacy AllExceptAllowed=true. No new Store, ledger or scheduler.

`Store.ApproveDefaultRouteConsent` uses full current config preimage + existing
file CAS, saves desired policy and approval only, preserves applied runtime and
SafeMode. App is the authenticated explicit writer. Config clone/strict loader
preserve full approval; malformed declared digest/scope/grants refuse loading.
Stale approval stays visible but `CurrentDefaultRouteConsent` is false. Unknown
node/source/kind/canonical protocol cannot be approved by the concrete reader.

Only existing `ReviewedNetworkPolicyCommitImage` may advance approval's current
ConfigRevision when the approved desired policy is unchanged and previously
current. Immutable approval digest/revision stay fixed. All unrelated config
changes, scope/source consent changes, Stop and owner replacements revoke use.
Restore draft's ordinary revision advance also leaves approval stale.

## Concrete readers

New `internal/defaultconsent` has concrete Owner/Review; no constructor from
Reference/DTO/hash/observed PASS. Owner takes actual configured Store slots,
original Gate, actual existing config/node/control paths, and denial-only App
pointer/configured-root continuity. It retains config/node root descriptors and
the existing protected ControlEpochReview. Reads use SAME actual Stores.

Config.OwnerBinding, nodestore.OwnerRoot and ownedfs.RootInfo are readonly
comparisons of original actual target/root descriptors. They create no writer
session/lease/file, reopen no replacement Store and issue no authority. Node
path MUST match the actual original Store root FD, not only a pathname digest.
Linux root UID/mode protections and before/after owner checks remain mandatory.

`Owner.Review(ctx,resolved) -> *Review` reads saved exact approval and fresh
enabled exact node/provenance/source permission/private material. Reference:
Schema, InstallationID, Sequence, ApprovalRevision, PolicyRevision,
ConsentDigest, EngineID, NodeID, Resolved, NodeGeneration, NodeMaterialSHA256.
Initial reference excludes derived Plan/LAN/profile/transport proof.

`Review.Reference()` detached, `MatchesNodeStore(*nodestore.Store)`, `Current(ctx)`,
`WithCurrent(ctx,use)` are the frozen VLESS seam. Every use requires a fresh live
original exclusive operation on SAME Gate, actual config memory+disk/control/
original roots/slots and source/material bookends. Old released context cannot
revive. A newly admitted operation may check the SAME durable intent. Zero/copy
handles refuse. No backdated clock/callback replaces actual time.Now.

Canonical protocol permission comes from bounded private outbound `type` inside
WithSecret. Public Node.Protocol is a display label (e.g. VLESS), never admission.
Material copies stay inside existing bounded Store callbacks.

`Review.AcceptCommitted(ctx,actualAfterConfig,started,finished)` consumes only
the exact original successful shared sanctioned policy CAS: before.Services,
full expected/actual Store postimage + disk, unchanged approval/control/source/
material. It retains a private cloned postimage, not the caller DTO. No renewal
of approval/reference/source/transport TTL; replay/unrelated postimage refuses.
The original private App executor will invoke this for bound handles in the next
consumer hookup; this slice does not silently waive postcommit checks.

## Actual App writer and deployment binding

`POST /api/v1/networkpolicy/review` requires actual authentication + existing
CSRF/origin middleware, original exclusive request, strict bounded JSON,
expected config/policy revisions, full Policy+Grants, exact explicit
`APPROVE_NETWORK_POLICY`. It saves only approved intent, returns live_applied=false.
GET is detached display, cannot issue approval. Private profile approval checks
actual WG profile catalog; missing AWG owner remains explicit refusal. Providers
USQUE/WARP are exact known classes/IDs, never account/route/TUN readiness.

Main supplies actual configured config/node paths through
`App.ConfigureDefaultConsent` after assigning the real Nodes/control owner and
closes retained roots on shutdown. The concrete reader is created by the actual
explicit request. `App.ReviewDefaultConsent` gives consumers the private handle
under original admission. UI hookup, actual default route/probe/adapters/main
effect wiring and fresh NFQ committed/cleanup guards remain the next separate
consumer slice. No whole-policy UDP/IPv6/native Apply PASS is asserted here.

## Checks

Windows Go1.26.5/GOMAXPROCS2/GOFLAGS-p2:

- Focused actual consent/config/App HTTP tests PASS 1.192s/0.405s/0.656s.
- Full defaultconsent/config/nodestore/ownedfs PASS 1.148s/2.946s/4.355s/0.256s.
- Related networkpolicy/default/admission/node-history suite with explicit
  Windows journal models PASS: defaultconsent1.116s/config0.639s/App4.305s/
  main0.294s; Windows vet all touched packages/App/main RC0.
- Real Store/HTTP fixtures cover authenticated/unauthenticated/foreign-origin,
  confirm, full CAS/replay, unknown node/source/kind/protocol, private canonical
  material, disk drift, source disable/generation, Stop, configured slot/root,
  close/zero/copy, detached edits, bookend drift, exact sanctioned commit and undo,
  original context release/new actual operation, unchanged approval reference.
- Linux AMD64/ARM64 vet all touched packages/App/main and full defaultconsent/App
  test cross-build RC0. Binaries `.review-local/core-consent[-app]-linux-*.test`.
- gofmt/diff check RC0. Linux native/race/power-loss acceptance belongs to Root;
  Windows models do not grant production namespace/process/effect authority.
