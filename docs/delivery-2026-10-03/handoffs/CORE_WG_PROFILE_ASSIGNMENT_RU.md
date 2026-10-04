# CORE: reviewed named WireGuard service draft

04.10.2026. Ordinary `App.Handler` service PUT now accepts a named
`wireguard:<id>` assignment with both `expected_revision` (whole configuration)
and `expected_profile_revision` (64 lowercase hex). Its private lookup uses the
same catalog registered by the runtime owner under exclusive operation
admission, serialized with profile CRUD. The persisted ServiceState contains
`wireguard_profile_revision`; the caller cannot replace the reviewed hash with
a different state field. A stale configuration/profile, malformed binding or
missing review refuses without changing intent. Withdrawing the same retained
route remains possible after its profile disappears, using whole-config CAS;
that operation cannot acquire a new profile binding.

`Store.UpdateServiceIfRevision` retains ordinary UpdateService normalization,
policy fencing, single revision increment and disk rollback. No DraftImage
shortcut is used. Reading and all saves validate nonempty binding shape across
desired/applied/suspended services; legacy empty metadata remains readable.
The onboarding view explicitly copies its existing subset, with whole config
revision fencing additional reviewed bindings.

Read-only route options expose imported metadata with Ready/Running false and
the exact profile revision. Choosing such an option stages intent only; it
does not make a reserve profile an automatic fallback or live evidence.
Service rows expose desired/applied revisions and treat their difference as a
dirty/stale plan. Ordinary manual plan construction checks the current same
catalog revision, refuses ID-only legacy Apply, and carries the frozen Route
field accepted from DEFAULT 70f4e01. NET must independently recheck that revision
before lifecycle effects. DEFAULT owns its compiler's config-to-path binding.

Regressions cover actual protected Handler auth/origin, exclusive catalog
lookup, successful and stale whole-config CAS, profile drift, missing/malformed
review, retained disable, ordinary plan binding and legacy refusal. Config
tests verify persisted shape, draft-import rejection and the ordinary automatic
permission fence. Initial targeted tests passed config 0.334s/app 2.627s; full
config/routes passed 2.321s/0.193s; related app subset with explicit Windows
default-journal fixtures passed 13.061s. Vet/diff, all-package test compilation
and Linux ARM64 main build RC0. No native WG/LAN readiness is claimed.
