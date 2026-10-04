# CORE: accepted owner entry points

04.10.2026. The ordinary App.Handler registers exact GET
`/api/v1/sources/offline` before the existing sources subtree, using CLOUD
8ad2533's saved-catalog handler and the unchanged security/operation chain.
The actual protected Handler regression verifies authenticated read, refused
unauthenticated read, POST 405, offline/read-only labels, Ready false and
unchanged files/state. Existing token-mode read policy is unchanged; the
protected fixture configures ordinary login credentials.

The actual early command dispatcher registers NFQWS ec275f's
`nfqws-managed-process-supervisor <32lowerhex invocation>`. Arguments cannot
carry paths, commands or command JSON. Existing trusted dataplane settings map
to the same `runtime/nfqws2` owner suffix and independent self-update control
root. The producer supplies the return code and revalidates its existing
immutable intent and Stop authority. Dispatch initializes no control or marker;
missing intent refuses before daemon startup. A production process launch or
scoped kernel permission is not created by this registration.

The ordinary cold main constructor regression uses nil Configs and checks the
registered proxy/WG/NFQWS typed inactivity observer contracts without creating
runtime or catalog files. Availability is not fresh absence proof. Root's
native57 uninstalled proxy executable boundary remains assigned to VLESS;
complete platform/kernel/process observations and missing ScopedDNS/LAN owner
proofs still determine D11 eligibility.

Accepted owner changes were consumed by normal merges, including proxy
322bc1c/0c9af4f, NET b6d4acb and VLESS 643ed62. New main/App registration tests
passed cmd 0.095s/app 0.416s; vet/diff RC0. No new native runtime readiness is
claimed by these local registration checks.
