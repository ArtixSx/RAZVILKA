# CORE: regular WG catalog registration

04.10.2026. Dependency: Root accepted NET factory
`b60d84b2ae05ce01cb8af52026b7c0cadbcec11c`, normal merge through Root
`b3440f5efeb5b26ab5241015b1e0162b4a62d15c`. CORE connects the factory in the
ordinary `App.Handler` behind existing security/operation middleware. Exact WG
collection/ID POST, PUT and DELETE use the same exclusive admission as private
restore; the handler reuses that request lease rather than acquiring it twice.

`newDataplaneManager` registers one explicit `wireguardprofile.Store` at
`filepath.Join(stateRoot, "profiles", "wireguard")` on its ordinary WG adapter.
Manager catalog and runtime use that same instance. Construction and a cold
List are read-only and do not create the state root. The profile path is not
discovered from HTTP and does not enter the mutable self-update snapshot.

New integration tests call the ordinary Handler: auth/Origin refusal before
catalog mutation, create/replace/delete observed under exclusive admission,
release after the request and the registered runtime seeing the same bytes.
Actual main constructor tests verify catalog identity and read-only cold state.
Addressed WireGuard/SelfUpdate app tests passed 7.405s and cmd tests 0.684s.
Vet and final compilation results are sent with the finished SHA to Root. No
network, native runtime or router execution is claimed.

This connects metadata CRUD, not named service assignment or check/Apply proof.
Existing service writer/policy fence remains required; named WG route options
and a revision-bound ordinary assignment are a separate CORE consumer portion.
No DraftImage bypass, live Apply, default-route capability or automatic reserve
selection is added; syntax-only metadata cannot become trusted runtime evidence.
