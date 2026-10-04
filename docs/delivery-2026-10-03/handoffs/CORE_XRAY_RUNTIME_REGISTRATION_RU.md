# CORE: ordinary Xray runtime registration, held checkpoint

04.10.2026. Ordinary main constructs the accepted `app.NewXrayNodeRuntime`
before registering Xray with the existing Manager. Its trusted factory options
bind the same private NodeStore, engine config manager and state root used by
the application. Fresh network observation calls `systemprobe.FreshWANProfile`
with the original operation context. There is one registered Xray owner and
no injected NodeTUNProbe, public launch permission or additional journal.

The narrow CLI rollback branch constructs its existing cold Manager and returns
before opening NodeStore. Cold/self-update constructors retain generic runtime
inactivity observers and never create a private catalog to prove absence.
Ordinary node-store opening moves before Manager construction; Sing-box later
receives that same store through its unchanged materializer binding.

This checkpoint is **HOLD**, not production acceptance. Root requires preserving
existing generic `xray` routes. The accepted factory currently selects scoped
Xray mode for its whole lifetime, whose route validator requires exact node
IDs. VLESS must provide explicit mode dispatch from the frozen plan before any
effects, inside this one adapter. A failed scoped operation must never fall
back to a generic route. Root owns review and actual integration after that
finished dependency; this main checkpoint must not be merged alone to enable
the new constructor. The shared execution registrar is another independently
owned dependency, and construction supplies no receipt/review authority.

Portable tests exercise the actual startup constructor with a real private
NodeStore, exact Xray history and a modeled network callback: materialization
uses the same catalog, rejects foreign-network history, preserves context and
cancellation, and writes no runtime/stage/backup/catalog state. Missing configs,
relative state root and missing fresh observer refuse instead of selecting
generic Xray. Existing cold owner/catalog and CLI reader tests pass too.
Targeted cmd tests passed 0.261s and the full cmd package passed 5.674s;
vet/diff RC0. Linux amd64 cmd test compilation
and Linux arm64 main build passed; temporary outputs were removed. No Linux
execution, TUN, packet, LAN, restart or rollback acceptance is claimed here.
