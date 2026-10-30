# Offline manual service control

This separate operator executable addresses the recovered rc.106 NFQWS2
incident pinned in `productionIncident`. It is not an application updater or a
general configuration editor. The installed `/opt/bin/razvilka` remains intact.

The only command is `razvilka-offline-manual save-manual`, executed as root on
Linux ARM64. Production paths and incident pins are compiled in. There are no
environment or command-line overrides. It never starts the panel, runs an
adapter, changes networking, replays a journal, or deletes recovery evidence.

The operator requires the original installed binary and init-script hashes,
the exact failed and committed plans, matching rolled-back execution records,
both successful retry stages, and the prior running NFQWS2 ownership receipt.
It does not reinterpret that receipt as a fresh process or service-health test.
Applied intent must still contain exactly the three services from revision 11.

Before opening the configuration, it acquires all four actual private restore
lifetime leases in daemon order. Only existing directories and valid existing
markers are allowed. Every journal must be idle; no recovery is performed.
The Stop, hook, execution, self-update, and component-update readers remain
mandatory. An active panel, pending recovery, foreign owner, changed source,
or uncertain observation refuses the operation.

`config.LoadExistingStrict` retains the original finite context and complete
raw file image. It refuses migration, normalization, duplicate/unknown fields,
and serialization changes. One ordinary `Store.UpdateServiceControl` call
changes only `service_control.mode` to `manual` and increments `revision` once,
through the existing file lease and exact raw-byte CAS. An already-manual
configuration is a checked no-op, with no revision increment. Closing checks
must confirm the complete after-image and preservation of credentials,
autonomy state, runtime files, receipts, and the installed executable.

The command emits one sanitized JSON result. It never emits raw settings,
keys, error details, process arguments, or recovery documents. A failure after
the write boundary is reported as `write-uncertain`; it does not retry, rewrite
the old configuration, or start the panel. Preserve the result and inspect the
specific stage before another action.

**Manual mode only disables automatic service Apply.** Normal installed-panel
startup can still perform boot recovery, maintenance, subscription work,
scheduled updates, and checks. This executable is not a full maintenance pause
and does not solve the application's local-update delivery path. Starting the
original panel is a separate owner action after reviewing the result.

Tests use private fixture coordinates, real Store/FileTarget CAS, and real
private restore leases. Fixture pins do not create a production path override.
Native router acceptance and client service reachability remain separate from
those tests.
