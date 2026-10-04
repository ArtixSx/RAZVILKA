# CORE: instance isolation for expert engine files

04.10.2026. VLESS reproduced the encrypted backup fixture failure independently:
its fresh draft contained one fixture, while the global expert catalog also
included an ambient WireGuard file. No ambient file or private bytes were read,
modified or removed to repair the fixture.

`engineconfig.Manager.LiveRoot` relocates the fixed allowlisted file catalog
under a trusted instance root configured before use. Empty retains existing
production paths. Read/List, Stage/batch, Validate/Apply, guided editor and NFQWS
mode use the same instance mapping and preserve allowlisted fallback order.
There is no HTTP path parameter or change to production backup inclusion.

The backup fixture now uses an empty temporary live root and retains its exact
one-file assertion. Its failure output reports count/error instead of dumping
decrypted private payload. Root assigned the four engineconfig source files and
new live_root tests to CORE; app test ownership remains CORE.

Regressions inspect live reads, another isolated instance, catalog metadata,
batch staging, actual draft Apply and original backup within temporary roots,
fallback path and guided/mode absence. Targeted tests passed engineconfig
0.536s/app 0.801s. Related Stage/Guided/Mode/PrivateBackup/Restore tests passed
0.945s/5.090s; vet/diff RC0. These are local tests, with no native runtime claim.
