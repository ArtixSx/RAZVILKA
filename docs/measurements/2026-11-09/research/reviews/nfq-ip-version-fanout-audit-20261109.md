# Original IP version fan-out audit (2026-11-09)

Scope: read-only source trace at local HEAD aa24c9a0 and actual lifecycle 6df3d753 manual Apply evidence. No production change.

## Actual evidence, not completion

lifecycle-6df3d753/managed-production.log:2850-2875: original Apply activation 16.147175795s; original native apply 19291ms; deadline at lan-preflight-inventory-nfq-consumer-open; rollback failed. ToolCheck1260 /7.256772016s, actual version Starts[94,94,1240], metadata6040. Owners439 /3.641402465s. These inclusive phases must not be added. The close-retry scenario also failed before its cut; older0f success cannot be carried to6df.

## Why IP is frequent

- startuptools/tools.go Check retains context via WithTimeout, locks same original lease, calls current(...,true).
- review_linux.go current invokes Provider.WithCurrent and versionBatchCurrent with its held context.
- netidentity/provider.go WithCurrent uses boundedContext(parent), not Background; observation marker survives.
- version_batch_linux.go versionBatchCurrent always runs b.read(...,2) for IP, including when retainedVersionFact is valid. Every actual child retains its pre-Start and closing complete metadata observations.
- version_fact.go deliberately retains only TWO fixed xtables version strings inside a single original readonly observation.
- docs/measurements/2026-11-01/native-version-fact/README.md documents get_libbpf_version potentially reading /proc/self/maps: IP is a runtime observation, not admitted as a static fact.
- native version_fact tests deliberately assert repeated/nested [0,0,1] Starts and actual IP Cmd.Start EAGAIN revokes fact. Removing an IP Start would alter an existing required refusal boundary.

## Call fan-out

NFQ verifyLAN -> observeActiveTools -> verifyLANObserved -> runtimeFrozen.Verify -> NetworkPolicyChecks.observeInventory -> boundary/Provider -> nfqConsumers -> e.owners -> inventory.CheckTools. This chain preserves the observation context. Existing pure current/health/inspect wrappers and pre-Add four callbacks share the original loan as intended.

Each e.owners invokes one fresh CheckTools; actual phase count439 already accounts for a substantial subset. forward brackets its work with two owners; each nfqConsumers brackets process/queue/receipt work with two owners and additionally observes current. Inventory capture independently calls TOOLS_A and TOOLS_B. nfqwsScopedTypedRunner checks tools before each original typed mangle read. These are explicit owner/read bookends, not accidental duplicates removable without a different proof.

94 xtables versus1240 IP starts is evidence the existing readonly static fact is being reused; broad context loss would increase xtables alongside IP. A broader readonly bracket cannot reduce mandatory IP subprocesses under the present contract. No concrete context propagation bug found.

## Safe follow-up

Do not add an IP result cache or skip existing Check calls. Inspect actual io.Copy parent attribution in next native profile, then consider allocation/pipe implementation that preserves every original subprocess Start, output bytes/bounds, metadata/source checks, cancellation, and joined Wait. Any semantic change to IP observation requires separate original-source research and independent review; the current audit grants none.
