# Native NFQWS metadata comparison, 2026-11-01

This experiment reduced repeated metadata work; it did **not** establish a completed probe or LAN workflow on this runner. All four script outcomes in each job were failure. The existing 14-second probe and five-second cleanup limits stayed unchanged.

The reference was `b0d6db98be420e581909e439fb6ab53b10b8b102`: production code from `5415a6ee`, plus measurement-only counters, cumulative profiles and identical native fault regressions. The after revision was `c21256a818c3b5d4676005141f81a6f1f443aeb7`. Each build mode ran both revisions on the same GitHub runner, using Go 1.26.5. Production and race results are separate experiments.

| Mode | CPU | Execute before / after | Inventory Check calls before / after | Check wall before / after | Metadata traversal attempts before / after | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| production | AMD EPYC 7763 | 15.341111910 / 14.597642019 s | 381 / 381 | 7.863359523 / 7.232780854 s | 3548 / 3114 | Both failed; deadline refusal preserved |
| race | AMD EPYC 9V45 | 15.010660849 / 15.007755809 s | 128 / 141 | 3.993842943 / 3.937627901 s | 1010 / 1068 | Both failed during capture; different completed prefixes |

The completed native three-version Check measured **8 → 6** metadata traversals in both modes. Across the comparable production execution, traversal attempts decreased by 434 (12.23%). Its measured elapsed reduction was 0.743469891 seconds. These are measurements of failed executions, **not** successful workflow latency or router readiness. The race run performed a different amount of work before its deadline, so its total attempts are not a reduction comparison.

Each actual version subprocess still checked the entire original FD/path/ctime/extension/absence graph before Start and after Wait. Only two duplicate batch checks inside the same original read-only observation were removed; full byte checks remained at observation opening and closing. Unscoped checks kept their original behavior. Actual protected-image/membership mutation, callback/version failure joins, cancellation/Close, copied/late borrowers and effect refusal regressions passed before and after, including race. The real WAN/bridge/two-client physical reader test also passed in both revisions; full LAN Apply was not reached because the preceding actual probe timed out.

The counters record attempted metadata traversals, including failed attempts. Inventory Check timing delegates every original callback but excludes other direct tool checks and outer byte brackets; total Execute/profile timing includes them. No network observation, kernel result or effect authorization was reused.

Evidence:

- [Production job](https://github.com/ArtixSx/RAZVILKA/actions/runs/41271187434/job/124744126893), full-log SHA256 `5bde910bab6a82fcf7bf1dfb4661f1f924120646e2c78564b77903601967b3d4`.
- [Race job](https://github.com/ArtixSx/RAZVILKA/actions/runs/41271187434/job/124744126880), full-log SHA256 `95f23eca158946f93c511695beb4c335b7a02e61e9d13262bb29a4b73707e6b4`.
- [CSV](results.csv) and [bounded verbatim log excerpts](raw-excerpts.log).

Platform/Home classification was modeled explicitly in the tagged fixture. Artifact bytes, protected source descriptors, real queue/process/packet observations and cleanup were actual. This is isolated Linux CI evidence, not NC1812/router acceptance.
