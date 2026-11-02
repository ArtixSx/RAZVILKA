# NFQWS metadata comparison

The same actual finite consumer completed on both revisions. `results.json` and
raw core excerpts record the exact jobs, allocation counters and read counts.
The later revision removes only the middle third named-file `Lstat`, retaining
both whole-path observations and the actual held-FD stat; it also adds diagnostic
active-phase counters. Fresh mutation, foreign descriptor, root-only metadata
and strict pointer tests passed.

Observed Execute wall time was 11.295 → 7.632 seconds, with unchanged payload,
tool and version-child counts. These are **single runs on separate CI runners**,
so they do not establish the change's causal speedup or production latency.
TotalAlloc is cumulative allocation, not live memory or RSS.

The ordinary three-probe HTTP test passed (40.75 → 27.13 seconds), but the full
LAN/manual Apply and race scenarios still fail. The 7038 active phase counters
are inclusive: 6 LAN checks cost about 8.4 seconds and prepared-active about
5.8 seconds; these values overlap and must not be added. No router acceptance
is implied. The prior GC fatal remains under investigation.

Exact native jobs: [before](https://github.com/ArtixSx/RAZVILKA/actions/runs/41413955470/job/125173184568), [after](https://github.com/ArtixSx/RAZVILKA/actions/runs/41417804693/job/125185814196). Both corresponding full CI runs passed.
