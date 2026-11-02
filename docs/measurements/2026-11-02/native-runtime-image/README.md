# Native NFQWS runtime image buffers: paired results

[Run 41377833743](https://github.com/ArtixSx/RAZVILKA/actions/runs/41377833743) compares baseline `1e14b1c27e4286fceb6101f1e2b0ae779c1f9ce6` with after `5dc53b9bd4ebe89c58897dfe9aad24c61cbbd863`, sequentially on the same worker in each build mode. Both have identical payload-read/allocation instrumentation, prior protected-tool scopes, complete catalog fixtures, directory fsync and unchanged 14s forward/5s cleanup budgets. Go is 1.26.5 linux/amd64 on Ubuntu 24.04 with kernel `7.0.0-1017-azure`; the reviewed fixture uses Ubuntu iptables `1.8.10-3ubuntu2`. Assets are the existing pinned genuine NFQWS/native fixture assets. Platform classification remains modeled; kernel, tool files, processes, queue, socket, TLS and byte comparisons are actual Linux observations. This is not router acceptance.

The runtime image reader retains **both complete reads** of every member. It first reads into an exact bounded allocation and verifies SHA256, then compares the complete original-FD contents through a fixed 32KiB buffer, including a mandatory EOF check. All eight files and four directories remain held through fresh name/inode/mode/owner/nlink/mtime/ctime/membership closing checks. Ctime is additional evidence, not a replacement for the second byte comparison; coarse filesystem timestamps cannot waive that comparison. No callback, cached image or execution permission is added. Installer/recovery retain their original default verifier.

## Matched complete production core

Production job [125061877561](https://github.com/ArtixSx/RAZVILKA/actions/runs/41377833743/job/125061877561) used AMD EPYC 7763. Both core Execute scenarios passed complete service flow and owned cleanup.

| Measurement | Before | After |
| --- | ---: | ---: |
| Execute wall | 13.094472209s | 12.334399823s |
| InventoryTools.Check callbacks | 382 | 382 |
| Measured callback wall | 5.640121055s | 5.621329866s |
| Member-read attempts | 13,260 | 13,260 |
| Returned payload bytes | 1,084,270,200 | 1,084,270,200 |
| In-process TotalAlloc delta | 5,439,873,832 bytes | 3,566,881,664 bytes |
| In-process Mallocs delta | 8,768,150 | 8,608,736 |

This single paired complete sample reduced wall by 0.760072386s (5.805%) and cumulative in-process allocation by 34.431%. The identical payload totals verify that the second full read was retained. These allocation values come from `runtime.MemStats.TotalAlloc/Mallocs`; they are not peak heap, RSS, retained memory, native child memory or a general speed guarantee. Execute wall is captured immediately on return, before reading the final memory statistics. Callback wall covers the existing inventory callback wrapper, not every source check.

## Failures and actual fault coverage

Production HTTP and LAN tests on **both sides failed at probe1's deadline after two real service flows**, with known cleanup and `recovery_required=false`. The complete three-pass/selection/LAN Apply workflow did not finish; Apply was not reached in this pair. HTTP test wall was 30.78s → 29.37s; LAN HTTP was 33.31s → 31.88s. These failed workflows do not establish successful workflow latency.

Race job [125061877503](https://github.com/ArtixSx/RAZVILKA/actions/runs/41377833743/job/125061877503) used AMD EPYC 9V74. Both core scenarios failed capture deadlines: before 15.010040214s/108 tool callbacks/572,062,920 payload bytes; after 15.020807279s/170 callbacks/789,898,200 bytes. They reached different prefixes and support no latency comparison. Race LAN stopped at probe0 with recovery required. Production and race hardware differ and must not be compared against each other.

The new Linux filesystem models passed normal and race execution: original lease/default-reader equivalence; actual restored-mtime, replaced inode, extra member, replaced root and closed FD refusal; cancellation; FIFO/symlink nonblocking refusal; and full second-read byte/trailing-byte/truncation/closed-FD checks independent of metadata. These use actual files/journals with explicitly modeled payload/installer authority, not native runtime grants. The full production core consumed the official native source. Existing original-source mutation/lifecycle tests also passed; no data race was reported. Both focused jobs remain FAILURE because their broader workflows remain incomplete.

[results.csv](results.csv) records all complete and failed rows. [raw-excerpts.log](raw-excerpts.log) preserves bounded original lines; full downloaded log SHA256 is `3873f4b074b520220832f456727a3fd1f4f069d694ef42931cd4d8c94b076585` (production) and `30d06dacdd252500c1412daf5c0024b6aa29ae2904379e76400990f06bb46ceb` (race).
