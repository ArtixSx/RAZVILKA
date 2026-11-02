# Original extension pathname: paired native results

[Run 41383456657](https://github.com/ArtixSx/RAZVILKA/actions/runs/41383456657) compares baseline `5277d4f59180dbe156d2e86d044cd0d149de6bfd` with `59998874d106d0c40a43ff91eb83b48dede7b7e3`, sequentially on the same worker within each build mode. Both already have conservative two-pass runtime images, the read-only runtime observer, directory fsync and identical counters. The execution change derives the extension directory pathname from the original acquisition instead of repeatedly evaluating symlinks. The intervening diagnostic-only stage labels and measurement documents do not change successful execution. Budgets remain 14s forward and 5s cleanup.

Both complete named node/link/negative-lookup scans, every held image FD/name metadata check, actual directory open/membership, each actual child and outer full SHA checks remain. Acquisition retains only exact original alias/profile/self/target derivation. The failed `37b3efe2` experiment is not treated as success: its directory `FileInfo` comparison incorrectly included atime refreshed by real acquisition. `59998874` fixes that false refusal with the existing directory `sameNode` semantics and adds an actual metadata-refresh regression. No file CTIM or byte comparison was relaxed.

## Complete production samples

[Production job 125079044065](https://github.com/ArtixSx/RAZVILKA/actions/runs/41383456657/job/125079044065) used AMD EPYC 9V45, Ubuntu 24.04/kernel `7.0.0-1017-azure`, Go 1.26.5 linux/amd64 and the existing pinned official NFQWS assets/Ubuntu iptables `1.8.10-3ubuntu2`.

| Measurement | Before | After |
| --- | ---: | ---: |
| Core Execute, complete flow and owned cleanup | 9.851421675s PASS | 8.789452066s PASS |
| Core inventory tool callbacks | 382 | 382 |
| Core callback wall | 4.639569673s | 4.095603930s |
| Core complete metadata traversal attempts | 2,571 | 2,571 |
| Core actual version child starts, IPv4/IPv6/IP | 175/175/386 | 175/175/386 |
| Core member-read attempts / returned payload bytes | 13,260 / 1,084,270,200 | 13,260 / 1,084,270,200 |
| Full HTTP test: three passes, selection/manual choice | 33.20s PASS | 31.35s PASS |
| HTTP aggregate tool callbacks / metadata traversals | 1,172 / 7,776 | 1,172 / 7,776 |
| HTTP actual version child starts | 528/528/1,164 | 528/528/1,164 |
| HTTP member-read attempts / returned bytes | 71,772 / 5,868,796,440 | 71,772 / 5,868,796,440 |

This single matched complete core sample reduced wall by 1.061969609s (10.780%); the complete HTTP test reduced by 1.85s (5.572%). These are one worker's sequential samples, not a general latency guarantee. Callback wall covers the existing inventory wrapper, not every source check. Identical attempts/children/bytes show that complete reads and actual commands were retained. The separate late-original-Wait/cleanup-retry scenario and all four source/runtime/control/environment closing-revocation tests passed before and after.

## Remaining failures and actual fault evidence

The production LAN scenario completed three probes and selection, then failed Apply: before 62.14s at `inventory-consumer-close` with deadline exceeded; after 63.89s at the same stage with source missing. Apply/owned LAN Stop was not completed. These different failed prefixes do not establish LAN speed or readiness. Both production and race focused jobs remain FAILURE. [Full CI 41383456629](https://github.com/ArtixSx/RAZVILKA/actions/runs/41383456629) also failed in the DomainTCP standby/original-writer and Xray original-record model tests on this isolated baseline; no full-suite PASS is asserted.

[Race job 125079044013](https://github.com/ArtixSx/RAZVILKA/actions/runs/41383456657/job/125079044013) used Intel Xeon 6973P-C. Core capture failed at 15.013212080s/236 callbacks before and 15.014476651s/240 callbacks after. These incomplete prefixes are not comparable completed latency samples. The race workflow did not complete HTTP/LAN. Production and race worker hardware differ; no cross-mode speed comparison is made.

All eight genuine held-source mutation/lifecycle scenarios passed after: production 1.07s, race 1.63s. The new symlink case mutates only a private copied extension after the real first literal `-S` opens the held TCP module, then requires the public collector to discard its complete image. Existing actual held-file, membership, readonly callback and external Close cases remain. Protected filesystem tests also passed, including original directory metadata refresh, symlink/inode/membership drift and copied/foreign/profile refusal. No data race was reported. Namespace/kernel/process/tool ownership is real; platform/Home classification remains explicitly modeled. This is not stock-router acceptance.

[results.csv](results.csv) contains complete and failed rows; [raw-excerpts.log](raw-excerpts.log) preserves bounded original evidence. Full downloaded production log SHA256: `905946feaa294264d7c77d6d12f5a6ff9e3391f6aefae8b9789523d406202c55`; race: `05d9778f8b363815cd9c0d38387f4b03369acb751f8adc80edf92f23bf070d34`.
