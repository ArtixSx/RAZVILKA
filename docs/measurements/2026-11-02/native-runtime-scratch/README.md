# Runtime scratch: allocated bytes, 2026-11-02

Original runtime payload and compare buffers are exclusively borrowed, fully cleared after every FD/root close, then returned to a bounded pool. The proc reader grows its result only for actual bytes read. Neither change retains a descriptor, digest, observation, permission or result. Every complete member read, byte comparison, EOF and ownership fence remains.

| Finite consumer, one sample | Before 7038cdd4 | After 071e0dcb |
|---|---:|---:|
| Execute seconds | 7.632065091 | 11.715606522 |
| Allocated bytes | 2,031,138,832 | 1,157,043,240 |
| Allocated objects | 7,493,694 | 7,482,215 |
| Member reads / bytes | 13,260 / 1,084,270,200 | 13,260 / 1,084,270,200 |
| ToolCheck calls | 382 | 382 |
| Version child starts, v4/v6/IP | 163 / 163 / 386 | 163 / 163 / 386 |
| Metadata traversals | 2,312 | 2,312 |

Allocation volume fell 43.03%; elapsed time increased. Different CI runners and only one sample per revision prevent a causal latency claim. This is not a resident-memory measurement. Actual member mutation, foreign inode/FD, FIFO/symlink, EOF/cancellation, scratch exclusivity/zeroing and proc read-bound tests passed in normal and race. Full CI [41421353395](https://github.com/ArtixSx/RAZVILKA/actions/runs/41421353395) passed.

The after run failed HTTP, LAN/manual and race execution deadlines; the complete managed workflow remains unfinished. Native evidence: [normal/race run](https://github.com/ArtixSx/RAZVILKA/actions/runs/41421353459), [machine-readable samples](results.json), [original core excerpt](after-core.log). Earlier raw sample and hash are retained in [metadata comparison](../native-metadata-read/README.md).
