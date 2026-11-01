# Native VLESS Check: CPU and observed RSS

Source `570b40c633ee59c1756f38fba785ec098e185a19`, run `41259861329`,
job `124710713791` (`node-native-performance`): PASS. The actual resource helper
test passed in 0.214 s. The original 104 Check samples and 39 App jobs all
completed with zero RSS read errors. Raw historical CSV artifacts are unchanged.

Each cohort uses the same new instrumentation. Reference means the current
native Check with only the per-Check literal-service reuse observation hidden;
it is an algorithm reference, **not a historical release binary**. Both use
official Xray 26.3.27, real TLS/DNS/SOCKS and native process cleanup inside a
disposable loopback-only network/mount namespace. Stable WAN identity and a
40 ms fixture service delay are modeled. This is no router acceptance.

All table entries are **p50 / p95**, N=12 repeated samples after the first
sample. Percentiles use **nearest rank**: sorted index `ceil(p*N)-1`; p50 is
the sixth sample and p95 the twelfth. Interpolated medians are different.

| Full live Check | Reference | Current reuse |
| --- | ---: | ---: |
| Wall, ms | 509.784 / 512.177 | 405.332 / 408.381 |
| Self user + system CPU, ms | 50.238 / 52.002 | 41.037 / 45.266 |
| Joined children user + system CPU, ms | 64.397 / 65.188 | 59.230 / 60.736 |
| Observed self peak RSS, KiB | 26608 / 27088 | 26476 / 27220 |
| Observed new-child tree peak RSS, KiB | 33192 / 33520 | 32988 / 33352 |

The controlled live wall p50 differs by 104.452 ms (20.49%). Actual service
requests remain two versus one. Self CPU includes fixture TLS/DNS servers and
the sampling observer. Child CPU includes native version/validation/client
commands reaped during each measurement window. This does **not** establish
RAM savings: RSS observations are close and do not measure physical memory.

| Current full Check | Wall, ms | Self CPU, ms | Joined child CPU, ms |
| --- | ---: | ---: | ---: |
| Dead service | 405.900 / 409.264 | 41.349 / 43.294 | 59.309 / 61.482 |
| Cancel | 364.725 / 367.109 | 40.564 / 42.487 | 58.307 / 59.668 |
| Dead node | 8.260 / 8.984 | 1.024 / 2.706 | 9.099 / 9.897 |

App measurements use the current original dispatcher only, a controlled 25 ms
hold before admission, native checks and actual HTTP readback. They do not
compare two queue implementations or include browser paint.

| App job | POST → HTTP readback, ms | Self CPU, ms | Joined child CPU, ms |
| --- | ---: | ---: | ---: |
| Single | 739.944 / 749.440 | 362.793 / 369.577 | 74.998 / 76.822 |
| Selected batch, two | 2579.349 / 2604.738 | 991.860 / 1012.242 | 160.401 / 163.837 |
| All VLESS, two | 2598.327 / 2621.005 | 1016.796 / 1033.123 | 161.766 / 166.100 |

`RUSAGE_SELF` and `RUSAGE_CHILDREN` user/system counters are subtracted per
window, after actual checker child cleanup. `RUSAGE_CHILDREN` accounts only
reaped children. RSS is sampled from `/proc/*/statm` every 10 ms; the sampler
discovers children across all Go OS threads, verifies birth/parent membership
and excludes the preexisting fixture-peer subtree. Stop joins the sampler.
RSS columns contain absolute observed peaks, **not a cumulative Maxrss delta**.
Child RSS sums can double-count shared pages and sampling can miss short-lived
processes. Dead-node child RSS is therefore blank: zero child samples means
unknown peak, not zero memory use. CPU was still measured for those children.

Reproduce using the SHA-verified binary and the workflow's Linux dependencies:

```sh
sudo env PATH="$PATH" \
  RAZVILKA_XRAY_NATIVE=/path/to/pinned-26.3.27/xray \
  RAZVILKA_NODE_PERF_OUTPUT="$PWD/artifacts/node-native-performance" \
  sh scripts/check-node-native-performance.sh
```

Kernel/toolchain/binary hashes and scope are recorded in `environment.txt`.
The raw three CSVs, native log and resource-helper log accompany this README.
No actual router, physical WAN, public Internet or browser rendering was used.
