# Original domain TCP: native CPU baseline

Source: `9978c86d784773af1e81e58bfd4e7536fc7a3316`.
GitHub run `41258260733`, scoped-native job `124705942950`, artifact
`13063998860` (`domain-native-9978c86d784773af1e81e58bfd4e7536fc7a3316`).
Profile timestamp: 2026-11-01 00:49:36 UTC. This directory follows the task's
measurement date; the actual sample ran after midnight UTC.

The original registered DNS source, actual held-FD Xray 26.3.27, Linux veth
LAN/WAN, real TLS peer and protected command lease ran in disposable mount/net
namespaces. Platform classification and stable WAN label are explicit fixture
models. No router, production deployment or real external service was used.

The profile starts after genuine operation-material/resource issuance, spans
`owner.Run` through its joined cleanup, and stops before leaving that callback.
The actual publication wait remains **12 seconds**. This run **failed** to
publish DNS within that budget; it provides no accepted selected-flow,
baseline-flow, live route, service or router-readiness proof.

| Sample | Value |
| --- | ---: |
| CPU-profile wall duration | 12.92 s |
| Total CPU samples | 13.55 s |
| `xrayDomainTCPExecutable.hash`, cumulative | 9.49 s / 70.04% |
| `startuptools.hashImage`, cumulative | 1.19 s / 8.78% |
| SHA-256 SHANI block, flat | 9.60 s / 70.85% |

These are one actual diagnostic sample, not p50/p95 or an improvement claim.
An earlier single goroutine stack happened to show tool hashing; the complete
CPU sample identifies repeated large Xray hashing as the dominant cost.

Reproduce from a Linux root CI runner with reviewed official Xray and the Go
toolchain installed, using the same pinned workflow dependencies:

```sh
sudo env PATH="$PATH" GOTOOLCHAIN=local \
  RAZVILKA_XRAY_NATIVE=/usr/local/lib/razvilka-fixtures/xray-node26.3.27/xray \
  RAZVILKA_DOMAIN_PROFILE_OUTPUT="$PWD/artifacts/domain-native" \
  GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" \
  sh scripts/test-domain-original-native.sh
```

The script builds the tagged App test, uses a fresh private `/opt` and original
controller inode, and preserves the native exit status after parent-side pprof.
It prewarms pprof before the native namespace run with a 50-second bound; the
parent `-top -nodecount=35` command is also bounded to 50 seconds and 64 KiB.

Raw files: `original-run.cpu.pprof`, `cpu-top.txt`, `status.txt`, `native.log`.
The log contains sanitized fixture diagnostics only; configurations and keys
are not emitted. CPU/RSS per process, repeated samples and after measurements
have not been collected in this baseline.
