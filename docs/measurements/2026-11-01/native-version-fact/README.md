# Scoped static version observation: provenance and limits

This audit concerns only the two fixed legacy `iptables --version` / `ip6tables --version` observations. It is not a cached kernel capture, runtime-health result, execution permission or router-readiness claim. The proposed transient fact belongs to one original read-only tool observation and one original Lease. Ordinary checks and subsequent observations still execute their own version commands.

The first whole version batch must execute and validate both aliases **and IP**, with successful Provider closing verification, before recording a fact. Repeated reads must retain the same original scope/source pointers, identity, digest, captured entry images, full cloned profile and fixed environment. They reobserve the entire metadata graph. All actual child Starts and completions keep their original metadata/identity/lifetime checks. The enclosing observation performs complete byte checks before and after its pure callback, revokes and joins borrowers, and refuses all effect Starts. A caller must not use intermediate comparison data as a positive result before that closing byte check succeeds.

IP `-Version` remains an actual subprocess on every Check. In iproute2 6.1.0, [ip/ip.c](https://github.com/iproute2/iproute2/blob/v6.1.0/ip/ip.c#L240) calls `get_libbpf_version`; [lib/bpf_glue.c](https://github.com/iproute2/iproute2/blob/v6.1.0/lib/bpf_glue.c#L37) may examine `/proc/self/maps`. This experiment does not treat that runtime observation as a static version fact.

For legacy xtables, the `V` branch prints `program_name` and `program_version` and exits. The audited branches are `iptables/xshared.c:1707` in upstream 1.8.10, `iptables/xshared.c:1837` in 1.8.11, and `iptables/iptables.c:1623` in 1.4.21. The actual alias/argv and the closed loader/library/extension environment remain mandatory; a matching version string or supplied hash alone cannot issue a fact.

The closed predicate uses the existing reviewed production profile/image pins (Ubuntu AMD64 1.8.11 and stock ARM64 1.4.21), plus the following independently checked CI Ubuntu package tuple. Any unknown image/profile uses real version subprocesses on every Check.

| Item | SHA256 |
| --- | --- |
| Official Ubuntu `iptables_1.8.10-3ubuntu2_amd64.deb` | `d341e8ffc42ca035f5aa0fd9a798c8d2b2edb019225dc11f4dac16edf9c57840` |
| Extracted `usr/sbin/xtables-legacy-multi` | `38ac0252c751be1c89ebc2e2eb6a05bf1720b05eea552a1dee8380af94d72a52` |
| Upstream `iptables_1.8.10.orig.tar.xz` | `5cc255c189356e317d070755ce9371eb63a1b783c34498fb8c30264f3cc59c9c` |
| Ubuntu `iptables_1.8.10-3ubuntu2.debian.tar.xz` | `9b2adc03e912f0d085cadbfe4d413ba8accad184b73a9c3b9d0aa0327ba6f069` |

The [official binary](https://archive.ubuntu.com/ubuntu/pool/main/i/iptables/iptables_1.8.10-3ubuntu2_amd64.deb) was downloaded and extracted without execution. Its control record identifies package `iptables`, version `1.8.10-3ubuntu2`, architecture `amd64`. The extracted ELF hash exactly matches the CI image. The [official source descriptor](https://archive.ubuntu.com/ubuntu/pool/main/i/iptables/iptables_1.8.10-3ubuntu2.dsc) identifies the upstream and Debian archive hashes above. The [distribution patch archive](https://archive.ubuntu.com/ubuntu/pool/main/i/iptables/iptables_1.8.10-3ubuntu2.debian.tar.xz) contains this applied series:

- `fix-spelling-mistakes.patch`: documentation, `libxt_multiport`, `libxt_set`, nft ARP and nft monitor documentation.
- `0001-ebtables-Fix-corner-case-noflush-restore-bug.patch`: ebtables code and its regression.
- `9002-libxt_recent-Add-support-for-reap-option.patch`: the recent extension.
- `skip-some-shell-tests.patch`: shell tests.

None changes `xshared.c`, the legacy version branch, or the legacy frontend initialization. `debian/rules` supplies ordinary build configuration (`--disable-libipq`, `--enable-devel`) and packaging of alternative command links. The [Ubuntu package record](https://packages.ubuntu.com/noble/iptables) identifies the same source release. This is a source/binary provenance check, not a reproducible-build claim.

Required acceptance evidence remains separate: actual first/repeated alias Start counters, fresh IP Start counters, failed/partial batches, source/profile/environment drift, copied/late/revoked scopes, full closing-byte mutation refusal and unchanged physical cleanup. Native fixture classification remains explicit; no stock-router acceptance follows from this audit.

## Actual paired native results, 2026-11-02 UTC

[Focused run 41371321144](https://github.com/ArtixSx/RAZVILKA/actions/runs/41371321144) ran baseline `ffb7f5201f75f94eb0b1949ce9c076470cb7d639` and after `83ad781d0e1875b7ac308255541eedacd0e84c73` sequentially on the same worker in each build mode. Both include the same child-Start/metadata instrumentation, reviewed original directory-fsync publication fix `70ff2196` (the applicable three-file slice of main `9ce81c87`), Go 1.26.5, pinned actual native assets and unchanged 14s forward / 5s cleanup budgets. Production and race ran on different hardware and must not be compared to each other.

| Same-worker scenario | Before | After | Outcome |
| --- | --- | --- | --- |
| Production core Execute | 10.536094406s | 10.293026737s | Both PASS complete flow and owned cleanup |
| Production actual HTTP test | 38.46s | 38.23s | Both PASS three probes, selection/manual intent, original selected source |
| Production actual LAN HTTP test | 43.68s | 42.46s | Both FAIL at review409, native-plan COMPILED_CAPABILITY_REFUSED after three probes/manual; no Apply |
| Race core Execute | 15.010610019s | 15.010071027s | Both FAIL capture deadline; different incomplete prefixes; original unknown custody retained |

Production job [125042203035](https://github.com/ArtixSx/RAZVILKA/actions/runs/41371321144/job/125042203035) used Intel Xeon Platinum 8573C. Its matched complete core performed 382 measured InventoryTools.Check callbacks on both sides: callback wall 5.021371352s → 4.592579319s, metadata traversal attempts 3120 → 2550, and actual successful child Starts `[iptables, ip6tables, IP]` `[386,386,386]` → `[196,196,386]`. Core wall improved 0.243067669s (2.307%) **in this single paired sample**. This does not establish a general speedup or completed LAN workflow. Callback wall includes only the existing InventoryTools.Check wrapper; whole Execute and CPU profiles include direct getters and other source checks as well.

Race job [125042203013](https://github.com/ArtixSx/RAZVILKA/actions/runs/41371321144/job/125042203013) used AMD EPYC 9V45. Its before/after capture prefixes performed different amounts of work, so their counts or wall times do not support a speed claim. Both LAN physical-boundary tests passed; race LAN HTTP stopped at probe0 deadline with recovery required.

All four actual static-fact tests passed in both modes: genuine fresh/nested/repeated/copy/expired/foreign source checks, actual IP Cmd.Start EAGAIN followed by fact retirement and full unfiltered original-scope batch recovery, partial IP-output mismatch refusing retention, and self/environment/profile/image-entry fingerprint refusal. The actual first/repeated batch Starts were `[1,1,1]` / `[0,0,1]`; a fresh source scope ran all three again. Existing five actual held-image/extension/lifecycle faults passed before and after in both modes; no data race was reported. Production late sole-Wait cleanup/retry and source/runtime/control/environment closing-revocation tests also passed on both sides. These are isolated native Linux results with modeled platform classification, not router acceptance.

[results.csv](results.csv) preserves all measured rows and boundaries, including failures. [raw-excerpts.log](raw-excerpts.log) contains bounded original log lines; full raw job SHA256 values are `278d310a2efcef408d640e6894845dbca3e948e72751eb667dab5eb8c25222ba` (production) and `b856ee5bab356b2421136e3e2d4ddd581e4ec59ada2d74a58a3cf7977f0c069d` (race). Full focused jobs remain FAILURE because the LAN workflow and race consumer are incomplete.
