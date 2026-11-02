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
