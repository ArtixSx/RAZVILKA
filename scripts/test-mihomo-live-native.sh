#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_XRAY_NATIVE:?official pinned Xray26.3.27 peer required}"
: "${RAZVILKA_MIHOMO_ARCHIVE:?official pinned Mihomo1.19.33 archive required}"
: "${RAZVILKA_HEV_NATIVE:?official pinned HEV2.17.1 binary required}"
case "${RAZVILKA_MIHOMO_LIVE_TEST_CASE:-lifecycle}" in
 lifecycle) live_test=TestMihomoLiveOriginalApplyStopAndFreshApply; live_rounds=2;;
 postcas-failure) live_test=TestMihomoLiveOriginalPostCASServiceFailure; live_rounds=1;;
 check-settlement) live_test=TestMihomoLiveOriginalFailedCheckSettlementStopRetry; live_rounds=1;;
 *) exit 2;;
esac
# Each independent user cycle retains its 300s ceiling and every operation
# retains 110s. Keep 60s for fatal-path teardown outside the source lifetime.
live_aggregate_budget=$((live_rounds * 300))
live_test_timeout=$((live_aggregate_budget + 60))
case "$RAZVILKA_XRAY_NATIVE:$RAZVILKA_MIHOMO_ARCHIVE:$RAZVILKA_HEV_NATIVE" in /*:/*:/*) ;; *) exit 2;; esac
for tool in python3 unshare mount ip iptables-legacy ip6tables-legacy curl go timeout; do command -v "$tool" >/dev/null; done
live_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
live_work=$(mktemp -d /tmp/razvilka-mihomo-live.XXXXXX)
chmod 700 "$live_work"
trap 'rm -rf -- "$live_work"' EXIT HUP INT TERM
export TMPDIR="$live_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_MIHOMO_LIVE_WORK="$live_work"
cp "$live_repo/scripts/fixtures/mihomo-live-peer.py" "$live_work/physical-peer"
chmod 500 "$live_work/physical-peer"
export RAZVILKA_MIHOMO_LIVE_PEER="$live_work/physical-peer"
live_profile_output_current() {
 python3 - "$live_repo" "$RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT" <<'PY'
import os,pathlib,stat,sys
repo=pathlib.Path(sys.argv[1]).resolve()
out=pathlib.Path(sys.argv[2])
if not out.is_absolute() or out != repo/'artifacts'/'mihomo-live-profile' or out.resolve() != out:
 raise SystemExit('fixed workspace CPU artifact directory required')
info=out.lstat()
if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid not in (os.geteuid(),repo.stat().st_uid):
 raise SystemExit('original private CPU artifact directory required')
PY
}
if test -n "${RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT:-}"; then live_profile_output_current; fi
python3 - <<'PY'
import hashlib,json,os,pathlib,subprocess
work=pathlib.Path(os.environ['RAZVILKA_MIHOMO_LIVE_WORK'])
xt=pathlib.Path('/usr/sbin/xtables-legacy-multi')
ip=pathlib.Path('/usr/bin/ip')
version=subprocess.check_output(['/usr/sbin/iptables-legacy','--version'],text=True).strip()
if not version.startswith('iptables v'): raise SystemExit('unexpected legacy tool identity')
review={'XTablesSHA256':hashlib.sha256(xt.read_bytes()).hexdigest(),'IPToolSHA256':hashlib.sha256(ip.read_bytes()).hexdigest(),'Version':version.removeprefix('iptables v'),'IPVersion':subprocess.check_output(['/usr/sbin/ip','-Version'],text=True)}
(work/'tools.json').write_text(json.dumps(review));(work/'tools.json').chmod(0o600)
print('CI-only platform classification; original protected tool closure:',json.dumps(review))
PY
export RAZVILKA_DOMAIN_TOOLS_REVIEW="$live_work/tools.json"
export RAZVILKA_DOMAIN_ORIGINAL_NATIVE=1 RAZVILKA_MIHOMO_LIVE_NATIVE=1
cd "$live_repo"
go test -tags razvilka_native_fixture -c -o "$live_work/app.test" ./internal/app
chmod 500 "$live_work/app.test"
# Go 1.26 may lazily build pprof; this bounded parent preparation is outside
# the measured native test and never changes the native result or its budgets.
timeout 50s go tool pprof -h > "$live_work/pprof-prewarm.log" 2>&1 || true
live_status=0
unshare --mount --net sh -eu -c '
 mount --make-rprivate /
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 touch /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 mount --bind "$1/app.test" /opt/bin/razvilka
 /usr/sbin/iptables-legacy -t mangle -S >/dev/null
 /usr/sbin/iptables-legacy -t raw -S >/dev/null
 /usr/sbin/iptables-legacy -t nat -S >/dev/null
 /usr/sbin/iptables-legacy -t filter -S >/dev/null
 /usr/sbin/ip6tables-legacy -t mangle -S >/dev/null
 # Load the real queue observation prerequisite through an inert UNHOOKED
 # chain, then remove that exact rule/chain before any tested admission.
 /usr/sbin/iptables-legacy -t mangle -N RZMLF_BOOT
 /usr/sbin/iptables-legacy -t mangle -A RZMLF_BOOT -j NFQUEUE --queue-num 65000
 /usr/sbin/iptables-legacy -t mangle -D RZMLF_BOOT -j NFQUEUE --queue-num 65000
 /usr/sbin/iptables-legacy -t mangle -X RZMLF_BOOT
 exec /opt/bin/razvilka -test.run="^$2$" -test.v -test.count=1 -test.timeout="${3}s" -test.cpuprofile="$1/live.cpu.pprof"
' sh "$live_work" "$live_test" "$live_test_timeout" || live_status=$?
# Analyze only after leaving the private /opt mount. CPU samples contain code
# symbols/paths, not exported runtime configuration or packet captures.
if test -n "${RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT:-}" && live_profile_output_current; then
 live_profile_status=missing
 if test -s "$live_work/live.cpu.pprof"; then
  live_profile_status=0
  timeout 50s go tool pprof -top -nodecount=35 -unit=ms "$live_work/app.test" "$live_work/live.cpu.pprof" > "$live_work/cpu-top.full.txt" 2>&1 || live_profile_status=$?
  head -c 65536 "$live_work/cpu-top.full.txt" > "$live_work/cpu-top.txt" || true
  cp "$live_work/live.cpu.pprof" "$live_work/cpu-top.txt" "$RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT/" || true
  chmod 600 "$RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT/live.cpu.pprof" "$RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT/cpu-top.txt" || true
 fi
 printf 'child_exit_status=%s\nprofile_analysis_status=%s\nprofile_span=whole_original_native_test_process\nnode_transit_budget_seconds=10\napply_budget_seconds=110\nGOMAXPROCS=2\nclaim=isolated_native_not_router\n' "$live_status" "$live_profile_status" > "$RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT/status.txt" || true
 printf 'rounds=%s\nround_budget_seconds=300\naggregate_budget_seconds=%s\nharness_timeout_seconds=%s\n' "$live_rounds" "$live_aggregate_budget" "$live_test_timeout" >> "$RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT/status.txt" || true
 chmod 600 "$RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT/status.txt" || true
 if test -f "$live_work/cpu-top.txt"; then cat "$live_work/cpu-top.txt" || true; fi
fi
exit "$live_status"
