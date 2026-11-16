#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_XRAY_NATIVE:?pinned Xray26.3.27 required}"
: "${RAZVILKA_MIHOMO_ARCHIVE:?pinned Mihomo1.19.33 archive required}"
: "${RAZVILKA_HEV_NATIVE:?pinned HEV2.17.1 required}"
case "$RAZVILKA_XRAY_NATIVE:$RAZVILKA_MIHOMO_ARCHIVE:$RAZVILKA_HEV_NATIVE" in /*:/*:/*) ;; *) exit 2;; esac
for tool in python3 unshare mount umount ip iptables-legacy ip6tables-legacy curl go timeout; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d /tmp/razvilka-mihomo-same-boot.XXXXXX)
chmod 700 "$work"
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
export TMPDIR="$work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_MIHOMO_LIVE_WORK="$work"
case "${RAZVILKA_MIHOMO_SAME_BOOT_CPU_PROFILE:-0}" in
 0) ;;
 1)
   case "${RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT:-}" in /*) ;; *) exit 2 ;; esac
   test "$RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT" != / || exit 2
   mkdir -p "$RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT"
   for artifact in sameboot-consumer.cpu.pprof sameboot-consumer.test; do
     test ! -e "$RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT/$artifact" || exit 2
   done ;;
 *) exit 2 ;;
esac
cp "$repo/scripts/fixtures/mihomo-live-peer.py" "$work/physical-peer-original"
cp "$repo/scripts/native-mihomo-same-boot-peer.py" "$work/physical-peer"
chmod 500 "$work/physical-peer" "$work/physical-peer-original"
export RAZVILKA_MIHOMO_LIVE_PEER="$work/physical-peer"
python3 - <<'PY'
import hashlib,json,os,pathlib,subprocess
work=pathlib.Path(os.environ['TMPDIR'])
version=subprocess.check_output(['/usr/sbin/iptables-legacy','--version'],text=True).strip()
if not version.startswith('iptables v'): raise SystemExit('unexpected original tool identity')
review={'XTablesSHA256':hashlib.sha256(pathlib.Path('/usr/sbin/xtables-legacy-multi').read_bytes()).hexdigest(),'IPToolSHA256':hashlib.sha256(pathlib.Path('/usr/bin/ip').read_bytes()).hexdigest(),'Version':version.removeprefix('iptables v'),'IPVersion':subprocess.check_output(['/usr/sbin/ip','-Version'],text=True)}
for name in ('tools.json','runtime-native-tool-review.json'):
 p=work/name;p.write_text(json.dumps(review));p.chmod(0o600)
print('CI-only Ubuntu classification; actual protected tools:',json.dumps(review))
PY
export RAZVILKA_DOMAIN_TOOLS_REVIEW="$work/tools.json"
export RAZVILKA_RUNTIME_NATIVE_REVIEW="$work/runtime-native-tool-review.json"
export RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3
export RAZVILKA_DOMAIN_ORIGINAL_NATIVE=1 RAZVILKA_MIHOMO_LIVE_NATIVE=1
export RAZVILKA_MANAGED_PROBE_NATIVE=1 RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW="$work/tools.json"
case "${RAZVILKA_MIHOMO_SAME_BOOT_ACK_CUT:-}" in
 ''|retirement.json|runtime-history|completed.json|terminal-transaction|terminal-global) ;;
 *) exit 2 ;;
esac
cd "$repo"
# Closed, compile-time lab selection. No arbitrary tags, hashes or relaxed
# installer receipt checks can be supplied by the environment.
case "${RAZVILKA_HEV_ALTSTACK_LAB:-0}" in
 0) native_tags=razvilka_native_fixture; printf '%s\n' 'HEV qualification=official' ;;
 1) native_tags=razvilka_native_fixture,razvilka_hev_altstack_lab
    printf '%s\n' 'HEV qualification=separate-source-lab production_pin_unchanged=true' ;;
 *) exit 2 ;;
esac
case "${RAZVILKA_NATIVE_RACE:-0}" in
 0) go test -tags "$native_tags" -ldflags='-s -w' -c -o "$work/app.test" ./internal/app
    go test -tags "$native_tags" -ldflags='-s -w' -c -o "$work/cmd.test" ./cmd/razvilka
    go test -tags "$native_tags" -ldflags='-s -w' -c -o "$work/startup.test" ./internal/startuptools ;;
 1) go test -race -tags "$native_tags" -ldflags='-s -w' -c -o "$work/app.test" ./internal/app
    go test -race -tags "$native_tags" -ldflags='-s -w' -c -o "$work/cmd.test" ./cmd/razvilka
    go test -race -tags "$native_tags" -ldflags='-s -w' -c -o "$work/startup.test" ./internal/startuptools ;;
 *) exit 2 ;;
esac
# Actual stdout/stderr pipes must respect the original shared helper cap.
"$work/cmd.test" -test.run='^TestMihomoSameBootNativeOutput' -test.v -test.count=1 -test.timeout=30s
python3 - "$work" <<'PY'
import pathlib,sys
for name in ('app.test','cmd.test','startup.test'):
 p=pathlib.Path(sys.argv[1])/name
 if not 0<p.stat().st_size<=64*1024*1024: raise SystemExit('original binary reader bound exceeded')
 p.chmod(0o500)
PY
# Preserve an actual outside namespace FD before creating either private ns.
exec 3</proc/self/ns/net
sameboot_status=0
timeout --foreground --kill-after=35s 300s unshare --mount --net sh -eu -c '
 mount --make-rprivate /
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 touch /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 mount --bind "$1/app.test" /opt/bin/razvilka
 for table in mangle raw nat filter; do /usr/sbin/iptables-legacy -t "$table" -S >/dev/null; done
 /usr/sbin/ip6tables-legacy -t mangle -S >/dev/null
 /usr/sbin/iptables-legacy -t mangle -N RZMLF_BOOT
 /usr/sbin/iptables-legacy -t mangle -A RZMLF_BOOT -j NFQUEUE --queue-num 65000
 /usr/sbin/iptables-legacy -t mangle -D RZMLF_BOOT -j NFQUEUE --queue-num 65000
 /usr/sbin/iptables-legacy -t mangle -X RZMLF_BOOT
 "$1/startup.test" -test.run="^TestStaticVersionFactNative(PolicyReadObservation|MihomoNumericReadObservation)$" -test.v -test.count=1 -test.timeout=50s
 exec python3 "$2/scripts/native-mihomo-same-boot.py" "$1"
' sh "$work" "$repo" || sameboot_status=$?
# The optional diagnostic samples the unchanged original consumer operation.
# Preserve the actual failure status and profile before the private work cleanup.
if test "${RAZVILKA_MIHOMO_SAME_BOOT_CPU_PROFILE:-0}" = 1; then
  if test -s "$work/sameboot-consumer.cpu.pprof"; then
    if ! cp "$work/sameboot-consumer.cpu.pprof" "$RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT/sameboot-consumer.cpu.pprof"; then
      if test "$sameboot_status" = 0; then sameboot_status=1; fi
    fi
    if ! cp "$work/cmd.test" "$RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT/sameboot-consumer.test"; then
      if test "$sameboot_status" = 0; then sameboot_status=1; fi
    fi
    # These diagnostics contain compiled public test code and CPU locations,
    # not fixture config. The unprivileged artifact uploader must read them.
    if ! chmod 0644 "$RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT/sameboot-consumer.cpu.pprof" "$RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT/sameboot-consumer.test"; then
      if test "$sameboot_status" = 0; then sameboot_status=1; fi
    fi
  else
    printf '%s\n' 'sameboot consumer profile unavailable; no diagnostic acceptance'
    if test "$sameboot_status" = 0; then sameboot_status=1; fi
  fi
  # Separate actual race-runtime exit experiment, after the full route actor.
  # No tests/effects run in these children and GORACE never changes for the
  # acceptance actor. This measures only the runtime's process-exit delay.
  if test "${RAZVILKA_NATIVE_RACE:-0}" = 1; then
    if ! python3 - "$work/cmd.test" "$RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT" <<'PY'
import json, os, pathlib, subprocess, sys, time
binary, output = sys.argv[1:]
rows = []
for block in range(3):
    for mode in ('original', 'exit-sleep-zero', 'exit-sleep-zero', 'original'):
        env = os.environ.copy()
        if mode == 'exit-sleep-zero':
            env['GORACE'] = env.get('GORACE', '') + ' atexit_sleep_ms=0'
        started = time.monotonic_ns()
        result = subprocess.run([binary, '-test.run=^$', '-test.timeout=5s'], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        rows.append({'block': block, 'mode': mode, 'elapsed_ms': (time.monotonic_ns()-started)/1e6,
                     'exit_code': result.returncode})
        if result.returncode != 0:
            raise SystemExit('race-exit diagnostic child failed')
with (pathlib.Path(output) / 'race-exit-cost.json').open('x') as stream:
    json.dump({'diagnostic_only': True, 'empty_test_selection': True,
               'acceptance_GORACE_unchanged': True, 'rows': rows}, stream, indent=2)
PY
    then
      if test "$sameboot_status" = 0; then sameboot_status=1; fi
    fi
  fi
fi
exit "$sameboot_status"
