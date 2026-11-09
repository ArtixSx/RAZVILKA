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
case "${RAZVILKA_NATIVE_RACE:-0}" in
 0) go test -tags razvilka_native_fixture -ldflags='-s -w' -c -o "$work/app.test" ./internal/app
    go test -tags razvilka_native_fixture -ldflags='-s -w' -c -o "$work/cmd.test" ./cmd/razvilka
    go test -tags razvilka_native_fixture -ldflags='-s -w' -c -o "$work/startup.test" ./internal/startuptools ;;
 1) go test -race -tags razvilka_native_fixture -ldflags='-s -w' -c -o "$work/app.test" ./internal/app
    go test -race -tags razvilka_native_fixture -ldflags='-s -w' -c -o "$work/cmd.test" ./cmd/razvilka
    go test -race -tags razvilka_native_fixture -ldflags='-s -w' -c -o "$work/startup.test" ./internal/startuptools ;;
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
' sh "$work" "$repo"
