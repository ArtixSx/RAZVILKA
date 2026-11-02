#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_XRAY_NATIVE:?official pinned Xray26.3.27 peer required}"
: "${RAZVILKA_MIHOMO_ARCHIVE:?official pinned Mihomo1.19.33 archive required}"
: "${RAZVILKA_HEV_NATIVE:?official pinned HEV2.17.1 binary required}"
case "$RAZVILKA_XRAY_NATIVE:$RAZVILKA_MIHOMO_ARCHIVE:$RAZVILKA_HEV_NATIVE" in /*:/*:/*) ;; *) exit 2;; esac
for tool in python3 unshare mount ip iptables-legacy ip6tables-legacy curl go; do command -v "$tool" >/dev/null; done
live_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
live_work=$(mktemp -d /tmp/razvilka-mihomo-live.XXXXXX)
chmod 700 "$live_work"
trap 'rm -rf -- "$live_work"' EXIT HUP INT TERM
export TMPDIR="$live_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_MIHOMO_LIVE_WORK="$live_work"
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
 exec /opt/bin/razvilka -test.run="^TestMihomoLiveOriginalApplyStopAndFreshApply$" -test.v -test.count=1 -test.timeout=360s
' sh "$live_work"
