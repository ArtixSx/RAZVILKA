#!/bin/sh
set -eu
# CI-only physical topology + original protected tool lease. Public ordinary
# domain Apply remains blocked; no router or existing namespace is changed.
test "$(id -u)" = 0 || { echo 'root isolated native fixture required' >&2; exit 2; }
: "${RAZVILKA_XRAY_NATIVE:?absolute SHA-verified official Xray binary required}"
case "$RAZVILKA_XRAY_NATIVE" in /*) ;; *) exit 2;; esac
for domain_tool in python3 unshare mount ip iptables-legacy ip6tables-legacy go timeout; do command -v "$domain_tool" >/dev/null; done
domain_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
domain_work=$(mktemp -d /tmp/razvilka-domain-original.XXXXXX)
chmod 700 "$domain_work"
trap 'rm -rf -- "$domain_work"' EXIT HUP INT TERM
export TMPDIR="$domain_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_DOMAIN_FIXTURE_WORK="$domain_work"
export RAZVILKA_DOMAIN_CPU_PROFILE="$domain_work"
python3 - <<'PY'
import hashlib,json,os,pathlib,subprocess
work=pathlib.Path(os.environ['RAZVILKA_DOMAIN_FIXTURE_WORK'])
xt=pathlib.Path('/usr/sbin/xtables-legacy-multi')
ip=pathlib.Path('/usr/bin/ip')
version=subprocess.check_output(['/usr/sbin/iptables-legacy','--version'],text=True).strip()
if not version.startswith('iptables v'): raise SystemExit('unexpected legacy tool identity')
review={'XTablesSHA256':hashlib.sha256(xt.read_bytes()).hexdigest(),'IPToolSHA256':hashlib.sha256(ip.read_bytes()).hexdigest(),'Version':version.removeprefix('iptables v'),'IPVersion':subprocess.check_output(['/usr/sbin/ip','-Version'],text=True)}
(work/'tools.json').write_text(json.dumps(review));(work/'tools.json').chmod(0o600)
print('CI-only platform classification; actual protected tool bytes:',json.dumps(review))
PY
export RAZVILKA_DOMAIN_ORIGINAL_NATIVE=1
export RAZVILKA_DOMAIN_TOOLS_REVIEW="$domain_work/tools.json"
cd "$domain_repo"
go test -tags razvilka_native_fixture -c -o "$domain_work/app.test" ./internal/app
chmod 500 "$domain_work/app.test"
# Go 1.26 may build pprof lazily; exclude that bounded parent preparation from
# both the namespace run and its CPU sample, retaining diagnostics on failure.
timeout 50s go tool pprof -h > "$domain_work/pprof-prewarm.log" 2>&1 || true
domain_status=0
unshare --mount --net sh -eu -c '
 mount --make-rprivate /
 # Original tool/preload review must observe protected ancestors, not the
 # unrelated hosted runners writable /opt cache. This mount is private.
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
 exec /opt/bin/razvilka -test.run="^TestDomainTCPOriginalNativeAcceptedFlows$" -test.v -test.count=1 -test.timeout=180s
' sh "$domain_work" || domain_status=$?
# Keep the child's result. CPU symbols and bounded top output contain no
# profile/config credentials and are analyzed by the parent outside /opt.
if test -n "${RAZVILKA_DOMAIN_PROFILE_OUTPUT:-}"; then
 case "$RAZVILKA_DOMAIN_PROFILE_OUTPUT" in /*) ;; *) exit 2;; esac
 mkdir -p "$RAZVILKA_DOMAIN_PROFILE_OUTPUT"
 if test -s "$domain_work/original-run.cpu.pprof"; then
  cp "$domain_work/original-run.cpu.pprof" "$RAZVILKA_DOMAIN_PROFILE_OUTPUT/"
  timeout 50s go tool pprof -top -nodecount=35 "$domain_work/app.test" "$domain_work/original-run.cpu.pprof" 2>&1 | head -c 65536 > "$RAZVILKA_DOMAIN_PROFILE_OUTPUT/cpu-top.txt" || true
 fi
 printf 'child_exit_status=%s\npublication_budget_seconds=12\nprofile_span=original_Run_through_join\n' "$domain_status" > "$RAZVILKA_DOMAIN_PROFILE_OUTPUT/status.txt"
fi
exit "$domain_status"
