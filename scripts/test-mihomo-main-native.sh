#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_MIHOMO_ARCHIVE:?official target archive required}"
: "${RAZVILKA_MIHOMO_PREDECESSOR_ARCHIVE:?official predecessor archive required}"
mihomo_main_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mihomo_main_work=$(mktemp -d /tmp/razvilka-mihomo-main.XXXXXX)
chmod 700 "$mihomo_main_work"
trap 'rm -rf -- "$mihomo_main_work"' EXIT HUP INT TERM
export TMPDIR="$mihomo_main_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$mihomo_main_repo"
go test -tags razvilka_native_fixture -c -o "$mihomo_main_work/app.test" ./internal/app
if test "${RAZVILKA_MIHOMO_MAIN_NATIVE_BINDING:-}" = 1; then
 # The same pinned original C initializer registers and joins a real no-hook
 # queue, so later complete inventories read the actual empty per-net file.
 curl --fail --location --retry 3 -o "$mihomo_main_work/nfqws-release.tar.gz" https://github.com/bol-van/zapret2/releases/download/v1.0.6/zapret2-v1.0.6.tar.gz
 echo "eb412aebc82cdef1f09b6aa9df45c8ff60fb88683b6663e6c4a9275d87ea2db4  $mihomo_main_work/nfqws-release.tar.gz" | sha256sum --check --strict
 tar -xzf "$mihomo_main_work/nfqws-release.tar.gz" -C "$mihomo_main_work" zapret2-v1.0.6/binaries/linux-x86_64/nfqws2
 echo "25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1  $mihomo_main_work/zapret2-v1.0.6/binaries/linux-x86_64/nfqws2" | sha256sum --check --strict
 chmod 500 "$mihomo_main_work/zapret2-v1.0.6/binaries/linux-x86_64/nfqws2"
 go test -tags razvilka_native_fixture ./internal/startuptools -run "^TestNativePolicyOuterNamespaceRequiresDifferentGenuineNetFD$" -count=1 -v
 go build -tags razvilka_native_fixture -o "$mihomo_main_work/controller" ./cmd/razvilka
 python3 - "$mihomo_main_work/runtime-native-tool-review.json" <<'PY'
import hashlib,json,pathlib,subprocess,sys
version=subprocess.check_output(['/usr/sbin/iptables-legacy','--version'],text=True).strip()
assert version.startswith('iptables v')
review={'XTablesSHA256':hashlib.sha256(pathlib.Path('/usr/sbin/xtables-legacy-multi').read_bytes()).hexdigest(),'IPToolSHA256':hashlib.sha256(pathlib.Path('/usr/bin/ip').read_bytes()).hexdigest(),'Version':version.removeprefix('iptables v'),'IPVersion':subprocess.check_output(['/usr/sbin/ip','-Version'],text=True)}
path=pathlib.Path(sys.argv[1]);path.write_text(json.dumps(review));path.chmod(0o600)
print('Tagged native platform classification only; actual tool image/version source:',json.dumps(review))
PY
 export RAZVILKA_RUNTIME_NATIVE_REVIEW="$mihomo_main_work/runtime-native-tool-review.json" RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3
else
 go build -o "$mihomo_main_work/controller" ./cmd/razvilka
fi
chmod 500 "$mihomo_main_work/app.test" "$mihomo_main_work/controller"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=github.com -addext subjectAltName=DNS:github.com -keyout "$mihomo_main_work/key.pem" -out "$mihomo_main_work/ca.pem" >/dev/null 2>&1
chmod 600 "$mihomo_main_work/key.pem" "$mihomo_main_work/ca.pem"
# Open the actual outer scope before unshare. This is retained comparison data
# for fixture isolation, never a signal, runtime owner or inactivity grant.
exec 3</proc/self/ns/net
unshare --mount --net sh -eu -c '
 mount --make-rprivate /
 if test "${RAZVILKA_MIHOMO_MAIN_NATIVE_BINDING:-}" = 1; then
  /usr/sbin/iptables-legacy -t mangle -S >/dev/null
  /usr/sbin/ip6tables-legacy -t mangle -S >/dev/null
  /usr/sbin/iptables-legacy -t mangle -N RZV_CI_NFQ_BOOTSTRAP
  /usr/sbin/iptables-legacy -t mangle -A RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
  /usr/sbin/iptables-legacy -t mangle -D RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
  /usr/sbin/iptables-legacy -t mangle -X RZV_CI_NFQ_BOOTSTRAP
  RAZVILKA_MANAGED_PROBE_FIXTURE_WORK="$1" python3 "$2/scripts/native-managed-probe-queue-init.py"
 fi
 exec unshare --mount --pid --fork sh "$2/scripts/fixtures/mihomo-main-session.sh" "$1" "$2"

' sh "$mihomo_main_work" "$mihomo_main_repo" || {
 mihomo_main_status=$?
 for mihomo_main_log in main proxy; do
  if test -f "$mihomo_main_work/$mihomo_main_log.log"; then tail -c 16384 "$mihomo_main_work/$mihomo_main_log.log"; fi
 done
 exit "$mihomo_main_status"
}
