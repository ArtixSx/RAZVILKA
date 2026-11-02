#!/bin/sh
set -eu

# CI-only ROOT fixture. All packet/address/rule effects occur in a new netns.
# Production installer/stock platform approval remains unchanged. The tagged
# fixture models platform classification, NOT artifact bytes, FD ownership,
# compatibility, NFQUEUE packets, TLS/catalogue predicates or cleanup.
test "$(id -u)" = 0 || { echo 'ROOT isolated CI fixture required' >&2; exit 2; }
for probe_tool in curl sha256sum tar python3 unshare mount ip iptables-legacy ip6tables-legacy nft go timeout; do
  command -v "$probe_tool" >/dev/null
done
probe_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
probe_work=$(mktemp -d /tmp/razvilka-managed-probe.XXXXXX)
chmod 700 "$probe_work"
trap 'rm -rf -- "$probe_work"' EXIT HUP INT TERM
export TMPDIR="$probe_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2

# Official release v1.0.6, source tag resolves to
# 221d7dff24bfec0cd5ac0a5070b8acef2008af3d. The archive digest was checked
# against the official release API's sha256 digest; every consumed member is
# additionally pinned below. No unreviewed release, branch or latest lookup.
curl --fail --location --retry 3 --output "$probe_work/release.tar.gz" \
  https://github.com/bol-van/zapret2/releases/download/v1.0.6/zapret2-v1.0.6.tar.gz
echo "eb412aebc82cdef1f09b6aa9df45c8ff60fb88683b6663e6c4a9275d87ea2db4  $probe_work/release.tar.gz" | sha256sum --check --strict
tar -xzf "$probe_work/release.tar.gz" -C "$probe_work" \
  zapret2-v1.0.6/binaries/linux-x86_64/nfqws2 \
  zapret2-v1.0.6/lua/zapret-lib.lua \
  zapret2-v1.0.6/lua/zapret-antidpi.lua \
  zapret2-v1.0.6/lua/zapret-auto.lua \
  zapret2-v1.0.6/files/fake/quic_initial_www_google_com.bin \
  zapret2-v1.0.6/files/fake/tls_clienthello_www_google_com.bin
export RAZVILKA_MANAGED_PROBE_FIXTURE_WORK="$probe_work"
export RAZVILKA_MANAGED_PROBE_FIXTURE_REPO="$probe_repo"
python3 - <<'PY'
import hashlib, json, os, pathlib, subprocess
work = pathlib.Path(os.environ['RAZVILKA_MANAGED_PROBE_FIXTURE_WORK'])
base = work / 'zapret2-v1.0.6'
members = [
 ('binaries/linux-x86_64/nfqws2', '25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1'),
 ('lua/zapret-lib.lua', '6bf528fef1f0fc3c65e189216fc8a06bb873f6e25d1c29d2bfa4695a09b73440'),
 ('lua/zapret-antidpi.lua', '6d1fa9168e5de1682fef91fd174f68b58c50f6739ef00f42ca7db2b940b6246d'),
 ('lua/zapret-auto.lua', '23a9b99a776d868d92f4cc0ee5110f5c1f12fe746620d9c0337022dbc2f52df0'),
 ('files/fake/quic_initial_www_google_com.bin', 'f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a'),
 ('files/fake/tls_clienthello_www_google_com.bin', '936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c'),
]
paths = []
for relative, expected in members:
    path = base / relative
    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit('pinned member refused: ' + relative)
    path.chmod(0o500 if not paths else 0o400)
    paths.append({'Path': str(path), 'SHA256': expected})
# Retain PRIVATE ancestors of the actual executable/assets, not just leaves.
for path in base.rglob('*'):
    if path.is_dir(): path.chmod(0o700)
base.chmod(0o700)
arguments = ['--lua-init=@' + p['Path'] for p in paths[1:4]]
arguments += ['--blob=quic_initial:@' + paths[4]['Path'], '--blob=tls_clienthello:@' + paths[5]['Path']]
(work / 'genuine.json').write_text(json.dumps({'BinaryPath': paths[0]['Path'], 'BinarySHA256': paths[0]['SHA256'], 'Assets': paths[1:], 'BaseArguments': arguments}))
xt = pathlib.Path('/usr/sbin/xtables-legacy-multi')
ip = pathlib.Path('/usr/bin/ip')
version = subprocess.check_output(['/usr/sbin/iptables-legacy', '--version'], text=True).strip()
if not version.startswith('iptables v'): raise SystemExit('unexpected xtables identity')
version = version.removeprefix('iptables v')
review = {'XTablesSHA256': hashlib.sha256(xt.read_bytes()).hexdigest(), 'IPToolSHA256': hashlib.sha256(ip.read_bytes()).hexdigest(), 'Version': version, 'IPVersion': subprocess.check_output(['/usr/sbin/ip', '-Version'], text=True)}
(work / 'tools.json').write_text(json.dumps(review))
print('CI-only platform classification; actual tool hashes/version:', json.dumps(review))
PY
export RAZVILKA_MANAGED_PROBE_NATIVE=1
export RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW="$probe_work/genuine.json"
export RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW="$probe_work/tools.json"
cd "$probe_repo"
probe_build_mode=${RAZVILKA_MANAGED_PROBE_BUILD_MODE:-race}
printf 'Actual native build mode: %s\n' "$probe_build_mode"
uname -a
go version
python3 - <<'PY'
import pathlib
for line in pathlib.Path('/proc/cpuinfo').read_text().splitlines():
    if line.startswith('model name'):
        print('Actual CPU:', line)
        break
PY
case "$probe_build_mode" in
  race)
    go test -race -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$probe_work/app.test" ./internal/app
    go test -race -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$probe_work/startuptools.test" ./internal/startuptools ;;
  production)
    go test -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$probe_work/app.test" ./internal/app
    go test -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$probe_work/startuptools.test" ./internal/startuptools ;;
  *) printf 'Unknown native build mode\n' >&2; exit 2 ;;
esac
if test "${RAZVILKA_MIHOMO_COLD_SOURCE_NATIVE:-0}" = 1; then
  if test "$probe_build_mode" = race; then
    go test -race -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$probe_work/dataplane.test" ./internal/dataplane
    go test -race -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$probe_work/controller.test" ./cmd/razvilka
  else
    go test -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$probe_work/dataplane.test" ./internal/dataplane
    go test -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$probe_work/controller.test" ./cmd/razvilka
  fi
  cp "$probe_work/tools.json" "$probe_work/runtime-native-tool-review.json"
  chmod 600 "$probe_work/runtime-native-tool-review.json"
  export RAZVILKA_RUNTIME_NATIVE_REVIEW="$probe_work/runtime-native-tool-review.json" RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3
  exec 3</proc/self/ns/net
fi
chmod 500 "$probe_work/app.test"
# Go 1.26 builds this builtin tool lazily. Warm it outside the packet actor and
# private /opt mount; this diagnostic compiler work is not a probe budget.
timeout 50s go tool pprof -h >/dev/null 2>&1
python3 - <<'PY'
import os, pathlib
program = pathlib.Path(os.environ['RAZVILKA_MANAGED_PROBE_FIXTURE_WORK']) / 'app.test'
size = program.stat().st_size
print('Actual compiled reader/consumer bytes:', size)
if not 0 < size <= 64 << 20:
    raise SystemExit('fixture exceeds the real controller binary admission bound')
PY
printf '127.0.0.1 localhost\n8.8.8.8 managed-probe.example\n' > "$probe_work/hosts"
chmod 400 "$probe_work/hosts"
# GitHub's host /opt is writable for its tool cache. The real protected tool
# review correctly refuses it as a preload ancestor. Give this disposable
# mount namespace an actual empty protected /opt; never chmod/change the host.
probe_cases='TestStaticVersionFactNativePolicyReadObservation TestStaticVersionFactNativeScope TestStaticVersionFactNativeFailedIPClearsFact TestStaticVersionFactNativePartialBatchNeverRetained TestStaticVersionFactNativeOriginalFingerprint TestClassicReadBatchNativeMutation TestManagedStrategyProbeNativeConsumer TestManagedStrategyProbeNativeConsumerLateWaitCleanup TestManagedStrategyProbeNativeAppHTTP TestManagedStrategyProbeNativeClosingSource TestManagedStrategyProbeNativeClosingRuntime TestManagedStrategyProbeNativeClosingControl TestManagedStrategyProbeNativeClosingEnvironment'
probe_timeout=100s
if test "${RAZVILKA_MANAGED_PROBE_LAN_NATIVE:-0}" = 1; then
  case "${RAZVILKA_MANAGED_PROBE_LAN_CASE:-full}" in
    full) probe_cases='TestNativeFixturePhysicalSourceCopiesRefuse TestManagedStrategyProbeNativeLANPhysical TestManagedStrategyProbeNativeLANAppHTTP' ;;
    manual) probe_cases='TestNativeFixturePhysicalSourceCopiesRefuse TestManagedStrategyProbeNativeLANPhysical TestManagedStrategyProbeNativeLANManualApply' ;;
    *) exit 2 ;;
  esac
  probe_timeout=240s
elif test "${RAZVILKA_MANAGED_PROBE_LAN_CASE:-full}" != full; then
  exit 2
fi
# Separate genuine source admission diagnostic; it does not stand in for the
# full NFQWS2 packet workflow or positive offline retirement.
if test "${RAZVILKA_MIHOMO_COLD_SOURCE_NATIVE:-0}" = 1; then
  probe_cases='TestStaticVersionFactNativeMihomoColdRead TestMihomoLiveColdPublicNativeHistoricalIntent TestMihomoLiveColdExportNativeHistoricalIntent TestMihomoLiveColdCLINativeHistoricalIntent TestMihomoLiveColdHealth9ExportNativeHistoricalIntent TestMihomoLiveColdHealth9CLINativeHistoricalIntent'
  probe_timeout=220s
fi
for probe_case in $probe_cases; do
probe_status=0
probe_program=/opt/bin/razvilka
case "$probe_case" in TestClassicReadBatchNativeMutation|TestStaticVersionFactNative*) probe_program="$probe_work/startuptools.test" ;; esac
case "$probe_case" in
  TestMihomoLiveColdPublicNativeHistoricalIntent|TestMihomoLiveColdExportNativeHistoricalIntent|TestMihomoLiveColdHealth9ExportNativeHistoricalIntent) probe_program="$probe_work/dataplane.test" ;;
  TestMihomoLiveColdCLINativeHistoricalIntent|TestMihomoLiveColdHealth9CLINativeHistoricalIntent) probe_program="$probe_work/controller.test" ;;
esac
RAZVILKA_MANAGED_PROBE_FIXTURE_CONTROLLER="$probe_work/app.test"
if test "$probe_case" = TestMihomoLiveColdHealth9CLINativeHistoricalIntent; then
  RAZVILKA_MANAGED_PROBE_FIXTURE_CONTROLLER="$probe_work/controller.test"
fi
export RAZVILKA_MANAGED_PROBE_FIXTURE_CONTROLLER
unshare --mount --net sh -c '

  set -eu
  mount --make-rprivate /
  mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
  # Bind the SAME compiled reader/consumer inode at the actual controller
  # pathname. The real fleet/identity scanner remains in the HTTP admission.
  mkdir -m 755 /opt/bin
  touch /opt/bin/razvilka
  chmod 500 /opt/bin/razvilka
  mount --bind "$RAZVILKA_MANAGED_PROBE_FIXTURE_CONTROLLER" /opt/bin/razvilka
  # Production LookupNetIP uses the real resolver and this private mount;
  # no supplied address/lookup callback bypasses catalogue DNS selection.
  mount --bind "$RAZVILKA_MANAGED_PROBE_FIXTURE_WORK/hosts" /etc/hosts
  # Register actual legacy table/proc inventories before the complete reader.
  # This unreferenced disposable chain loads the NFQUEUE target, sees no
  # packets, and is deleted before original App/Manager admission begins.
  /usr/sbin/iptables-legacy -t mangle -S >/dev/null
  /usr/sbin/ip6tables-legacy -t mangle -S >/dev/null
  /usr/sbin/iptables-legacy -t mangle -N RZV_CI_NFQ_BOOTSTRAP
  /usr/sbin/iptables-legacy -t mangle -A RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
  /usr/sbin/iptables-legacy -t mangle -D RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
  /usr/sbin/iptables-legacy -t mangle -X RZV_CI_NFQ_BOOTSTRAP
  python3 "$RAZVILKA_MANAGED_PROBE_FIXTURE_REPO/scripts/native-managed-probe-queue-init.py"
  exec "$@"
' sh "$probe_program" -test.run="^${probe_case}\$" -test.count=1 -test.v -test.timeout="$probe_timeout" || probe_status=$?
# Analyze outside the private /opt mount; retain the original native failure.
if test -f "$probe_work/$probe_case.pprof"; then
  if ! timeout 50s go tool pprof -top -nodecount=20 "$probe_work/app.test" "$probe_work/$probe_case.pprof"; then
    if test "$probe_status" = 0; then probe_status=1; fi
  fi
  # Cumulative callers attribute syscall/SHA cost to the original producer;
  # flat runtime leaves alone cannot distinguish tools from runtime assets.
  if ! timeout 50s go tool pprof -top -cum -nodecount=20 "$probe_work/app.test" "$probe_work/$probe_case.pprof"; then
    if test "$probe_status" = 0; then probe_status=1; fi
  fi
  # Filter ancestors/runtime leaves to expose actual source/controller costs.
  if ! timeout 50s go tool pprof -top -cum -nodecount=40 -show="github.com/ArtixSx/razvilka/internal/(dataplane|strategylab|startuptools|components|app)" "$probe_work/app.test" "$probe_work/$probe_case.pprof"; then
    if test "$probe_status" = 0; then probe_status=1; fi
  fi
fi
if test -f "$probe_work/$probe_case.pprof.alloc"; then
  if ! timeout 50s go tool pprof -top -sample_index=alloc_space -nodecount=30 "$probe_work/app.test" "$probe_work/$probe_case.pprof.alloc"; then
    if test "$probe_status" = 0; then probe_status=1; fi
  fi
fi
test "$probe_status" = 0 || exit "$probe_status"
done
